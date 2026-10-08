import os from 'node:os';
import { AgentConfig } from './config.js';
import { AgentClient, IncompatibleProtocolError } from './client.js';
import { AgentWorker } from './worker.js';
import { logger } from '@security-lab/logger';

export class AgentDaemon {
  private readonly config: AgentConfig;
  private readonly client: AgentClient;
  private readonly worker: AgentWorker;
  private agentId?: string;
  private isRunning = false;
  private heartbeatTimer?: NodeJS.Timeout;
  private pollTimer?: NodeJS.Timeout;
  private activeJobsCount = 0;
  private readonly activeLeaseIds = new Set<string>();
  private readonly activeJobControllers = new Map<string, AbortController>();

  constructor(config: AgentConfig) {
    this.config = config;
    this.client = new AgentClient(config.controllerUrl, config.agentToken);
    this.worker = new AgentWorker(this.client, { allowLocalTesting: config.allowLocalTesting });
    this.agentId = config.agentId;
  }

  async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    logger.info(`Starting Security Lab Execution Agent: "${this.config.name}"`);
    logger.info(`Target Control Plane URL: ${this.config.controllerUrl}`);

    // 1. Ensure Agent is Registered and has a valid Token
    try {
      if (!this.client.getToken() || !this.agentId) {
        logger.info('No agent token provided; enrolling agent dynamically with control plane...');
        const registration = await this.client.register(
          {
            name: this.config.name,
            tags: this.config.tags,
            capabilities: this.config.capabilities,
            systemInfo: {
              os: os.platform(),
              arch: os.arch(),
              nodeVersion: process.version,
              cpuCount: os.cpus().length,
              totalMemoryMb: Math.round(os.totalmem() / 1024 / 1024),
              hostname: os.hostname(),
            },
          },
          this.config.enrollmentKey,
          this.config.tenantId,
        );

        this.agentId = registration.agentId;
        logger.info(`Agent enrolled successfully. Agent ID: ${this.agentId}`);
      }
    } catch (regErr: unknown) {
      if (regErr instanceof IncompatibleProtocolError) {
        logger.error(
          { err: regErr.message, code: regErr.code, statusCode: regErr.statusCode },
          'Fatal: Agent protocol version is incompatible with controller. Shutting down daemon gracefully.',
        );
        await this.stop();
        return;
      }
      throw regErr;
    }

    // 2. Start Periodic Heartbeat
    this.startHeartbeatLoop();

    // 3. Start Polling Loop
    this.startPollingLoop();
  }

  private startHeartbeatLoop() {
    const runHeartbeat = async () => {
      if (!this.isRunning || !this.agentId) return;
      try {
        const memUsage = process.memoryUsage();
        const activeLeases = Array.from(this.activeLeaseIds);
        const hbResponse = await this.client.heartbeat(
          this.agentId,
          this.activeJobsCount > 0 ? 'busy' : 'online',
          {
            memoryUsageMb: Math.round(memUsage.heapUsed / 1024 / 1024),
            activeJobsCount: this.activeJobsCount,
          },
          activeLeases[0],
          activeLeases,
        );

        // Process bidirectional cancellation signals from controller
        if (hbResponse.cancelledJobIds && hbResponse.cancelledJobIds.length > 0) {
          for (const cancelledId of hbResponse.cancelledJobIds) {
            const controller = this.activeJobControllers.get(cancelledId);
            if (controller) {
              logger.warn(
                { event: 'job.cancelled_propagated', jobId: cancelledId },
                'Controller signaled job cancellation; aborting worker execution',
              );
              controller.abort(new Error(`Job "${cancelledId}" was cancelled by the controller`));
            }
            // Send cancellation acknowledgment to controller
            await this.client.acknowledgeCancellation(cancelledId);
          }
        }
      } catch (err: unknown) {
        if (err instanceof IncompatibleProtocolError) {
          logger.error(
            { err: err.message, code: err.code, statusCode: err.statusCode },
            'Fatal: Agent protocol version is incompatible with controller during heartbeat. Shutting down daemon gracefully.',
          );
          await this.stop();
          return;
        }
        logger.warn({ err }, 'Agent heartbeat check-in failed');
      }
    };

    runHeartbeat();
    this.heartbeatTimer = setInterval(runHeartbeat, this.config.heartbeatIntervalMs);
  }

  private startPollingLoop() {
    const pollNext = async () => {
      if (!this.isRunning || !this.agentId) return;

      try {
        if (this.activeJobsCount === 0) {
          const jobs = await this.client.poll(
            this.agentId,
            this.config.capabilities,
            this.config.tags,
            1,
          );

          if (jobs.length > 0) {
            for (const job of jobs) {
              if (job.leaseId) {
                this.activeLeaseIds.add(job.leaseId);
              }
              this.activeJobsCount++;
              const abortController = new AbortController();
              this.activeJobControllers.set(job.jobId, abortController);
              try {
                await this.worker.executeJob(job, abortController.signal);
              } finally {
                this.activeJobControllers.delete(job.jobId);
                this.activeJobsCount--;
                if (job.leaseId) {
                  this.activeLeaseIds.delete(job.leaseId);
                }
              }
            }
          }
        }
      } catch (pollErr: unknown) {
        if (pollErr instanceof IncompatibleProtocolError) {
          logger.error(
            { err: pollErr.message, code: pollErr.code, statusCode: pollErr.statusCode },
            'Fatal: Agent protocol version is incompatible with controller during polling. Shutting down daemon gracefully.',
          );
          await this.stop();
          return;
        }
        logger.warn({ pollErr }, 'Job polling iteration encountered an error');
      }

      if (this.isRunning) {
        this.pollTimer = setTimeout(pollNext, this.config.pollIntervalMs);
      }
    };

    pollNext();
  }

  async stop(): Promise<void> {
    logger.info('Stopping agent daemon...');
    this.isRunning = false;

    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.pollTimer) clearTimeout(this.pollTimer);

    if (this.agentId && this.client.getToken()) {
      try {
        await this.client.heartbeat(this.agentId, 'offline', { activeJobsCount: 0 });
      } catch {
        // Best effort
      }
    }

    logger.info('Agent daemon stopped.');
  }

  getAgentId(): string | undefined {
    return this.agentId;
  }
}
