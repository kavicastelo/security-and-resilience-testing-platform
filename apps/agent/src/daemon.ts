import os from 'node:os';
import { AgentConfig } from './config.js';
import { AgentClient } from './client.js';
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

  constructor(config: AgentConfig) {
    this.config = config;
    this.client = new AgentClient(config.controllerUrl, config.agentToken);
    this.worker = new AgentWorker(this.client);
    this.agentId = config.agentId;
  }

  async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    logger.info(`Starting Security Lab Execution Agent: "${this.config.name}"`);
    logger.info(`Target Control Plane URL: ${this.config.controllerUrl}`);

    // 1. Ensure Agent is Registered and has a valid Token
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
        this.config.tenantId,
      );

      this.agentId = registration.agentId;
      logger.info(`Agent enrolled successfully. Agent ID: ${this.agentId}`);
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
        await this.client.heartbeat(this.agentId, this.activeJobsCount > 0 ? 'busy' : 'online', {
          memoryUsageMb: Math.round(memUsage.heapUsed / 1024 / 1024),
          activeJobsCount: this.activeJobsCount,
        });
      } catch (err: unknown) {
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
              this.activeJobsCount++;
              try {
                await this.worker.executeJob(job);
              } finally {
                this.activeJobsCount--;
              }
            }
          }
        }
      } catch (pollErr: unknown) {
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
