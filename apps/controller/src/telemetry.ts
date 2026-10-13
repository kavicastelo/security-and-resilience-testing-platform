import crypto from 'node:crypto';

// ============================================================================
// W3C Trace Context (Distributed Tracing / OpenTelemetry)
// Spec: https://www.w3.org/TR/trace-context/
// Format: 00-${traceId}-${spanId}-${traceFlags}
// ============================================================================

export interface ParsedTraceparent {
  valid: boolean;
  version?: string;
  traceId?: string;
  spanId?: string;
  sampled?: boolean;
}

export function generateTraceId(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function generateSpanId(): string {
  return crypto.randomBytes(8).toString('hex');
}

export function createTraceparent(
  traceId: string = generateTraceId(),
  spanId: string = generateSpanId(),
  sampled: boolean = true,
): string {
  const flags = sampled ? '01' : '00';
  return `00-${traceId}-${spanId}-${flags}`;
}

export function parseTraceparent(header?: string | null): ParsedTraceparent {
  if (!header || typeof header !== 'string') {
    return { valid: false };
  }

  const parts = header.trim().split('-');
  if (parts.length < 4) {
    return { valid: false };
  }

  const [version, traceId, spanId, flags] = parts;
  if (!version || !traceId || !spanId || !flags) {
    return { valid: false };
  }

  if (traceId.length !== 32 || spanId.length !== 16 || flags.length !== 2) {
    return { valid: false };
  }

  // Reject all-zero IDs per W3C specification
  if (/^0+$/.test(traceId) || /^0+$/.test(spanId)) {
    return { valid: false };
  }

  return {
    valid: true,
    version,
    traceId,
    spanId,
    sampled: flags === '01',
  };
}

// ============================================================================
// Prometheus Metrics Registry
// Exports metrics on /metrics adhering to Prometheus exposition format (v0.0.4)
// ============================================================================

export interface AgentHeartbeatMetricEntry {
  agentId: string;
  tenantId: string;
  status: string;
  lastUpdated: number;
}

export interface ActiveLeaseMetricEntry {
  agentId: string;
  tenantId: string;
  count: number;
}

class TelemetryRegistry {
  private agentHeartbeats = new Map<string, AgentHeartbeatMetricEntry>();
  private activeLeases = new Map<string, ActiveLeaseMetricEntry>();
  private jobsLeasedTotal = 0;
  private jobsCompletedTotal = 0;
  private jobsFailedTotal = 0;

  recordAgentHeartbeat(agentId: string, tenantId: string, status: string): void {
    this.agentHeartbeats.set(agentId, {
      agentId,
      tenantId,
      status,
      lastUpdated: Date.now(),
    });
  }

  recordActiveLeases(agentId: string, tenantId: string, count: number): void {
    this.activeLeases.set(agentId, {
      agentId,
      tenantId,
      count,
    });
  }

  incrementJobsLeased(count = 1): void {
    this.jobsLeasedTotal += count;
  }

  incrementJobsCompleted(count = 1): void {
    this.jobsCompletedTotal += count;
  }

  incrementJobsFailed(count = 1): void {
    this.jobsFailedTotal += count;
  }

  clear(): void {
    this.agentHeartbeats.clear();
    this.activeLeases.clear();
    this.jobsLeasedTotal = 0;
    this.jobsCompletedTotal = 0;
    this.jobsFailedTotal = 0;
  }

  exportPrometheus(): string {
    const lines: string[] = [];

    // 1. Agent Heartbeat Status Gauge
    lines.push('# HELP security_lab_agent_heartbeat_status Current heartbeat status of registered agents (1=active)');
    lines.push('# TYPE security_lab_agent_heartbeat_status gauge');
    if (this.agentHeartbeats.size === 0) {
      lines.push('# (no agents currently registered)');
    } else {
      for (const [agentId, entry] of this.agentHeartbeats.entries()) {
        const value = entry.status === 'online' || entry.status === 'busy' ? 1 : 0;
        lines.push(
          `security_lab_agent_heartbeat_status{agent_id="${agentId}",tenant_id="${entry.tenantId}",status="${entry.status}"} ${value}`,
        );
      }
    }

    // 2. Active Leases Gauge
    lines.push('# HELP security_lab_active_leases Number of active job leases currently held by agents');
    lines.push('# TYPE security_lab_active_leases gauge');
    if (this.activeLeases.size === 0) {
      lines.push('# (no active leases)');
    } else {
      for (const [agentId, entry] of this.activeLeases.entries()) {
        lines.push(
          `security_lab_active_leases{agent_id="${agentId}",tenant_id="${entry.tenantId}"} ${entry.count}`,
        );
      }
    }

    // 3. Jobs Leased Total Counter
    lines.push('# HELP security_lab_jobs_leased_total Total number of jobs leased to execution agents');
    lines.push('# TYPE security_lab_jobs_leased_total counter');
    lines.push(`security_lab_jobs_leased_total ${this.jobsLeasedTotal}`);

    // 4. Jobs Completed Total Counter
    lines.push('# HELP security_lab_jobs_completed_total Total number of jobs successfully completed by agents');
    lines.push('# TYPE security_lab_jobs_completed_total counter');
    lines.push(`security_lab_jobs_completed_total ${this.jobsCompletedTotal}`);

    // 5. Jobs Failed Total Counter
    lines.push('# HELP security_lab_jobs_failed_total Total number of jobs failed during agent execution');
    lines.push('# TYPE security_lab_jobs_failed_total counter');
    lines.push(`security_lab_jobs_failed_total ${this.jobsFailedTotal}`);

    return lines.join('\n') + '\n';
  }
}

export const telemetryRegistry = new TelemetryRegistry();
