export type CapabilityCategory =
  | 'passive_analysis'
  | 'active_fuzzing'
  | 'protocol_audit'
  | 'resilience_stress'
  | 'compliance_check';

export interface TestCapability {
  readonly id: string;
  readonly name: string;
  readonly category: CapabilityCategory;
  readonly description: string;
  /**
   * Indicates if running this capability could disrupt or alter target state.
   * Disruptive tests require explicit target scope authorization.
   */
  readonly isDisruptive: boolean;
  /**
   * Target scope capability flags required before execution is permitted.
   */
  readonly requiredScopeFlags?: string[];
}
