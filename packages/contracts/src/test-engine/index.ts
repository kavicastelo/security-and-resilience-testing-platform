import { z } from 'zod';

export const EngineCapabilityCategorySchema = z.enum([
  'passive_analysis',
  'active_fuzzing',
  'protocol_audit',
  'resilience_stress',
  'compliance_check',
]);

export type EngineCapabilityCategory = z.infer<typeof EngineCapabilityCategorySchema>;

export const EngineCapabilityDeclarationSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: EngineCapabilityCategorySchema,
  description: z.string(),
  isDisruptive: z.boolean().default(false),
  requiredScopeFlags: z.array(z.string()).default([]),
});

export type EngineCapabilityDeclaration = z.infer<typeof EngineCapabilityDeclarationSchema>;

export const EngineDescriptorSchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string(),
  author: z.string().optional(),
  executionClass: z.enum(['class_a_native', 'class_b_container', 'class_c_worker']),
  capabilities: z.array(EngineCapabilityDeclarationSchema),
});

export type EngineDescriptor = z.infer<typeof EngineDescriptorSchema>;
