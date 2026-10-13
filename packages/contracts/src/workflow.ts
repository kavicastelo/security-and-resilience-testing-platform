import { z } from 'zod';

export const WorkflowStepSchema = z.object({
  id: z.string(),
  name: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('POST'),
  path: z.string(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(),
  extractVariables: z
    .array(
      z.object({
        name: z.string(),
        path: z.string().describe('JSON path (e.g. data.orderId) or regex to extract from response'),
      }),
    )
    .optional(),
  expectedStatus: z.number().int().default(200),
  isPrivileged: z.boolean().optional().default(false),
  isPaymentOrTerminal: z.boolean().optional().default(false),
  order: z.number().int().nonnegative(),
});

export type WorkflowStep = z.infer<typeof WorkflowStepSchema>;

export const StateTransitionSchema = z.object({
  fromStepId: z.string(),
  toStepId: z.string(),
  allowed: z.boolean().default(true),
  description: z.string().optional(),
});

export type StateTransition = z.infer<typeof StateTransitionSchema>;

export const WorkflowDefinitionSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  initialStepId: z.string(),
  terminalStepIds: z.array(z.string()).default([]),
  steps: z.array(WorkflowStepSchema),
  transitions: z.array(StateTransitionSchema).optional(),
});

export type WorkflowDefinition = z.infer<typeof WorkflowDefinitionSchema>;

export const RaceConditionTestSchema = z.object({
  id: z.string(),
  name: z.string(),
  endpointPath: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('POST'),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(),
  concurrency: z.number().int().min(2).max(30).default(20),
  expectedMaxSuccessCount: z.number().int().min(1).default(1),
  expectedSuccessCodes: z.array(z.number()).default([200, 201, 204]),
});

export type RaceConditionTest = z.infer<typeof RaceConditionTestSchema>;

export const TamperTestParameterSchema = z.object({
  fieldName: z.string(),
  targetType: z.enum(['quantity', 'price', 'discount', 'fee', 'amount', 'numeric']).default('numeric'),
  location: z.enum(['body', 'query', 'path']).default('body'),
  payloadValues: z.array(z.union([z.number(), z.string()])).optional(),
});

export type TamperTestParameter = z.infer<typeof TamperTestParameterSchema>;

export const ParameterTamperTestSchema = z.object({
  id: z.string(),
  name: z.string(),
  endpointPath: z.string(),
  method: z.enum(['POST', 'PUT', 'PATCH']).default('POST'),
  headers: z.record(z.string(), z.string()).optional(),
  baseBody: z.record(z.string(), z.unknown()).default({}),
  parameters: z.array(TamperTestParameterSchema),
});

export type ParameterTamperTest = z.infer<typeof ParameterTamperTestSchema>;

export const BusinessLogicOptionsSchema = z.object({
  workflows: z.array(WorkflowDefinitionSchema).optional(),
  raceConditions: z.array(RaceConditionTestSchema).optional(),
  tamperTests: z.array(ParameterTamperTestSchema).optional(),
  singlePacketBarrier: z.boolean().default(true),
  burstConcurrency: z.number().int().min(2).max(30).default(20),
  timeoutMs: z.number().int().positive().default(15000),
  autoDiscoverCommonPatterns: z.boolean().default(true),
});

export type BusinessLogicOptions = z.infer<typeof BusinessLogicOptionsSchema>;
