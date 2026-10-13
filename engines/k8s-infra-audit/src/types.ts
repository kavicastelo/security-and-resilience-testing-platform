import {
  K8sAuditRuleFinding,
  K8sSecurityRuleSeverity,
} from '@security-lab/contracts';

export * from '@security-lab/contracts';

export interface K8sManifestMetadata {
  name?: string;
  namespace?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface K8sSecurityContext {
  privileged?: boolean;
  runAsNonRoot?: boolean;
  runAsUser?: number;
  runAsGroup?: number;
  readOnlyRootFilesystem?: boolean;
  allowPrivilegeEscalation?: boolean;
  capabilities?: {
    add?: string[];
    drop?: string[];
  };
  seccompProfile?: {
    type?: string;
  };
}

export interface K8sResourceRequirements {
  limits?: {
    cpu?: string;
    memory?: string;
  };
  requests?: {
    cpu?: string;
    memory?: string;
  };
}

export interface K8sVolumeMount {
  name: string;
  mountPath: string;
  readOnly?: boolean;
}

export interface K8sContainer {
  name: string;
  image?: string;
  securityContext?: K8sSecurityContext;
  resources?: K8sResourceRequirements;
  volumeMounts?: K8sVolumeMount[];
  ports?: Array<{ containerPort: number; protocol?: string }>;
}

export interface K8sHostPath {
  path: string;
  type?: string;
}

export interface K8sVolume {
  name: string;
  hostPath?: K8sHostPath;
  emptyDir?: Record<string, unknown>;
  secret?: Record<string, unknown>;
  configMap?: Record<string, unknown>;
}

export interface K8sPodSpec {
  securityContext?: K8sSecurityContext;
  containers?: K8sContainer[];
  initContainers?: K8sContainer[];
  volumes?: K8sVolume[];
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  serviceAccountName?: string;
  automountServiceAccountToken?: boolean;
}

export interface K8sWorkloadDocument {
  apiVersion?: string;
  kind?: string;
  metadata?: K8sManifestMetadata;
  spec?: {
    template?: {
      metadata?: K8sManifestMetadata;
      spec?: K8sPodSpec;
    };
    spec?: K8sPodSpec; // For bare Pods
    containers?: K8sContainer[];
    volumes?: K8sVolume[];
    [key: string]: unknown;
  };
  rawText?: string;
  startLine?: number;
  endLine?: number;
  filePath?: string;
}

export interface DockerfileInstruction {
  instruction: string;
  args: string;
  raw: string;
  lineNumber: number;
}

export interface ParsedDockerfile {
  filePath?: string;
  rawContent: string;
  instructions: DockerfileInstruction[];
}

export interface RuleEvaluationContext {
  filePath?: string;
  rawContent?: string;
  policyLevel?: 'privileged' | 'baseline' | 'restricted';
}

export interface K8sRule {
  id: string;
  name: string;
  severity: K8sSecurityRuleSeverity;
  category: string;
  description: string;
  evaluate(doc: K8sWorkloadDocument, context: RuleEvaluationContext): K8sAuditRuleFinding[];
}

export interface DockerfileRule {
  id: string;
  name: string;
  severity: K8sSecurityRuleSeverity;
  category: string;
  description: string;
  evaluate(dockerfile: ParsedDockerfile, context: RuleEvaluationContext): K8sAuditRuleFinding[];
}
