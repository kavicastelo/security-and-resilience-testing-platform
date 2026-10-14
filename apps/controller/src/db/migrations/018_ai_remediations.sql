-- ==============================================================================
-- Security Lab: Phase 20 AI-Assisted Security Analysis & Remediation (018)
-- Stores context-aware code remediation diffs, explainability, and verification
-- ==============================================================================

CREATE TABLE IF NOT EXISTS ai_remediations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  explanation TEXT NOT NULL,
  git_diff TEXT NOT NULL,
  confidence_score REAL NOT NULL DEFAULT 0.85,
  verified_status VARCHAR(32) NOT NULL DEFAULT 'UNVERIFIED', -- 'UNVERIFIED', 'PASSED', 'FAILED'
  model VARCHAR(128),
  prompt_tokens INTEGER DEFAULT 0,
  completion_tokens INTEGER DEFAULT 0,
  verification_output TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_remediations_finding_id ON ai_remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_ai_remediations_workspace_id ON ai_remediations(workspace_id);
CREATE INDEX IF NOT EXISTS idx_ai_remediations_verified_status ON ai_remediations(verified_status);
