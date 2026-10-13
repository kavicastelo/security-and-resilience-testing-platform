import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: [
      'tests/**/*.test.ts',
      'packages/*/tests/**/*.test.ts',
      'apps/*/tests/**/*.test.ts',
      'engines/*/tests/**/*.test.ts',
    ],
    env: {
      SECURITY_LAB_BYPASS_AUTH_IN_TESTS: 'true',
      AGENT_MASTER_SECRET: 'test-agent-master-secret-at-least-32-chars-long',
      SECURITY_LAB_API_KEY: 'test-api-key-at-least-16-chars-long',
    },
  },
  resolve: {
    alias: {
      '@security-lab/domain': path.resolve(__dirname, './packages/domain/src/index.ts'),
      '@security-lab/crypto': path.resolve(__dirname, './packages/crypto/src/index.ts'),
      '@security-lab/contracts': path.resolve(__dirname, './packages/contracts/src/index.ts'),
      '@security-lab/config': path.resolve(__dirname, './packages/config/src/index.ts'),
      '@security-lab/logger': path.resolve(__dirname, './packages/logger/src/index.ts'),
      '@security-lab/evidence': path.resolve(__dirname, './packages/evidence/src/index.ts'),
      '@security-lab/scoring': path.resolve(__dirname, './packages/scoring/src/index.ts'),
      '@security-lab/policy-engine': path.resolve(__dirname, './packages/policy-engine/src/index.ts'),
      '@security-lab/test-sdk': path.resolve(__dirname, './packages/test-sdk/src/index.ts'),
      '@security-lab/scope-engine': path.resolve(__dirname, './packages/scope-engine/src/index.ts'),
      '@security-lab/test-runner': path.resolve(__dirname, './packages/test-runner/src/index.ts'),
      '@security-lab/engine-sdk': path.resolve(__dirname, './packages/engine-sdk/src/index.ts'),
      '@security-lab/web-crawler': path.resolve(__dirname, './engines/web-crawler/src/index.ts'),
      '@security-lab/injection-fuzzer': path.resolve(__dirname, './engines/injection-fuzzer/src/index.ts'),
      '@security-lab/graphql-security': path.resolve(__dirname, './engines/graphql-security/src/index.ts'),
    },
  },
});
