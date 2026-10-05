import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
  resolve: {
    alias: {
      '@security-lab/domain': path.resolve(__dirname, './packages/domain/src/index.ts'),
      '@security-lab/contracts': path.resolve(__dirname, './packages/contracts/src/index.ts'),
      '@security-lab/config': path.resolve(__dirname, './packages/config/src/index.ts'),
      '@security-lab/logger': path.resolve(__dirname, './packages/logger/src/index.ts'),
      '@security-lab/evidence': path.resolve(__dirname, './packages/evidence/src/index.ts'),
      '@security-lab/scoring': path.resolve(__dirname, './packages/scoring/src/index.ts'),
      '@security-lab/policy-engine': path.resolve(__dirname, './packages/policy-engine/src/index.ts'),
      '@security-lab/test-sdk': path.resolve(__dirname, './packages/test-sdk/src/index.ts'),
    },
  },
});
