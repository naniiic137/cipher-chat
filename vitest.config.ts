import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['shared/test/**/*.test.ts', 'server/test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Keep the machine responsive: Argon2 (64 MiB) tests run in a few workers only.
    maxWorkers: 2,
  },
});
