import { config } from 'dotenv';
import { defineConfig } from 'vitest/config';

config({
  path: '.env.test',
  override: true,
});

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.e2e-spec.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
  },
});
