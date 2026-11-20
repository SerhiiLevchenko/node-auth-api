import { z } from 'zod';

export const envSchema = z.object({
  DATABASE_URL: z.string().min(1),

  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),

  JWT_ACCESS_TTL_SECONDS: z.coerce.number().int().positive().default(900),

  JWT_REFRESH_TTL_SECONDS: z.coerce.number().int().positive().default(604800),

  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  FRONTEND_ORIGIN: z.string().url(),

  RATE_LIMIT_TTL_MS: z.coerce.number().int().positive().default(60000),

  RATE_LIMIT_LIMIT: z.coerce.number().int().positive().default(100),

  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
});
