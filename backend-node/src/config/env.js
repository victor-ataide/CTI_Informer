import dotenv from 'dotenv';
import { z } from 'zod';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../../.env');

dotenv.config({ path: envPath });

const schema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().default(8100),
  LOG_LEVEL: z.string().default('info'),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  AUTH_USERNAME: z.string().min(3),
  AUTH_PASSWORD_HASH: z.string().regex(/^\$2[aby]\$\d{2}\$.{53}$/),
  AUTH_TOKEN_TTL: z.string().default('8h'),
  AUTH_LOGIN_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(20).default(5),
  AUTH_LOGIN_WINDOW: z.string().default('1 minute'),
  CORS_ORIGIN: z.string().default('*'),
  CRON_COLLECT: z.string().default('*/10 * * * *'),
  CRON_REFRESH: z.string().default('0 3 * * *'),
  FEED_TIMEOUT_MS: z.coerce.number().default(10000),
  FEED_MAX_ENTRIES: z.coerce.number().default(50),
  SOURCES_FILE: z.string().default('../data/sources.json'),
  ENRICH_ENABLED: z.string().default('true'),
  ENRICH_TIMEOUT_MS: z.coerce.number().default(6000),
  ENRICH_MAX_IOCS: z.coerce.number().default(6),
  OTX_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional()
});

export const env = schema.parse(process.env);
