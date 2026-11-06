// Runtime config của BFF.
import { envBoolean, loadConfig } from '@ol/node-kit';
import { z } from 'zod';

const DbSchema = z.object({
  APP_ENV: z.enum(['local', 'dev', 'staging', 'prod']).default('local'),
  LOG_LEVEL: z.string().default('info'),
  DB_HOST: z.string().min(1),
  DB_PORT: z.coerce.number().int().positive().default(5432),
  DB_NAME: z.string().default('bff'),
  DB_USER: z.string().min(1),
  DB_PASSWORD: z.string().min(1),
  DB_SSL: z.string().optional(),
  DB_SSL_CA_FILE: z.string().optional(),
  DB_POOL_MAX: z.coerce.number().int().positive().default(10),
});

const AppSchema = DbSchema.extend({
  PORT: z.coerce.number().int().positive().default(3000),
  APP_URL: z.url(), // https://app.ol.test — origin duy nhất của frontend
  OIDC_ISSUER: z.url(), // https://id.ol.test/realms/ol
  OIDC_CLIENT_ID: z.string().default('ol-bff'),
  OIDC_CLIENT_SECRET: z.string().min(16),
  OIDC_SCOPES: z.string().default('openid profile email'),
  // Khóa 32 byte mã hóa base64 để mã hóa token trong DB: openssl rand -base64 32
  SESSION_ENC_KEY: z.string().refine((v) => Buffer.from(v, 'base64').length === 32, 'Cần 32 byte base64'),
  SESSION_IDLE_MINUTES: z.coerce.number().int().positive().default(30),
  SESSION_ABSOLUTE_HOURS: z.coerce.number().int().positive().default(8),
  IAM_INTERNAL_URL: z.url(),
  WAREHOUSE_INTERNAL_URL: z.url(),
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(300),
  DRAIN_DELAY_MS: z.coerce.number().int().nonnegative().default(5_000),
});

export type DbEnv = z.infer<typeof DbSchema>;
export type AppConfig = z.infer<typeof AppSchema>;
export const loadDbConfig = (): DbEnv => loadConfig(DbSchema);
export const loadAppConfig = (): AppConfig => loadConfig(AppSchema);

export function dbOptions(cfg: DbEnv) {
  return {
    host: cfg.DB_HOST,
    port: cfg.DB_PORT,
    database: cfg.DB_NAME,
    user: cfg.DB_USER,
    password: cfg.DB_PASSWORD,
    ssl: envBoolean(cfg.DB_SSL),
    sslCaFile: cfg.DB_SSL_CA_FILE,
    maxConnections: cfg.DB_POOL_MAX,
  };
}
