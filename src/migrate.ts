// Migration cho schema bff (chạy bằng bff_migrator trước khi deploy).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import pg from 'pg';
import { createLogger, envBoolean } from '@ol/node-kit';
import { loadDbConfig } from './config.js';

const cfg = loadDbConfig();
const logger = createLogger({ service: 'ol-bff-migrate', level: cfg.LOG_LEVEL });
const pool = new pg.Pool({
  host: cfg.DB_HOST,
  port: cfg.DB_PORT,
  database: cfg.DB_NAME,
  user: cfg.DB_USER,
  password: cfg.DB_PASSWORD,
  max: 1,
  ssl: envBoolean(cfg.DB_SSL)
    ? {
        rejectUnauthorized: true,
        ...(cfg.DB_SSL_CA_FILE ? { ca: readFileSync(cfg.DB_SSL_CA_FILE, 'utf8') } : {}),
      }
    : undefined,
});

try {
  await migrate(drizzle(pool), {
    migrationsFolder: fileURLToPath(new URL('../migrations', import.meta.url)),
  });
  logger.info('migrate_done');
} catch (err) {
  logger.error({ err }, 'migrate_failed');
  process.exitCode = 1;
} finally {
  await pool.end();
}
