// Composition root của BFF (ít phụ thuộc nên ghép tay, không cần container DI).
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { createLogger, envBoolean, HealthState, startServer } from '@ol/node-kit';
import { buildApp } from './app.js';
import { OpenIdClient } from './auth/oidc.js';
import { loadAppConfig } from './config.js';
import { TokenSealer } from './session/crypto.js';
import { PgSessionStore } from './session/session-store.js';

const cfg = loadAppConfig();
const logger = createLogger({ service: 'ol-bff', level: cfg.LOG_LEVEL });
const health = new HealthState();
const pool = new pg.Pool({
  host: cfg.DB_HOST,
  port: cfg.DB_PORT,
  database: cfg.DB_NAME,
  user: cfg.DB_USER,
  password: cfg.DB_PASSWORD,
  max: cfg.DB_POOL_MAX,
  connectionTimeoutMillis: 3_000,
  statement_timeout: 5_000,
  application_name: 'ol-bff',
  ssl: envBoolean(cfg.DB_SSL)
    ? {
        rejectUnauthorized: true,
        ...(cfg.DB_SSL_CA_FILE ? { ca: readFileSync(cfg.DB_SSL_CA_FILE, 'utf8') } : {}),
      }
    : undefined,
});
const sealer = new TokenSealer(cfg.SESSION_ENC_KEY);
const store = new PgSessionStore(pool, sealer, cfg.SESSION_IDLE_MINUTES * 60_000);
const oidc = new OpenIdClient({
  issuer: cfg.OIDC_ISSUER,
  clientId: cfg.OIDC_CLIENT_ID,
  clientSecret: cfg.OIDC_CLIENT_SECRET,
  redirectUri: `${cfg.APP_URL}/auth/callback`,
  scopes: cfg.OIDC_SCOPES,
});

const app = buildApp({
  logger,
  health,
  store,
  oidc,
  sealer,
  appUrl: cfg.APP_URL,
  absoluteMs: cfg.SESSION_ABSOLUTE_HOURS * 3_600_000,
  upstreams: { iam: cfg.IAM_INTERNAL_URL, warehouse: cfg.WAREHOUSE_INTERNAL_URL },
  rateLimitPerMinute: cfg.RATE_LIMIT_PER_MINUTE,
  healthChecks: { db: () => pool.query('SELECT 1') },
});

// Dọn phiên hết hạn mỗi 10 phút (chạy ở mọi task cũng an toàn vì DELETE là idempotent)
const purge = setInterval(() => {
  store
    .purgeExpired()
    .then((n) => n > 0 && logger.info({ purged: n }, 'sessions_purged'))
    .catch((err) => logger.warn({ err }, 'purge_failed'));
}, 10 * 60_000);
purge.unref();

startServer({
  app,
  port: cfg.PORT,
  logger,
  health,
  drainDelayMs: cfg.DRAIN_DELAY_MS,
  onShutdown: [() => pool.end()],
});
