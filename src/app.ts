// Dựng app BFF. Thứ tự middleware quan trọng:
// request id → log → health → auth routes → [session → CSRF → rate limit → chặn /internal → proxy] → 404 → lỗi
import express, { type Express } from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import {
  accessLogMiddleware,
  errorHandler,
  healthRouter,
  notFoundHandler,
  requestContextMiddleware,
  type HealthState,
  type Logger,
} from '@ol/node-kit';
import { csrfGuard, requireSession } from './auth/guards.js';
import type { OidcPort } from './auth/oidc.js';
import { authRouter } from './auth/routes.js';
import { apiProxy, blockInternalPaths } from './proxy/api-proxy.js';
import type { TokenSealer } from './session/crypto.js';
import type { SessionStore } from './session/session-store.js';

export interface AppDeps {
  logger: Logger;
  health: HealthState;
  store: SessionStore;
  oidc: OidcPort;
  sealer: TokenSealer;
  appUrl: string;
  absoluteMs: number;
  upstreams: Record<string, string>; // { iam: 'http://iam-service:3000', warehouse: '...' }
  rateLimitPerMinute: number;
  healthChecks?: Record<string, () => Promise<unknown>>;
  fetchImpl?: typeof fetch;
}

export function buildApp(d: AppDeps): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // Đứng sau đúng 1 lớp proxy (ALB hoặc Caddy) → req.ip, req.protocol chính xác
  app.use(helmet({ contentSecurityPolicy: false })); // BFF chỉ trả JSON/redirect; CSP do web-admin đặt
  app.use(requestContextMiddleware());
  app.use(accessLogMiddleware(d.logger));
  app.use(healthRouter(d.health, d.healthChecks ?? {}));

  // Giới hạn chung theo IP cho /auth/* (chống dò đăng nhập, spam callback)
  app.use(
    '/auth',
    rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false }),
  );
  app.use(
    authRouter({
      appUrl: d.appUrl,
      oidc: d.oidc,
      store: d.store,
      sealer: d.sealer,
      logger: d.logger,
      absoluteMs: d.absoluteMs,
      iamInternalUrl: d.upstreams.iam!,
      fetchImpl: d.fetchImpl,
    }),
  );

  const appOrigin = new URL(d.appUrl).origin;
  const guard = requireSession({ store: d.store, oidc: d.oidc, logger: d.logger });
  // Giới hạn theo phiên cho API — mỗi người dùng một hạn mức riêng
  const apiLimiter = rateLimit({
    windowMs: 60_000,
    limit: d.rateLimitPerMinute,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: (req) => req.session!.idHash,
  });

  for (const [name, target] of Object.entries(d.upstreams)) {
    // app.use('/api/iam', ...) → Express cắt tiền tố, service nhận đường dẫn /v1/...
    app.use(
      `/api/${name}`,
      guard,
      csrfGuard(appOrigin),
      apiLimiter,
      blockInternalPaths(),
      apiProxy(target),
    );
  }

  app.use(notFoundHandler());
  app.use(errorHandler(d.logger));
  return app;
}
