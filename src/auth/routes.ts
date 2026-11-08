// Luồng đăng nhập/đăng xuất. Đây là nơi DUY NHẤT trình duyệt tương tác với OIDC;
// sau đăng nhập trình duyệt chỉ cầm cookie phiên, không bao giờ thấy token.
import express, { Router } from 'express';
import { serialize } from 'cookie';
import { ValidationError, type Logger } from '@ol/node-kit';
import type { TokenSealer } from '../session/crypto.js';
import { hashSessionId, newSessionId } from '../session/crypto.js';
import type { SessionStore } from '../session/session-store.js';
import { csrfGuard, readCookie, requireSession, SESSION_COOKIE, TX_COOKIE } from './guards.js';
import type { LoginTransaction, OidcPort } from './oidc.js';

export interface AuthDeps {
  appUrl: string;
  oidc: OidcPort;
  store: SessionStore;
  sealer: TokenSealer;
  logger: Logger;
  absoluteMs: number;
  iamInternalUrl: string;
  fetchImpl?: typeof fetch;
}

const cookieBase = { httpOnly: true, secure: true, sameSite: 'lax' as const, path: '/' };

// Chỉ cho quay về đường dẫn nội bộ: "/x" hợp lệ; "//evil.com" hay "https://evil.com" bị chặn (open redirect)
function safeReturnTo(value: unknown): string {
  return typeof value === 'string' &&
    value.startsWith('/') &&
    !value.startsWith('//') &&
    !value.includes('\\')
    ? value
    : '/';
}

export function authRouter(d: AuthDeps): Router {
  const r = Router();
  const appOrigin = new URL(d.appUrl).origin;

  r.get('/auth/login', async (req, res) => {
    const { url, tx } = await d.oidc.startLogin(safeReturnTo(req.query.returnTo));
    // Lưu state/nonce/PKCE trong cookie đã mã hóa, sống 10 phút
    res.setHeader(
      'set-cookie',
      serialize(TX_COOKIE, d.sealer.seal(JSON.stringify(tx)), { ...cookieBase, maxAge: 600 }),
    );
    res.redirect(302, url);
  });

  r.get('/auth/callback', async (req, res) => {
    if (typeof req.query.error === 'string') {
      d.logger.info({ error: req.query.error }, 'login_error_from_idp');
      res.redirect(302, '/?login_error=1');
      return;
    }
    const sealed = readCookie(req.header('cookie'), TX_COOKIE);
    if (!sealed) throw new ValidationError('Phiên đăng nhập đã hết hạn, hãy thử lại');
    let tx: LoginTransaction;
    try {
      tx = JSON.parse(d.sealer.open(sealed)) as LoginTransaction;
    } catch {
      throw new ValidationError('Cookie đăng nhập không hợp lệ');
    }

    // Dựng URL callback từ APP_URL cấu hình (không tin Host header của request)
    const callbackUrl = new URL(req.originalUrl, d.appUrl);
    const login = await d.oidc.finishLogin(callbackUrl, tx);

    const sessionId = newSessionId();
    await d.store.create({
      idHash: hashSessionId(sessionId),
      userSub: login.sub,
      keycloakSid: login.sid,
      email: login.email,
      name: login.name,
      idToken: login.idToken,
      accessToken: login.accessToken,
      refreshToken: login.refreshToken,
      accessExpiresAt: login.accessExpiresAt,
      absoluteExpiresAt: new Date(Date.now() + d.absoluteMs),
    });

    // Đồng bộ hồ sơ với IAM (kích hoạt lời mời, cập nhật MFA). Lỗi thì ghi log, UI sẽ gọi lại /v1/me
    try {
      const f = d.fetchImpl ?? fetch;
      const me = await f(`${d.iamInternalUrl}/v1/me`, {
        headers: { authorization: `Bearer ${login.accessToken}` },
        signal: AbortSignal.timeout(3_000),
      });
      if (!me.ok) d.logger.warn({ status: me.status }, 'iam_me_sync_failed');
    } catch (err) {
      d.logger.warn({ err }, 'iam_me_sync_failed');
    }

    res.setHeader('set-cookie', [
      serialize(SESSION_COOKIE, sessionId, {
        ...cookieBase,
        maxAge: Math.floor(d.absoluteMs / 1000),
      }),
      serialize(TX_COOKIE, '', { ...cookieBase, maxAge: 0 }), // Xóa cookie giao dịch
    ]);
    res.redirect(302, tx.returnTo);
  });

  // Trạng thái đăng nhập cho SPA — chỉ thông tin hiển thị, không có token
  r.get('/auth/session', async (req, res) => {
    const raw = readCookie(req.header('cookie'), SESSION_COOKIE);
    const s = raw ? await d.store.get(hashSessionId(raw)) : null;
    res.setHeader('cache-control', 'no-store');
    res.json(
      s
        ? {
            authenticated: true,
            user: { id: s.userSub, email: s.email, name: s.name },
            absoluteExpiresAt: s.absoluteExpiresAt,
          }
        : { authenticated: false },
    );
  });

  r.post(
    '/auth/logout',
    csrfGuard(appOrigin),
    requireSession({ store: d.store, oidc: d.oidc, logger: d.logger }),
    async (req, res) => {
      const s = req.session!;
      await d.store.delete(s.idHash);
      res.setHeader('set-cookie', serialize(SESSION_COOKIE, '', { ...cookieBase, maxAge: 0 }));
      // SPA điều hướng tới URL này để Keycloak kết thúc phiên SSO
      res.json({ logoutUrl: await d.oidc.endSessionUrl(s.idToken, `${d.appUrl}/`) });
    },
  );

  // Keycloak gọi trực tiếp (server-to-server) khi phiên SSO kết thúc: người dùng bị khóa, admin đăng xuất hộ...
  r.post(
    '/auth/backchannel-logout',
    express.urlencoded({ extended: false, limit: '10kb' }),
    async (req, res) => {
      const token = (req.body as Record<string, unknown> | undefined)?.logout_token;
      if (typeof token !== 'string') {
        res.status(400).json({ error: 'invalid_request' });
        return;
      }
      try {
        const { sid, sub } = await d.oidc.verifyLogoutToken(token);
        const removed = sid
          ? await d.store.deleteByKeycloakSid(sid)
          : await d.store.deleteByUser(sub!);
        d.logger.info({ removed }, 'backchannel_logout');
        res.setHeader('cache-control', 'no-store');
        res.status(200).end();
      } catch (err) {
        d.logger.warn({ err: (err as Error).message }, 'backchannel_logout_rejected');
        res.status(400).json({ error: 'invalid_request' });
      }
    },
  );

  return r;
}
