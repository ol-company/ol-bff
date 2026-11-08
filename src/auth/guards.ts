// Middleware bảo vệ: bắt buộc có session hợp lệ (tự refresh token) và chống CSRF.
import type { RequestHandler } from 'express';
import { parse } from 'cookie';
import { ForbiddenError, UnauthenticatedError, type Logger } from '@ol/node-kit';
import { hashSessionId } from '../session/crypto.js';
import type { SessionStore } from '../session/session-store.js';
import type { OidcPort } from './oidc.js';
import '../types.js';

// Tiền tố __Host-: trình duyệt chỉ nhận cookie này khi có Secure, Path=/ và KHÔNG có Domain
// → subdomain khác (kể cả bị chiếm) không ghi đè được cookie phiên
export const SESSION_COOKIE = '__Host-ol_session';
export const TX_COOKIE = '__Host-ol_tx';

export function readCookie(header: string | undefined, name: string): string | undefined {
  return header ? parse(header)[name] : undefined;
}

export function requireSession(deps: {
  store: SessionStore;
  oidc: OidcPort;
  logger: Logger;
}): RequestHandler {
  return async (req, _res, next) => {
    const raw = readCookie(req.header('cookie'), SESSION_COOKIE);
    if (!raw) throw new UnauthenticatedError('Chưa đăng nhập');
    const idHash = hashSessionId(raw);
    let session = await deps.store.get(idHash);
    if (!session) throw new UnauthenticatedError('Phiên đã hết hạn');

    // Access token còn dưới 60 giây → refresh trước khi chuyển tiếp
    const expiring = (s: { accessExpiresAt: Date }) =>
      s.accessExpiresAt.getTime() - Date.now() < 60_000;
    if (expiring(session)) {
      try {
        session = await deps.store.refreshIfNeeded(idHash, expiring, async (s) => {
          if (!s.refreshToken) throw new Error('Không có refresh token');
          return deps.oidc.refresh(s.refreshToken);
        });
      } catch (err) {
        // Refresh token bị thu hồi (người dùng bị khóa/đăng xuất ở Keycloak) → hủy phiên
        deps.logger.info({ err: (err as Error).message }, 'refresh_failed_session_revoked');
        await deps.store.delete(idHash);
        throw new UnauthenticatedError('Phiên đã bị thu hồi');
      }
      if (!session) throw new UnauthenticatedError('Phiên đã hết hạn');
    }

    void deps.store.touch(idHash).catch(() => undefined); // Gia hạn idle timeout, không chặn request
    req.session = session;
    next();
  };
}

// Chống CSRF cho request thay đổi dữ liệu:
//  1) Bắt buộc header tùy chỉnh X-OL-CSRF — form/ảnh từ trang khác không gửi được header này,
//     còn fetch từ origin khác sẽ bị chặn bởi CORS preflight (BFF không bật CORS)
//  2) Header Origin (nếu có) phải đúng origin của ứng dụng
export function csrfGuard(appOrigin: string): RequestHandler {
  const safe = new Set(['GET', 'HEAD', 'OPTIONS']);
  return (req, _res, next) => {
    if (safe.has(req.method)) return next();
    if (req.header('x-ol-csrf') !== '1') throw new ForbiddenError('Thiếu header chống CSRF');
    const origin = req.header('origin');
    if (origin && origin !== appOrigin) throw new ForbiddenError('Origin không hợp lệ');
    next();
  };
}
