// Reverse proxy /api/<service>/* → service nội bộ, gắn access token của phiên.
// BFF KHÔNG quyết định quyền nghiệp vụ — service đích tự xác minh token và hỏi IAM.
import type { Request, RequestHandler } from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { NotFoundError } from '@ol/node-kit';
import '../types.js';

export function blockInternalPaths(): RequestHandler {
  // API /internal/* chỉ dành cho service-to-service, không bao giờ mở cho trình duyệt
  return (req, _res, next) => {
    if (req.path.startsWith('/internal')) throw new NotFoundError();
    next();
  };
}

export function apiProxy(target: string): RequestHandler {
  return createProxyMiddleware<Request>({
    target,
    changeOrigin: true, // Host header = service đích
    xfwd: true, // Thêm X-Forwarded-* để service ghi đúng IP người dùng vào audit
    proxyTimeout: 10_000, // Service đích quá 10 giây → 504
    timeout: 10_000,
    on: {
      proxyReq: (proxyReq, req) => {
        proxyReq.removeHeader('cookie'); // Cookie phiên KHÔNG đi tiếp vào mạng nội bộ
        proxyReq.setHeader('authorization', `Bearer ${req.session!.accessToken}`);
        proxyReq.setHeader('x-request-id', req.requestId);
      },
      error: (_err, _req, res) => {
        // res có thể là socket (websocket) — chỉ trả JSON khi là HTTP response
        if ('writeHead' in res && !res.headersSent) {
          res.writeHead(502, { 'content-type': 'application/problem+json' });
          res.end(JSON.stringify({ status: 502, code: 'bad_gateway', title: 'Service phía sau không phản hồi' }));
        }
      },
    },
  });
}
