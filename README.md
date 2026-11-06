# ol-bff

Backend-for-Frontend: OIDC Authorization Code + PKCE với Keycloak, session phía server (token mã hóa AES-256-GCM trong PostgreSQL), reverse proxy `/api/<service>/*` gắn Bearer token, chống CSRF, back-channel logout, rate limit.

## Cấu trúc

```text
src/
├── auth/              # OIDC (openid-client), guard phiên + CSRF, route /auth/*
├── session/           # Session store PostgreSQL, mã hóa token
├── proxy/             # Reverse proxy /api/<service>/*
├── app.ts / main.ts   # Dựng Express, khởi động server
└── migrate.ts         # Chạy migration (role *_migrator)
migrations/            # SQL migration — viết tay, review trong PR, không sửa file đã chạy
```

## Lệnh

| Lệnh | Ý nghĩa |
|---|---|
| `pnpm install` | Cài dependency (cần `$env:NODE_AUTH_TOKEN = gh auth token`) |
| `pnpm test` | Unit + integration test (integration cần Docker cho Testcontainers) |
| `pnpm typecheck` / `pnpm lint` / `pnpm format` | Kiểm tra kiểu / lint / định dạng |
| `pnpm build` | Biên dịch ra `dist/` |
| `pnpm db:new <tên>` | Tạo file migration mới |

Chạy cả hệ thống ở local: xem `ol-infra/local` và `ol-handbook/docs/02-source-code-va-local.md`.
