-- 0000_init — Session phía server của BFF.
-- Không lưu session id gốc: chỉ lưu SHA-256 của nó → lộ DB không lấy được cookie để giả danh.
-- Token được mã hóa AES-256-GCM bằng khóa SESSION_ENC_KEY (Secrets Manager) trước khi lưu.
CREATE TABLE bff.sessions (
  id_hash              text PRIMARY KEY,
  user_sub             uuid NOT NULL,
  keycloak_sid         text,
  email                text,
  name                 text,
  id_token_enc         text NOT NULL,
  access_token_enc     text NOT NULL,
  refresh_token_enc    text,
  access_expires_at    timestamptz NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  last_seen_at         timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_sid_idx ON bff.sessions (keycloak_sid);
CREATE INDEX sessions_sub_idx ON bff.sessions (user_sub);
CREATE INDEX sessions_last_seen_idx ON bff.sessions (last_seen_at);
