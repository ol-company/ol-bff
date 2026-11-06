// Kho session phía server trên PostgreSQL.
import type pg from 'pg';
import type { TokenSealer } from './crypto.js';

export interface Tokens {
  idToken: string;
  accessToken: string;
  refreshToken: string | null;
  accessExpiresAt: Date;
}

export interface Session extends Tokens {
  idHash: string;
  userSub: string;
  keycloakSid: string | null;
  email: string | null;
  name: string | null;
  lastSeenAt: Date;
  absoluteExpiresAt: Date;
}

export interface SessionStore {
  create(s: Omit<Session, 'lastSeenAt'>): Promise<void>;
  get(idHash: string): Promise<Session | null>; // null nếu không có hoặc đã hết hạn
  touch(idHash: string): Promise<void>;
  // Làm mới token dưới khóa dòng: nhiều task BFF cùng refresh một session sẽ không giẫm lên nhau
  refreshIfNeeded(idHash: string, needsRefresh: (s: Session) => boolean, refresh: (s: Session) => Promise<Tokens>): Promise<Session | null>;
  delete(idHash: string): Promise<void>;
  deleteByKeycloakSid(sid: string): Promise<number>;
  deleteByUser(sub: string): Promise<number>;
  purgeExpired(): Promise<number>;
}

interface Row {
  id_hash: string;
  user_sub: string;
  keycloak_sid: string | null;
  email: string | null;
  name: string | null;
  id_token_enc: string;
  access_token_enc: string;
  refresh_token_enc: string | null;
  access_expires_at: Date;
  last_seen_at: Date;
  absolute_expires_at: Date;
}

export class PgSessionStore implements SessionStore {
  constructor(
    private readonly pool: pg.Pool,
    private readonly sealer: TokenSealer,
    private readonly idleMs: number,
  ) {}

  private toSession(r: Row): Session {
    return {
      idHash: r.id_hash,
      userSub: r.user_sub,
      keycloakSid: r.keycloak_sid,
      email: r.email,
      name: r.name,
      idToken: this.sealer.open(r.id_token_enc),
      accessToken: this.sealer.open(r.access_token_enc),
      refreshToken: r.refresh_token_enc ? this.sealer.open(r.refresh_token_enc) : null,
      accessExpiresAt: r.access_expires_at,
      lastSeenAt: r.last_seen_at,
      absoluteExpiresAt: r.absolute_expires_at,
    };
  }

  private alive(r: Row): boolean {
    const now = Date.now();
    return r.absolute_expires_at.getTime() > now && r.last_seen_at.getTime() + this.idleMs > now;
  }

  async create(s: Omit<Session, 'lastSeenAt'>) {
    await this.pool.query(
      `INSERT INTO bff.sessions (id_hash, user_sub, keycloak_sid, email, name, id_token_enc, access_token_enc, refresh_token_enc, access_expires_at, absolute_expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        s.idHash,
        s.userSub,
        s.keycloakSid,
        s.email,
        s.name,
        this.sealer.seal(s.idToken),
        this.sealer.seal(s.accessToken),
        s.refreshToken ? this.sealer.seal(s.refreshToken) : null,
        s.accessExpiresAt,
        s.absoluteExpiresAt,
      ],
    );
  }

  async get(idHash: string) {
    const { rows } = await this.pool.query<Row>('SELECT * FROM bff.sessions WHERE id_hash = $1', [idHash]);
    const row = rows[0];
    if (!row || !this.alive(row)) return null;
    return this.toSession(row);
  }

  async touch(idHash: string) {
    // Chỉ ghi khi lần cuối cách đây > 60 giây — giảm ghi DB cho mỗi request
    await this.pool.query(
      "UPDATE bff.sessions SET last_seen_at = now() WHERE id_hash = $1 AND last_seen_at < now() - interval '60 seconds'",
      [idHash],
    );
  }

  async refreshIfNeeded(idHash: string, needsRefresh: (s: Session) => boolean, refresh: (s: Session) => Promise<Tokens>) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // FOR UPDATE: task BFF khác đang refresh cùng session phải chờ ở đây
      const { rows } = await client.query<Row>('SELECT * FROM bff.sessions WHERE id_hash = $1 FOR UPDATE', [idHash]);
      const row = rows[0];
      if (!row || !this.alive(row)) {
        await client.query('ROLLBACK');
        return null;
      }
      const current = this.toSession(row);
      if (!needsRefresh(current)) {
        await client.query('COMMIT'); // Task khác vừa refresh xong → dùng luôn token mới
        return current;
      }
      const t = await refresh(current);
      await client.query(
        `UPDATE bff.sessions SET id_token_enc = $2, access_token_enc = $3, refresh_token_enc = $4, access_expires_at = $5 WHERE id_hash = $1`,
        [idHash, this.sealer.seal(t.idToken), this.sealer.seal(t.accessToken), t.refreshToken ? this.sealer.seal(t.refreshToken) : null, t.accessExpiresAt],
      );
      await client.query('COMMIT');
      return { ...current, ...t };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async delete(idHash: string) {
    await this.pool.query('DELETE FROM bff.sessions WHERE id_hash = $1', [idHash]);
  }

  async deleteByKeycloakSid(sid: string) {
    return (await this.pool.query('DELETE FROM bff.sessions WHERE keycloak_sid = $1', [sid])).rowCount ?? 0;
  }

  async deleteByUser(sub: string) {
    return (await this.pool.query('DELETE FROM bff.sessions WHERE user_sub = $1', [sub])).rowCount ?? 0;
  }

  async purgeExpired() {
    const res = await this.pool.query(
      'DELETE FROM bff.sessions WHERE absolute_expires_at < now() OR last_seen_at < now() - make_interval(secs => $1)',
      [Math.floor(this.idleMs / 1000)],
    );
    return res.rowCount ?? 0;
  }
}
