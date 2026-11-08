// Test BFF không cần Keycloak/DB thật: session store trong bộ nhớ, OIDC giả, upstream giả.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLogger, HealthState } from '@ol/node-kit';
import { buildApp } from '../src/app.js';
import type { LoginTransaction, OidcPort } from '../src/auth/oidc.js';
import { hashSessionId, TokenSealer } from '../src/session/crypto.js';
import type { Session, SessionStore, Tokens } from '../src/session/session-store.js';

class MemoryStore implements SessionStore {
  m = new Map<string, Session>();
  async create(s: Omit<Session, 'lastSeenAt'>) {
    this.m.set(s.idHash, { ...s, lastSeenAt: new Date() });
  }
  async get(h: string) {
    return this.m.get(h) ?? null;
  }
  async touch() {}
  async refreshIfNeeded(
    h: string,
    needs: (s: Session) => boolean,
    refresh: (s: Session) => Promise<Tokens>,
  ) {
    const s = this.m.get(h);
    if (!s) return null;
    if (!needs(s)) return s;
    const next = { ...s, ...(await refresh(s)) };
    this.m.set(h, next);
    return next;
  }
  async delete(h: string) {
    this.m.delete(h);
  }
  async deleteByKeycloakSid(sid: string) {
    let n = 0;
    for (const [k, v] of this.m) if (v.keycloakSid === sid && this.m.delete(k)) n++;
    return n;
  }
  async deleteByUser(sub: string) {
    let n = 0;
    for (const [k, v] of this.m) if (v.userSub === sub && this.m.delete(k)) n++;
    return n;
  }
  async purgeExpired() {
    return 0;
  }
}

const sealer = new TokenSealer(Buffer.alloc(32, 7).toString('base64'));
const store = new MemoryStore();
let refreshCalls = 0;
const oidc: OidcPort = {
  async startLogin(returnTo) {
    return {
      url: 'https://id.ol.test/realms/ol/protocol/openid-connect/auth?x=1',
      tx: { state: 's', nonce: 'n', codeVerifier: 'v', returnTo },
    };
  },
  async finishLogin(_url: URL, tx: LoginTransaction) {
    if (tx.state !== 's') throw new Error('state');
    return {
      sub: '11111111-1111-4111-8111-111111111111',
      sid: 'kc-sid-1',
      email: 'a@acme.test',
      name: 'A',
      idToken: 'id',
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      accessExpiresAt: new Date(Date.now() + 300_000),
    };
  },
  async refresh() {
    refreshCalls++;
    return {
      idToken: 'id2',
      accessToken: 'access-2',
      refreshToken: 'refresh-2',
      accessExpiresAt: new Date(Date.now() + 300_000),
    };
  },
  async endSessionUrl() {
    return 'https://id.ol.test/logout';
  },
  async verifyLogoutToken(t: string) {
    if (t !== 'valid-logout-token') throw new Error('bad');
    return { sid: 'kc-sid-1', sub: null };
  },
};

// Upstream giả: trả lại header nhận được để kiểm tra
let upstream: Server;
let upstreamUrl = '';
let app: ReturnType<typeof buildApp>;

beforeAll(async () => {
  const u = express();
  u.use(
    (req, res) =>
      void res.json({
        path: req.url,
        authorization: req.headers.authorization ?? null,
        cookie: req.headers.cookie ?? null,
      }),
  );
  upstream = createServer(u).listen(0);
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  app = buildApp({
    logger: createLogger({ service: 'ol-bff-test', level: 'silent' }),
    health: new HealthState(),
    store,
    oidc,
    sealer,
    appUrl: 'https://app.ol.test',
    absoluteMs: 8 * 3_600_000,
    upstreams: { iam: upstreamUrl, warehouse: upstreamUrl },
    rateLimitPerMinute: 1000,
    fetchImpl: async () => new Response('{}', { status: 200 }),
  });
});

afterAll(() => {
  upstream.close();
});

async function login(): Promise<string> {
  const start = await request(app).get('/auth/login?returnTo=/warehouses').expect(302);
  const txCookie = (start.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
  const cb = await request(app)
    .get('/auth/callback?code=c&state=s')
    .set('cookie', txCookie)
    .expect(302);
  expect(cb.headers.location).toBe('/warehouses');
  const sessionCookie = (cb.headers['set-cookie'] as unknown as string[]).find((c) =>
    c.startsWith('__Host-ol_session='),
  )!;
  expect(sessionCookie).toMatch(/HttpOnly/);
  expect(sessionCookie).toMatch(/Secure/);
  return sessionCookie.split(';')[0]!;
}

describe('BFF', () => {
  it('chặn open redirect trong returnTo', async () => {
    const res = await request(app).get('/auth/login?returnTo=//evil.com').expect(302);
    const sealed = decodeURIComponent(
      (res.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!.split('=')[1]!,
    );
    expect(JSON.parse(sealer.open(sealed)).returnTo).toBe('/');
  });

  it('chưa đăng nhập → /api trả 401', async () => {
    await request(app).get('/api/warehouse/v1/x').expect(401);
  });

  it('đăng nhập → proxy gắn Bearer token, KHÔNG chuyển cookie vào nội bộ', async () => {
    const cookie = await login();
    const res = await request(app)
      .get('/api/warehouse/v1/tenants/t1/warehouses')
      .set('cookie', cookie)
      .expect(200);
    expect(res.body).toMatchObject({
      path: '/v1/tenants/t1/warehouses',
      authorization: 'Bearer access-1',
      cookie: null,
    });
  });

  it('trình duyệt không bao giờ thấy token trong /auth/session', async () => {
    const cookie = await login();
    const res = await request(app).get('/auth/session').set('cookie', cookie).expect(200);
    expect(JSON.stringify(res.body)).not.toContain('access-1');
    expect(res.body.authenticated).toBe(true);
  });

  it('POST thiếu header CSRF → 403; có header → qua', async () => {
    const cookie = await login();
    await request(app).post('/api/iam/v1/tenants').set('cookie', cookie).send({}).expect(403);
    await request(app)
      .post('/api/iam/v1/tenants')
      .set('cookie', cookie)
      .set('x-ol-csrf', '1')
      .send({})
      .expect(200);
  });

  it('Origin lạ → 403', async () => {
    const cookie = await login();
    await request(app)
      .post('/api/iam/v1/x')
      .set('cookie', cookie)
      .set('x-ol-csrf', '1')
      .set('origin', 'https://evil.com')
      .expect(403);
  });

  it('không truy cập được /internal qua BFF', async () => {
    const cookie = await login();
    await request(app)
      .post('/api/iam/internal/v1/authorize')
      .set('cookie', cookie)
      .set('x-ol-csrf', '1')
      .expect(404);
  });

  it('token sắp hết hạn → tự refresh trước khi proxy', async () => {
    const cookie = await login();
    const h = hashSessionId(cookie.split('=')[1]!);
    store.m.get(h)!.accessExpiresAt = new Date(Date.now() + 10_000);
    const before = refreshCalls;
    const res = await request(app).get('/api/iam/v1/me').set('cookie', cookie).expect(200);
    expect(refreshCalls).toBe(before + 1);
    expect(res.body.authorization).toBe('Bearer access-2');
  });

  it('back-channel logout xóa phiên theo sid', async () => {
    const cookie = await login();
    await request(app)
      .post('/auth/backchannel-logout')
      .type('form')
      .send({ logout_token: 'valid-logout-token' })
      .expect(200);
    await request(app).get('/api/iam/v1/me').set('cookie', cookie).expect(401);
  });

  it('logout token giả → 400', async () => {
    await request(app)
      .post('/auth/backchannel-logout')
      .type('form')
      .send({ logout_token: 'forged' })
      .expect(400);
  });
});

describe('TokenSealer', () => {
  it('mã hóa/giải mã và phát hiện dữ liệu bị sửa', () => {
    const sealed = sealer.seal('secret-token');
    expect(sealer.open(sealed)).toBe('secret-token');
    const tampered = sealed.slice(0, -2) + (sealed.endsWith('A') ? 'BB' : 'AA');
    expect(() => sealer.open(tampered)).toThrow();
  });
});
