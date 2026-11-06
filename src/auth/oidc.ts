// OIDC client: Authorization Code + PKCE với Keycloak, refresh token, end-session, back-channel logout.
// Dùng thư viện openid-client (được chứng nhận OpenID) và jose — không tự hiện thực giao thức.
import { createRemoteJWKSet, jwtVerify } from 'jose';
import * as oidc from 'openid-client';
import type { Tokens } from '../session/session-store.js';

export interface LoginTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
}

export interface LoginResult extends Tokens {
  sub: string;
  sid: string | null;
  email: string | null;
  name: string | null;
}

export interface OidcPort {
  startLogin(returnTo: string): Promise<{ url: string; tx: LoginTransaction }>;
  finishLogin(callbackUrl: URL, tx: LoginTransaction): Promise<LoginResult>;
  refresh(refreshToken: string): Promise<Tokens>;
  endSessionUrl(idToken: string, postLogoutRedirect: string): Promise<string>;
  verifyLogoutToken(token: string): Promise<{ sid: string | null; sub: string | null }>;
}

export interface OidcOptions {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string; // APP_URL + /auth/callback — phải khớp chính xác trong Keycloak
  scopes: string;
}

export class OpenIdClient implements OidcPort {
  private configPromise?: Promise<oidc.Configuration>;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly o: OidcOptions) {
    this.jwks = createRemoteJWKSet(new URL(`${o.issuer}/protocol/openid-connect/certs`), { timeoutDuration: 2_000 });
  }

  // Tải metadata (.well-known/openid-configuration) lần đầu cần; lỗi thì lần sau thử lại
  private config(): Promise<oidc.Configuration> {
    this.configPromise ??= oidc.discovery(new URL(this.o.issuer), this.o.clientId, this.o.clientSecret).catch((err) => {
      this.configPromise = undefined;
      throw err;
    });
    return this.configPromise;
  }

  async startLogin(returnTo: string) {
    const config = await this.config();
    const codeVerifier = oidc.randomPKCECodeVerifier(); // Bí mật một lần, chống đánh cắp authorization code
    const state = oidc.randomState(); // Chống CSRF trên callback
    const nonce = oidc.randomNonce(); // Chống phát lại ID token
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: this.o.redirectUri,
      scope: this.o.scopes,
      code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
      state,
      nonce,
    });
    return { url: url.href, tx: { state, nonce, codeVerifier, returnTo } };
  }

  async finishLogin(callbackUrl: URL, tx: LoginTransaction): Promise<LoginResult> {
    const config = await this.config();
    // Thư viện tự kiểm: state, đổi code lấy token, chữ ký + iss + aud + nonce của ID token
    const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: tx.codeVerifier,
      expectedState: tx.state,
      expectedNonce: tx.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims()!;
    return {
      sub: claims.sub,
      sid: typeof claims.sid === 'string' ? claims.sid : null,
      email: typeof claims.email === 'string' ? claims.email : null,
      name: typeof claims.name === 'string' ? claims.name : null,
      idToken: tokens.id_token!,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token ?? null,
      accessExpiresAt: new Date(Date.now() + (tokens.expiresIn() ?? 300) * 1000),
    };
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    const config = await this.config();
    const t = await oidc.refreshTokenGrant(config, refreshToken);
    return {
      idToken: t.id_token ?? '',
      accessToken: t.access_token,
      refreshToken: t.refresh_token ?? refreshToken,
      accessExpiresAt: new Date(Date.now() + (t.expiresIn() ?? 300) * 1000),
    };
  }

  async endSessionUrl(idToken: string, postLogoutRedirect: string) {
    const config = await this.config();
    return oidc.buildEndSessionUrl(config, { id_token_hint: idToken, post_logout_redirect_uri: postLogoutRedirect }).href;
  }

  // OpenID Connect Back-Channel Logout 1.0 — mục 2.6 "Logout Token Validation"
  async verifyLogoutToken(token: string) {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.o.issuer,
      audience: this.o.clientId,
      maxTokenAge: '5m',
      algorithms: ['RS256', 'PS256', 'ES256'],
    });
    const events = payload.events as Record<string, unknown> | undefined;
    if (!events || !('http://schemas.openid.net/event/backchannel-logout' in events)) throw new Error('Thiếu sự kiện backchannel-logout');
    if ('nonce' in payload) throw new Error('Logout token không được có nonce');
    const sid = typeof payload.sid === 'string' ? payload.sid : null;
    const sub = typeof payload.sub === 'string' ? payload.sub : null;
    if (!sid && !sub) throw new Error('Logout token cần sid hoặc sub');
    return { sid, sub };
  }
}
