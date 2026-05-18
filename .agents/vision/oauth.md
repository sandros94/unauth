# OAuth 2.1 Authorization Server — Design Document

> **Status:** Draft v3 — updated for unjwt adapter improvements and resource protection middleware
> **Scope:** `unauth/h3v2/oauth` — composable-per-endpoint OAuth 2.1 authorization server toolkit
> **Dependencies:** `unjwt` (JWS/JWE session adapters, low-level encrypt/decrypt), `unsecure` (PKCE hashing, secure compare), `h3` (peer)

---

## 1. Design Decisions

### API Shape: Composable per Endpoint

Each OAuth endpoint is its own `defineOAuth*` factory, consistent with the `defineSession` / `defineTokenPair` / `defineCsrf` pattern:

```ts
import {
  defineOAuthAuthorize,
  defineOAuthToken,
  defineOAuthDeviceAuthorization,
  defineOAuthRevocation,
  defineOAuthIntrospection,
  requireOAuth,
  optionalOAuth,
} from "unauth/h3v2/oauth";

const authorize = defineOAuthAuthorize({ ... });
const token = defineOAuthToken({ ... });
const deviceAuthorize = defineOAuthDeviceAuthorization({ ... });
const revoke = defineOAuthRevocation({ ... });
const introspect = defineOAuthIntrospection({ ... });

app.all("/oauth/authorize", authorize);
app.post("/oauth/token", token);
app.post("/oauth/device_authorization", deviceAuthorize);
app.post("/oauth/revoke", revoke);
app.post("/oauth/introspect", introspect);

// Protect resource endpoints
app.get("/api/me", handler, { middleware: [requireOAuth(oauthTokenConfig)] });
```

Shared concerns (client authentication, scope validation) are internal helpers. The developer shares hooks across endpoints by spreading a common hooks object.

### Token Management: Built-in via unjwt Session Adapters

Mirrors the `defineTokenPair` approach — uses `useJWSSession` / `useJWESession` from `unjwt/adapters/h3v2`:

- **Access tokens:** JWS session (`useJWSSession`). Short-lived, client-readable. Cookie is set automatically; `session.token` provides the raw JWT for the JSON response body.
- **Refresh tokens:** JWE session (`useJWESession`). Long-lived, encrypted, httpOnly cookie. `session.token` provides the raw JWE for the JSON response body.
- **Authorization codes:** JWE via low-level `encrypt()` / `decrypt()` from `unjwt/jwe`. Stateless, db-less — the code itself is an encrypted token containing grant params (`sub`, `client_id`, `redirect_uri`, `scope`, `code_challenge`). Single-use enforcement relies on PKCE (db-less) or an optional hook (db-backed).
- **Device codes:** Opaque strings via `secureGenerate` from `unsecure`. Requires developer storage (inherent to the polling model).

### Token Delivery: JSON Body + Cookies

The token endpoint returns the standard OAuth JSON response **and** sets cookies via the unjwt session adapters:

```json
{
  "access_token": "<JWS>",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write",
  "refresh_token": "<JWE>"
}
```

Cookies provide frictionless SSR support (Nuxt, Nitro). The JSON body is spec-compliant for traditional OAuth clients. Cookies default to on (matching unjwt adapter behavior); developers can opt out with `cookie: false` on the unjwt config.

### DB-less by Default

The baseline flow requires **no database**:

- Authorization codes are self-contained JWE tokens
- Access tokens are JWS sessions (cookie-backed)
- Refresh tokens are JWE sessions (cookie-backed)
- PKCE prevents third-party auth code replay without needing jti tracking

Developers who need server-side token revocation add it via the optional `onCheckRevoked` hook. No opinionated features like token family IDs are built in — the developer can store whatever they need in the session data and check it in the hook.

### Mirrors `defineTokenPair`

The OAuth module uses the same unjwt primitives and patterns as `defineTokenPair`:

- `useJWSSession` for AT, `useJWESession` for RT
- Per-request caching via unjwt's `event.context` (no re-caching)
- unjwt lifecycle hooks (`onRead`, `onUpdate`, `onClear`, `onExpire`) wired to OAuth-specific logic
- `session.token` accessed in hooks and for the JSON response body (unjwt now guarantees `token: string` in `onRead` when `id` is present)
- Lower-level utilities (`updateJWSSession`, `updateJWESession`, `clearJWSSession`, `clearJWESession`) used in grant handlers where needed

The developer **can** also use `defineSession` alongside for the authorization server's own login session. The `onAuthorize` hook receives the `HTTPEvent` so the developer can call their own `useSession(event)` inside it.

### Keys: Separate per Purpose

Three distinct keys for security separation:

| Key      | Type                       | Used by                                    | Purpose                        |
| -------- | -------------------------- | ------------------------------------------ | ------------------------------ |
| AT key   | JWS (asymmetric/symmetric) | Token, Introspection, Revocation, Middleware | Sign/verify access tokens      |
| RT key   | JWE (symmetric/asymmetric) | Token                                      | Encrypt/decrypt refresh tokens |
| Code key | JWE (symmetric/asymmetric) | Authorize, Token                           | Encrypt/decrypt auth codes     |

### Client Model: Full Spec-Compliant

Always requires client registration (`client_id`, `client_type`, `redirect_uris`, `grant_types`, `token_endpoint_auth_method`). Both first-party and third-party clients are supported. A future `unauth` client implementation will make first-party usage frictionless.

### Scope Validation: String Matching + Optional Hook

Default behavior: plain string matching against a configured `scopes` list. Opt-in `onValidateScope` hook for custom logic (hierarchical scopes, dynamic scopes, etc.).

### Revocation: Optional `onCheckRevoked` Hook

DB-less users skip revocation (beyond clearing cookies). DB users implement the `onCheckRevoked` hook, which receives the session (with `id`/jti, `data`, and `token`) and a `clear()` function. The developer can check jti against a blocklist, inspect session data for family tracking, or any custom logic. No opinionated revocation strategy is built in.

The hook is part of the shared `OAuthTokenConfig` type, so it fires both during token endpoint operations **and** in the resource protection middleware (`requireOAuth` / `optionalOAuth`). It is wired into unjwt's `onRead` hook internally.

### Resource Protection Middleware

`requireOAuth` and `optionalOAuth` protect non-OAuth resource endpoints, analogous to `requireAuth` / `optionalAuth` from `defineTokenPair`. They read the access token from:

1. `Authorization: Bearer <token>` header (via unjwt's `sessionHeader: "Authorization"`)
2. Cookie fallback (for same-origin SSR clients)

Both share the `OAuthTokenConfig` type with `defineOAuthToken` for consistent key/cookie/revocation configuration.

### Grant Types in Scope

1. **Authorization Code + PKCE** (OAuth 2.1, mandatory S256)
2. **Client Credentials** (RFC 6749)
3. **Refresh Token** (RFC 6749)
4. **Device Authorization** (RFC 8628) — requires storage hooks

### OAuth 2.1 Security Enforcement

- PKCE is **required** for all authorization code grants (only `S256`)
- No implicit grant (removed in 2.1)
- No resource owner password credentials (removed in 2.1)
- Redirect URI exact match (no pattern matching)
- Authorization codes: PKCE-protected; optional hook for strict single-use enforcement

---

## 2. File Structure

```
src/
├── index.ts                          (modify: add h3v2OAuth re-export)
├── h3v2-oauth.ts                     (NEW: public barrel)
└── base/
    └── h3v2/
        └── oauth/
            ├── _types.ts             (~220 LoC: shared OAuth types, OAuthTokenConfig)
            ├── _errors.ts            (~80 LoC: OAuth error response helpers)
            ├── _pkce.ts              (~50 LoC: PKCE S256 validation)
            ├── _client-auth.ts       (~100 LoC: client credential extraction)
            ├── _response.ts          (~60 LoC: token response formatting)
            ├── authorize.ts          (~180 LoC: defineOAuthAuthorize)
            ├── token.ts              (~180 LoC: defineOAuthToken — grant dispatch)
            ├── _grant-authorization-code.ts  (~100 LoC)
            ├── _grant-client-credentials.ts  (~60 LoC)
            ├── _grant-refresh-token.ts       (~100 LoC: dual-source RT reading)
            ├── _grant-device-code.ts         (~80 LoC)
            ├── device-authorization.ts       (~120 LoC: defineOAuthDeviceAuthorization)
            ├── revocation.ts         (~80 LoC: defineOAuthRevocation)
            ├── introspection.ts      (~80 LoC: defineOAuthIntrospection)
            └── middleware.ts         (~80 LoC: requireOAuth, optionalOAuth)
```

```
test/
└── h3v2/
    └── oauth/
        ├── authorization-code.test.ts
        ├── client-credentials.test.ts
        ├── refresh-token.test.ts
        ├── device-authorization.test.ts
        ├── revocation.test.ts
        ├── introspection.test.ts
        ├── middleware.test.ts
        ├── pkce.test.ts
        └── _utils.ts              (test helpers: mock client store, token store)
```

---

## 3. Build & Export Configuration

**package.json** — add:

```jsonc
"./h3v2/oauth": {
  "types": "./dist/h3v2-oauth.d.mts",
  "import": "./dist/h3v2-oauth.mjs"
}
```

**build.config.ts** — add `"./src/h3v2-oauth.ts"` to the input array.

**src/index.ts** — add: `export * as h3v2OAuth from "./h3v2-oauth.ts";`

**src/h3v2-oauth.ts** — public barrel re-exporting:

- `defineOAuthAuthorize`, `OAuthAuthorizeOptions`
- `defineOAuthToken`, `OAuthTokenOptions`
- `defineOAuthDeviceAuthorization`, `OAuthDeviceAuthorizationOptions`
- `defineOAuthRevocation`, `OAuthRevocationOptions`
- `defineOAuthIntrospection`, `OAuthIntrospectionOptions`
- `requireOAuth`, `optionalOAuth`, `OAuthTokenConfig`
- `OAuthClient`, `OAuthGrantType`, `ClientAuthMethod`, `DeviceCodeData`
- `OAuthTokenResponse`, `IntrospectionResponse`, `OAuthErrorCode`

---

## 4. Type Design (`_types.ts`)

```ts
// --- Client ---
interface OAuthClient {
  clientId: string;
  clientType: "confidential" | "public";
  redirectUris: string[];
  grantTypes: OAuthGrantType[];
  scopes?: string[];
  tokenEndpointAuthMethod?: ClientAuthMethod;
}

type OAuthGrantType =
  | "authorization_code"
  | "client_credentials"
  | "refresh_token"
  | "urn:ietf:params:oauth:grant-type:device_code";

type ClientAuthMethod = "client_secret_post" | "client_secret_basic" | "none";

// --- Shared token configuration (used by defineOAuthToken + middleware) ---
interface OAuthTokenConfig<TAccess extends SessionData = SessionClaims> {
  accessToken: {
    key: SessionConfigJWS<TAccess, ExpiresIn>["key"];
    maxAge: ExpiresIn;
    /** @default "oauth_at" */
    name?: string;
    cookie?: SessionConfigJWS<TAccess, ExpiresIn>["cookie"];
    jws?: SessionConfigJWS<TAccess, ExpiresIn>["jws"];
    issuer?: string;
    /**
     * Header to read access tokens from.
     * The resource protection middleware (requireOAuth/optionalOAuth) defaults
     * this to "Authorization" to enable Bearer token support for API clients.
     * The token endpoint itself ignores this (it reads from grant params).
     * @default false (token endpoint) / "Authorization" (middleware)
     */
    sessionHeader?: false | string;
  };
  refreshToken: {
    key: SessionConfigJWE<SessionData, ExpiresIn>["key"];
    maxAge: ExpiresIn;
    /** @default "oauth_rt" */
    name?: string;
    cookie?: SessionConfigJWE<SessionData, ExpiresIn>["cookie"];
    jwe?: SessionConfigJWE<SessionData, ExpiresIn>["jwe"];
  };
  hooks?: {
    /**
     * Check if a token has been revoked. Receives the session (with jti,
     * data, and the raw token string) and a `clear()` function.
     * Call `clear()` to invalidate. DB-less users omit this hook.
     *
     * Wired into unjwt's `onRead` hook — fires on every token read
     * (token endpoint, middleware, etc.).
     */
    onCheckRevoked?(args: {
      session: { id: string; data: SessionData; createdAt: number; expiresAt: number; token: string };
      source: "access" | "refresh";
      event: HTTPEvent;
      clear(): Promise<void>;
    }): void | Promise<void>;
  };
}

// --- Device code ---
interface DeviceCodeData {
  deviceCode: string;
  userCode: string;
  clientId: string;
  scope: string;
  expiresAt: number;
  interval: number;
  userId?: string;
  approved?: boolean;
}

// --- Token response ---
interface OAuthTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  refresh_token?: string;
}

// --- Introspection response ---
interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  sub?: string;
  exp?: number;
  iat?: number;
  token_type?: string;
  [key: string]: unknown;
}

// --- Shared hook types ---
interface ClientHooks {
  onFindClient(args: { clientId: string; event: HTTPEvent }): Promise<OAuthClient | undefined>;

  onVerifyClientSecret?(args: {
    client: OAuthClient;
    clientSecret: string;
    event: HTTPEvent;
  }): Promise<boolean>;
}

// --- Error codes ---
type OAuthErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable"
  | "invalid_client"
  | "invalid_grant"
  | "unsupported_grant_type"
  | "invalid_token"
  | "authorization_pending"
  | "slow_down"
  | "expired_token";
```

Note: `AuthorizationCodeData` is **not** a stored type — the authorization code is a self-contained JWE. The claims inside the JWE are: `sub` (userId), `client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method`, `exp`, `iat`, `jti`.

---

## 5. Endpoint APIs

### `defineOAuthAuthorize`

```ts
interface OAuthAuthorizeOptions {
  /** JWE encryption key for authorization codes. Required. */
  code: {
    key: SessionConfigJWE["key"];
    maxAge: ExpiresIn;
  };
  /** Allowed scopes. If omitted, any scope string is accepted. */
  scopes?: string[];
  hooks: {
    onFindClient: ClientHooks["onFindClient"];

    /**
     * Called with a valid, validated authorization request.
     * Developer authenticates user and obtains consent.
     *
     * Return { userId, scope } to approve and issue a code.
     * Return { error } to deny (redirect with error params).
     * Return { redirect } to redirect to login/consent page
     *   (developer preserves OAuth params in their own session
     *    or passes them through as query params on the redirect URL).
     */
    onAuthorize(args: {
      client: OAuthClient;
      scope: string;
      state?: string;
      redirectUri: string;
      codeChallenge: string;
      codeChallengeMethod: "S256";
      event: HTTPEvent;
    }): Promise<
      | { userId: string; scope: string }
      | { error: OAuthErrorCode; errorDescription?: string }
      | { redirect: string }
    >;

    /** Optional scope validation. Return the validated/narrowed scope string. */
    onValidateScope?(args: {
      requestedScope: string;
      client: OAuthClient;
      event: HTTPEvent;
    }): Promise<string | undefined>;

    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthAuthorize(
  options: OAuthAuthorizeOptions,
): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**

- Validates `response_type=code` (only value allowed in 2.1)
- Validates `redirect_uri` exact match against `client.redirectUris`
- Validates `code_challenge` presence and `code_challenge_method=S256`
- Validates scope via `onValidateScope` hook or plain string matching against `scopes`
- Calls `onAuthorize` for user authentication/consent
- On approval: encrypts grant params into a JWE code via `encrypt()` from `unjwt/jwe` with `expiresIn: code.maxAge`, redirects with `?code=...&state=...`
- Errors before `redirect_uri` validation: returns error response (not redirect)
- Errors after `redirect_uri` validation: redirects with error params

**Runtime guards:** `code.key`, `code.maxAge`, `hooks.onFindClient`, `hooks.onAuthorize` are required.

**Note on authorization code lifetime:** The code is created via `encrypt(payload, key, { expiresIn: code.maxAge })` which sets the `exp` claim. On the token endpoint, `decrypt(code, key, { validateJWT: true })` automatically validates `exp` and throws on expired codes. No manual `computeExpiresInSeconds` call is needed.

### `defineOAuthToken`

```ts
interface OAuthTokenOptions extends OAuthTokenConfig {
  /** JWE key for decrypting authorization codes. Required if auth code grant is supported. */
  code?: {
    key: SessionConfigJWE["key"];
  };
  hooks: OAuthTokenConfig["hooks"] & {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];

    // --- Authorization code grant (optional hook for strict single-use) ---
    /**
     * Optional: called after decrypting a JWE auth code to enforce
     * strict single-use. Track the code's jti and reject replays.
     * DB-less users omit this — PKCE prevents third-party replay.
     */
    onConsumeAuthorizationCode?(args: {
      jti: string;
      clientId: string;
      event: HTTPEvent;
    }): Promise<boolean>;

    // --- Device code grant ---
    onConsumeDeviceCode?(args: {
      deviceCode: string;
      clientId: string;
      event: HTTPEvent;
    }): Promise<DeviceCodeData | undefined>;

    // --- Claims customization ---
    onAccessTokenClaims?(args: {
      clientId: string;
      userId?: string;
      scope: string;
      grantType: OAuthGrantType;
      event: HTTPEvent;
    }): Promise<Record<string, unknown>>;

    /** Optional scope validation. */
    onValidateScope?(args: {
      requestedScope: string;
      client: OAuthClient;
      event: HTTPEvent;
    }): Promise<string | undefined>;

    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthToken(options: OAuthTokenOptions): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**

- Extracts client credentials (Basic auth or POST body)
- Validates client via `onFindClient`
- Authenticates confidential clients via `onVerifyClientSecret`
- Dispatches to grant handler based on `grant_type`:
  - `authorization_code` — decrypts JWE code via `decrypt()` from `unjwt/jwe` with `validateJWT: true`, verifies PKCE, optionally calls `onConsumeAuthorizationCode`, issues AT+RT sessions
  - `client_credentials` — validates confidential client, issues AT session (no RT)
  - `refresh_token` — dual-source RT reading (see below), validates, rotates, issues new AT+RT
  - `urn:ietf:params:oauth:grant-type:device_code` — calls `onConsumeDeviceCode`
- AT issued via `updateJWSSession(event, atConfig, data)` → cookie set automatically, `session.token` for JSON body
- RT issued via `updateJWESession(event, rtConfig, data)` → cookie set automatically, `session.token` for JSON body
- Returns JSON: `{ access_token, token_type, expires_in, scope, refresh_token? }`
- Headers: `Content-Type: application/json`, `Cache-Control: no-store`

**Dual-source refresh token reading (`refresh_token` grant):**

1. Read `refresh_token` from POST body. If present:
   - Decrypt via `decrypt()` from `unjwt/jwe` using `refreshToken.key` with `validateJWT: true` to validate claims (`exp`, `iat`)
   - Extract session data (`sub`, `scope`, `client_id`, `jti`) from decrypted payload
   - If `onCheckRevoked` is configured, call it with the decrypted session data and the raw token string
2. If no POST body `refresh_token`: fall back to cookie via `useJWESession(event, rtConfig)` (same-origin clients). The session adapter handles reading, validation, and `onCheckRevoked` via its `onRead` hook.
3. On valid RT (from either source): issue new AT via `updateJWSSession(event, atConfig, data)` and new RT via `updateJWESession(event, rtConfig, data)`. Both set cookies AND provide `session.token` on the returned `SessionManager` for the JSON response body.

**Internal config construction:**

The token endpoint constructs unjwt session configs from `OAuthTokenOptions`, following the same pattern as `defineTokenPair` (`token-pair.ts:194-295`):

```ts
const rtConfig = {
  key: options.refreshToken.key,
  maxAge: options.refreshToken.maxAge,
  name: options.refreshToken.name ?? "oauth_rt",
  cookie: {
    httpOnly: true, secure: true, sameSite: "lax", path: "/",
    ...options.refreshToken.cookie,
  },
  jwe: options.refreshToken.jwe,
  hooks: {
    async onRead({ session, event }) {
      if (session.id && options.hooks?.onCheckRevoked) {
        await options.hooks.onCheckRevoked({
          session, source: "refresh", event,
          clear: () => clearJWESession(event, rtConfig),
        });
      }
    },
  },
} satisfies SessionConfigJWE;

const atConfig = {
  key: options.accessToken.key,
  maxAge: options.accessToken.maxAge,
  name: options.accessToken.name ?? "oauth_at",
  cookie: {
    httpOnly: false, secure: true, sameSite: "lax", path: "/",
    ...options.accessToken.cookie,
  },
  jws: options.accessToken.jws,
  hooks: {
    async onRead({ session, event }) {
      if (session.id && options.hooks?.onCheckRevoked) {
        await options.hooks.onCheckRevoked({
          session, source: "access", event,
          clear: () => clearJWSSession(event, atConfig),
        });
      }
    },
  },
} satisfies SessionConfigJWS;
```

These configs are reused by both the token endpoint grant handlers and the resource protection middleware.

**Runtime guards:**

- `accessToken.key` and `accessToken.maxAge` are required
- `refreshToken.key` and `refreshToken.maxAge` are required
- `hooks.onFindClient` is required
- If `code` is provided, `code.key` is required

### `requireOAuth` / `optionalOAuth`

```ts
function requireOAuth<TAccess extends SessionData = SessionClaims>(
  config: OAuthTokenConfig<TAccess>,
  options?: {
    onAuthenticated?(ctx: {
      session: SessionManager<TAccess>;
      event: HTTPEvent;
    }): void | Promise<void>;
  },
): (event: HTTPEvent) => Promise<void>;

function optionalOAuth<TAccess extends SessionData = SessionClaims>(
  config: OAuthTokenConfig<TAccess>,
  options?: {
    onAuthenticated?(ctx: {
      session: SessionManager<TAccess>;
      event: HTTPEvent;
    }): void | Promise<void>;
  },
): (event: HTTPEvent) => Promise<void>;
```

**Behavior:**

- Constructs `atConfig` from `config.accessToken` with `sessionHeader` defaulting to `"Authorization"` (enabling Bearer token support for API clients while falling back to cookie for SSR)
- Calls `useJWSSession(event, atConfig)` — unjwt tries the header first, then cookie
- `onCheckRevoked` is wired into the `onRead` hook of `atConfig` (shared from `OAuthTokenConfig`)
- `requireOAuth`: throws `HTTPError 401` if `!session.id`
- `optionalOAuth`: silently skips if `!session.id`
- Both accept optional `onAuthenticated` hook for authorization checks

**Usage:**

```ts
const oauthConfig: OAuthTokenConfig = {
  accessToken: { key: atKey, maxAge: "15m" },
  refreshToken: { key: rtKey, maxAge: "30D" },
  hooks: {
    async onCheckRevoked({ session, clear }) {
      if (await db.isRevoked(session.id)) await clear();
    },
  },
};

const token = defineOAuthToken({ ...oauthConfig, code: { key: codeKey }, hooks: { ...oauthConfig.hooks, onFindClient: ..., ... } });

app.get("/api/me", handler, { middleware: [requireOAuth(oauthConfig)] });
app.get("/api/feed", handler, { middleware: [optionalOAuth(oauthConfig)] });
```

### `defineOAuthDeviceAuthorization`

```ts
interface OAuthDeviceAuthorizationOptions {
  deviceCodeLifetime: ExpiresIn;
  pollingInterval?: number; // @default 5
  verificationUri: string;
  verificationUriComplete?: string; // template with {user_code}
  scopes?: string[];
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    onSaveDeviceCode(args: { deviceCode: DeviceCodeData; event: HTTPEvent }): Promise<void>;
    onValidateScope?(args: {
      requestedScope: string;
      client: OAuthClient;
      event: HTTPEvent;
    }): Promise<string | undefined>;
    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthDeviceAuthorization(
  options: OAuthDeviceAuthorizationOptions,
): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**

- Validates client (public clients allowed)
- Generates `device_code` (long, opaque) and `user_code` (short, e.g., `BCDG-HJKL`)
- Calls `onSaveDeviceCode`
- Returns JSON: `{ device_code, user_code, verification_uri, verification_uri_complete?, expires_in, interval }`
- Developer implements their own approval page and updates their storage directly

### `defineOAuthRevocation`

```ts
interface OAuthRevocationOptions {
  accessToken?: { key: SessionConfigJWS["key"] };
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    onRevokeToken(args: {
      token: string;
      tokenTypeHint?: "access_token" | "refresh_token";
      clientId: string;
      event: HTTPEvent;
    }): Promise<void>;
    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthRevocation(
  options: OAuthRevocationOptions,
): (event: HTTPEvent) => Promise<Response>;
```

Always returns 200 (per RFC 7009).

### `defineOAuthIntrospection`

```ts
interface OAuthIntrospectionOptions {
  accessToken?: { key: SessionConfigJWS["key"] };
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    onIntrospectToken?(args: {
      token: string;
      tokenTypeHint?: "access_token" | "refresh_token";
      clientId: string;
      event: HTTPEvent;
    }): Promise<IntrospectionResponse>;
    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthIntrospection(
  options: OAuthIntrospectionOptions,
): (event: HTTPEvent) => Promise<Response>;
```

If `accessToken.key` is provided, attempts local JWS verification first. Falls back to `onIntrospectToken` hook. Returns `{ active: false }` for invalid tokens.

---

## 6. Internal Module Responsibilities

### `_errors.ts`

- `oauthJsonError(code, description, statusCode)` → `Response` with `{ error, error_description }` JSON body
- `oauthRedirectError(redirectUri, code, description, state)` → redirect `Response` with error params in query
- Status code mapping: 400 for most, 401 for `invalid_client`, 403 for `access_denied`

### `_pkce.ts`

- `verifyCodeChallenge(codeVerifier, codeChallenge)` → `Promise<boolean>`
- Uses `hash(codeVerifier, { algorithm: "SHA-256", returnAs: "base64url" })` from `unsecure`, then `secureCompare`
- Only `S256` (OAuth 2.1 removes `plain`)
- Validates `code_verifier` length (43–128 chars per spec)

### `_client-auth.ts`

- `extractClientCredentials(event)` → `{ clientId, clientSecret? }` or `undefined`
- Extracts from `Authorization: Basic` header or POST body (`client_secret_post`)
- Public clients: `client_id` from POST body, no secret

### `_response.ts`

- `formatTokenResponse(data: OAuthTokenResponse)` → `Response` with JSON body, `Cache-Control: no-store`, `Content-Type: application/json`
- `generateUserCode()` → `string` — `XXXX-XXXX` format (consonants only, no ambiguous chars)

### `_grant-refresh-token.ts`

- Reads `refresh_token` from POST body first; if present, decrypts via `decrypt()` from `unjwt/jwe` with `validateJWT: true` using `rtConfig.key`
- Falls back to cookie-based RT via `useJWESession(event, rtConfig)` for same-origin clients
- On valid RT from either source: validates `client_id` matches the requesting client, calls `onCheckRevoked` if the token came from POST body (cookie path is handled by unjwt's `onRead` hook)
- Issues new AT via `updateJWSSession(event, atConfig, accessData)` and new RT via `updateJWESession(event, rtConfig, refreshData)`
- Returns both `session.token` values for the JSON response

---

## 7. Import Strategy

| Module                               | Import style           | Reason                                                   |
| ------------------------------------ | ---------------------- | -------------------------------------------------------- |
| `unjwt/adapters/h3v2`                | Static                 | Session adapters: `useJWSSession`, `useJWESession`, `updateJWSSession`, `updateJWESession`, `clearJWSSession`, `clearJWESession`, `verifyJWSSession` |
| `unjwt/jwe`                          | Static                 | Auth code encrypt/decrypt: `encrypt`, `decrypt`          |
| `unsecure`                           | Static                 | PKCE: `hash`, `secureCompare`. Tokens: `secureGenerate`  |
| `h3v2` (types)                       | Static `import type`   | Erased at build                                          |
| `h3v2` (runtime values)              | `await import("h3v2")` | Optional peer dep: `HTTPError`, `readBody`               |

---

## 8. OIDC Extensibility

The architecture accommodates future OIDC by:

1. `onAccessTokenClaims` can return custom claims; token response can be extended with `id_token`
2. `onAuthorize` can be extended with OIDC-specific fields (`nonce`, `acr_values`)
3. A future `defineOIDCProvider` can compose the existing endpoint factories
4. The `scope` system already supports `openid` as a scope string
5. JWE auth codes can carry additional OIDC state (`nonce`) in their encrypted payload

---

## 9. Implementation Sequence

### Phase 1: Foundation

Files: `_types.ts`, `_errors.ts`, `_pkce.ts`, `_client-auth.ts`, `_response.ts`

1. Define all shared types including `OAuthTokenConfig`
2. Implement OAuth error response helpers
3. Implement PKCE verification (S256 only)
4. Implement client credential extraction
5. Implement token response formatting and user code generation
6. Write unit tests for PKCE and error formatting

### Phase 2: Authorization Code Grant + Resource Protection

Files: `authorize.ts`, `token.ts`, `_grant-authorization-code.ts`, `middleware.ts`

1. Implement authorization endpoint (`defineOAuthAuthorize`) with JWE code generation
2. Implement auth code grant handler with JWE code decryption + PKCE verification
3. Implement token endpoint dispatcher (`defineOAuthToken`) with unjwt session adapters for AT/RT
4. Implement `requireOAuth` and `optionalOAuth` middleware using shared `OAuthTokenConfig`
5. Write integration tests for the full auth code + PKCE flow (db-less)
6. Write tests for middleware (cookie-based and Bearer header-based AT reading)

### Phase 3: Client Credentials + Refresh

Files: `_grant-client-credentials.ts`, `_grant-refresh-token.ts`

1. Implement client credentials grant (AT only, no RT)
2. Implement refresh token grant with dual-source RT reading (POST body + cookie fallback)
3. Write tests for both, including third-party refresh (POST body) and same-origin refresh (cookie)

### Phase 4: Device Authorization

Files: `device-authorization.ts`, `_grant-device-code.ts`

1. Implement device authorization endpoint (`defineOAuthDeviceAuthorization`)
2. Implement device code grant handler in token endpoint
3. Write tests

### Phase 5: Revocation + Introspection

Files: `revocation.ts`, `introspection.ts`

1. Implement revocation endpoint (`defineOAuthRevocation`)
2. Implement introspection endpoint (`defineOAuthIntrospection`)
3. Write tests

### Phase 6: Integration

Files: `h3v2-oauth.ts`, `package.json`, `build.config.ts`, `src/index.ts`

1. Create the barrel file
2. Add export path and build entry
3. End-to-end test of the full flow
4. Run `pnpm fmt`, `pnpm typecheck`, `pnpm test`

---

## 10. Potential Challenges

- **Request body parsing:** Token endpoint reads `application/x-www-form-urlencoded`. Use h3v2's `readFormData` or `readBody` via dynamic import.
- **Redirect responses:** Use `new Response(null, { status: 302, headers: { Location: url } })` for platform neutrality.
- **Error handling split:** Authorization endpoint errors before `redirect_uri` validation must NOT redirect. Errors after validation redirect with error params. Token endpoint errors always return JSON.
- **Session adapter cookie names:** OAuth defaults to `oauth_at` / `oauth_rt`. `defineTokenPair` uses `auth_at` / `auth_rt`. Neither uses unjwt's raw defaults (`h3-jws` / `h3-jwe`). Avoid `access_token` / `refresh_token` as cookie names — they conflict with POST body parameter names in the token endpoint's `application/x-www-form-urlencoded` requests.
- **Device code user code:** Must be short, unambiguous, easy to type. Use consonants only (`BCDFGHJKLMNPQRSTVWXZ`, no vowels to avoid offensive words) in `XXXX-XXXX` format.
- **JWE auth code size:** A JWE containing grant params will be longer than an opaque code (~200-400 chars). This is fine for redirect URLs but worth noting.
- **Session adapter caching with dual-source RT:** unjwt caches sessions in `event.context` per cookie name. When the refresh token arrives via POST body (not cookie), decrypt it directly with `decrypt()` from `unjwt/jwe` — do NOT pass it through `useJWESession` (would prime the cache incorrectly). Use `updateJWESession(event, rtConfig, newData)` to issue the new RT (which sets the cookie and creates the cache entry). For the new AT, use `updateJWSSession(event, atConfig, accessData)`. Both return the updated `SessionManager` with `.token` for the JSON response.

---

## 11. Critical Files to Reference

- `src/base/h3v2/token-pair.ts:194-295` — pattern: unjwt session config construction (`atConfig`/`rtConfig`), cookie defaults, `onRead` hook wiring
- `src/base/h3v2/token-pair.ts:347-381` — pattern: resource protection middleware (`requireAuth`/`optionalAuth`)
- `src/base/h3v2/session.ts:34,56` — pattern: hook `session` type with `{ id: string; token: string }` (unjwt guarantee)
- `src/base/h3v2/csrf.ts` — pattern: dynamic h3v2 imports, `unsecure` usage
- `src/h3v2.ts` — barrel file structure
- `build.config.ts` — build entry configuration
- `package.json` — export map
