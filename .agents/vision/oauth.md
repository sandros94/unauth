# OAuth 2.1 Authorization Server — Design Document

> **Status:** Draft v2 — refined from Q&A session on 2026-03-24
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
- `session.token` accessed for the JSON response body
- Lower-level utilities (`updateJWSSession`, `updateJWESession`, etc.) used in hooks where needed

The developer **can** also use `defineSession` alongside for the authorization server's own login session. The `onAuthorize` hook receives the `HTTPEvent` so the developer can call their own `useSession(event)` inside it.

### Keys: Separate per Purpose

Three distinct keys for security separation:

| Key | Type | Used by | Purpose |
|-----|------|---------|---------|
| AT key | JWS (asymmetric/symmetric) | Token, Introspection, Revocation | Sign/verify access tokens |
| RT key | JWE (symmetric/asymmetric) | Token | Encrypt/decrypt refresh tokens |
| Code key | JWE (symmetric/asymmetric) | Authorize, Token | Encrypt/decrypt auth codes |

### Client Model: Full Spec-Compliant

Always requires client registration (`client_id`, `client_type`, `redirect_uris`, `grant_types`, `token_endpoint_auth_method`). Both first-party and third-party clients are supported. A future `unauth` client implementation will make first-party usage frictionless.

### Scope Validation: String Matching + Optional Hook

Default behavior: plain string matching against a configured `scopes` list. Opt-in `onValidateScope` hook for custom logic (hierarchical scopes, dynamic scopes, etc.).

### Revocation: Optional `onCheckRevoked` Hook

DB-less users skip revocation (beyond clearing cookies). DB users implement the `onCheckRevoked` hook, which receives the session (with `id`/jti and `data`) and a `clear()` function. The developer can check jti against a blocklist, inspect session data for family tracking, or any custom logic. No opinionated revocation strategy is built in.

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
            ├── _types.ts             (~180 LoC: shared OAuth types)
            ├── _errors.ts            (~80 LoC: OAuth error response helpers)
            ├── _pkce.ts              (~50 LoC: PKCE S256 validation)
            ├── _client-auth.ts       (~100 LoC: client credential extraction)
            ├── _response.ts          (~60 LoC: token response formatting)
            ├── authorize.ts          (~180 LoC: defineOAuthAuthorize)
            ├── token.ts              (~180 LoC: defineOAuthToken — grant dispatch)
            ├── _grant-authorization-code.ts  (~100 LoC)
            ├── _grant-client-credentials.ts  (~60 LoC)
            ├── _grant-refresh-token.ts       (~80 LoC)
            ├── _grant-device-code.ts         (~80 LoC)
            ├── device-authorization.ts       (~120 LoC: defineOAuthDeviceAuthorization)
            ├── revocation.ts         (~80 LoC: defineOAuthRevocation)
            └── introspection.ts      (~80 LoC: defineOAuthIntrospection)
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

**src/h3v2-oauth.ts** — public barrel re-exporting from `base/h3v2/oauth/*.ts` (public files only).

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

type ClientAuthMethod =
  | "client_secret_post"
  | "client_secret_basic"
  | "none";

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
  onFindClient(args: {
    clientId: string;
    event: HTTPEvent;
  }): Promise<OAuthClient | undefined>;

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
- On approval: encrypts grant params into a JWE code via `encrypt()` from `unjwt/jwe`, redirects with `?code=...&state=...`
- Errors before `redirect_uri` validation: returns error response (not redirect)
- Errors after `redirect_uri` validation: redirects with error params

**Runtime guards:** `code.key`, `code.maxAge`, `hooks.onFindClient`, `hooks.onAuthorize` are required.

### `defineOAuthToken`

```ts
interface OAuthTokenOptions {
  /** JWS access token configuration (mirrors defineTokenPair's access config). */
  accessToken: {
    key: SessionConfigJWS["key"];
    maxAge: ExpiresIn;
    name?: string;
    cookie?: SessionConfigJWS["cookie"];
    jws?: SessionConfigJWS["jws"];
    issuer?: string;
  };
  /** JWE refresh token configuration (mirrors defineTokenPair's refresh config). */
  refreshToken: {
    key: SessionConfigJWE["key"];
    maxAge: ExpiresIn;
    name?: string;
    cookie?: SessionConfigJWE["cookie"];
    jwe?: SessionConfigJWE["jwe"];
  };
  /** JWE key for decrypting authorization codes. Required if auth code grant is supported. */
  code?: {
    key: SessionConfigJWE["key"];
  };
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];

    // --- Optional revocation check (runs on token read) ---
    /**
     * Check if a token has been revoked. Receives the session (with jti
     * and data) and a `clear()` function. Call `clear()` to invalidate.
     * DB-less users omit this hook.
     */
    onCheckRevoked?(args: {
      session: { id: string; data: SessionData; createdAt: number; expiresAt: number };
      source: "access" | "refresh";
      event: HTTPEvent;
      clear(): Promise<void>;
    }): void | Promise<void>;

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

function defineOAuthToken(
  options: OAuthTokenOptions,
): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**
- Extracts client credentials (Basic auth or POST body)
- Validates client via `onFindClient`
- Authenticates confidential clients via `onVerifyClientSecret`
- Dispatches to grant handler based on `grant_type`:
  - `authorization_code` — decrypts JWE code, verifies PKCE, optionally calls `onConsumeAuthorizationCode`, issues AT+RT sessions
  - `client_credentials` — validates confidential client, issues AT session (no RT)
  - `refresh_token` — reads RT session via `useJWESession`, rotates, issues new AT+RT
  - `urn:ietf:params:oauth:grant-type:device_code` — calls `onConsumeDeviceCode`
- AT created via `useJWSSession` + `session.update()` → cookie set automatically, `session.token` for JSON body
- RT created via `useJWESession` + `session.update()` → cookie set automatically, `session.token` for JSON body
- Returns JSON: `{ access_token, token_type, expires_in, scope, refresh_token? }`
- Headers: `Content-Type: application/json`, `Cache-Control: no-store`

**Runtime guards:**
- `accessToken.key` and `accessToken.maxAge` are required
- `refreshToken.key` and `refreshToken.maxAge` are required
- `hooks.onFindClient` is required
- If `code` is provided, `code.key` is required

### `defineOAuthDeviceAuthorization`

```ts
interface OAuthDeviceAuthorizationOptions {
  deviceCodeLifetime: ExpiresIn;
  pollingInterval?: number;          // @default 5
  verificationUri: string;
  verificationUriComplete?: string;  // template with {user_code}
  scopes?: string[];
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    onSaveDeviceCode(args: {
      deviceCode: DeviceCodeData;
      event: HTTPEvent;
    }): Promise<void>;
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

---

## 7. Import Strategy

| Module | Import style | Reason |
|--------|-------------|--------|
| `unjwt/adapters/h3v2` | Static | Regular dependency (session adapters) |
| `unjwt/jwe` | Static | Regular dependency (auth code encrypt/decrypt) |
| `unsecure` | Static | Regular dependency (hash, secureCompare) |
| `h3v2` (types) | Static `import type` | Erased at build |
| `h3v2` (runtime values) | `await import("h3v2")` | Optional peer dep |

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

1. Define all shared types
2. Implement OAuth error response helpers
3. Implement PKCE verification (S256 only)
4. Implement client credential extraction
5. Implement token response formatting and user code generation
6. Write unit tests for PKCE and error formatting

### Phase 2: Authorization Code Grant
Files: `authorize.ts`, `token.ts`, `_grant-authorization-code.ts`

1. Implement authorization endpoint (`defineOAuthAuthorize`) with JWE code generation
2. Implement auth code grant handler with JWE code decryption + PKCE verification
3. Implement token endpoint dispatcher (`defineOAuthToken`) with unjwt session adapters for AT/RT
4. Write integration tests for the full auth code + PKCE flow (db-less)

### Phase 3: Client Credentials + Refresh
Files: `_grant-client-credentials.ts`, `_grant-refresh-token.ts`

1. Implement client credentials grant (AT only, no RT)
2. Implement refresh token grant via JWE session rotation
3. Write tests for both

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
- **Session adapter cookie names:** Default AT/RT cookie names should differ from `defineTokenPair` defaults to avoid conflicts when both are used. Suggest `oauth_at` / `oauth_rt`.
- **Device code user code:** Must be short, unambiguous, easy to type. Use consonants only (`BCDFGHJKLMNPQRSTVWXZ`, no vowels to avoid offensive words) in `XXXX-XXXX` format.
- **JWE auth code size:** A JWE containing grant params will be longer than an opaque code (~200-400 chars). This is fine for redirect URLs but worth noting.

---

## 11. Critical Files to Reference

- `src/base/h3v2/token-pair.ts` — pattern: unjwt session adapters, hook-based factory, runtime guards, `session.token` access
- `src/base/h3v2/csrf.ts` — pattern: dynamic h3v2 imports, `unsecure` usage
- `src/h3v2.ts` — barrel file structure
- `build.config.ts` — build entry configuration
- `package.json` — export map
