# OAuth 2.1 Authorization Server — Design Document

> **Status:** Draft v1
> **Scope:** `unauth/h3v2/oauth` — composable-per-endpoint OAuth 2.1 authorization server toolkit
> **Dependencies:** `unjwt` (JWS signing/verification), `unsecure` (PKCE hashing, secure compare, token generation), `h3` (peer)

---

## 1. Design Decisions

### API Shape: Composable per Endpoint

Each OAuth endpoint is its own factory, consistent with the `defineSession` / `defineTokenPair` / `defineCsrf` pattern. The developer registers each endpoint they need:

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

### Token Management: Built-in JWS/JWE

- **Access tokens:** JWS (signed JWT) created with `unjwt/jws` `sign()`. Standard claims: `sub`, `client_id`, `scope`, `exp`, `iat`, `iss`, `jti`. Developer can customize claims via `onAccessTokenClaims` hook.
- **Refresh tokens:** Opaque strings generated with `secureGenerate` from `unsecure`. Developer stores/retrieves them via hooks (`onSaveRefreshToken`, `onConsumeRefreshToken`).
- **Authorization codes:** Opaque strings generated with `secureGenerate`. Single-use, developer stores/consumes via hooks.
- **Device codes:** Opaque strings generated with `secureGenerate`. Developer stores/consumes via hooks.

### No Reuse of `defineSession` / `defineTokenPair`

OAuth bearer tokens are fundamentally different from cookie-based sessions:

- Delivered via JSON response body, not `Set-Cookie` headers
- Validated via `Authorization: Bearer` header, not cookies
- Storage is database-backed (developer-provided), not cookie-backed
- Refresh tokens have single-use rotation semantics, not sliding-window

The developer **can** use `defineSession` alongside the OAuth module for the authorization server's own login session (the "are you logged in to approve this grant?" state). The `onAuthorize` hook receives the `HTTPEvent`, so the developer can call their own `useSession(event)` inside it.

### Grant Types in Scope

1. **Authorization Code + PKCE** (RFC 6749 / OAuth 2.1)
2. **Client Credentials** (RFC 6749)
3. **Refresh Token** with rotation (RFC 6749)
4. **Device Authorization** (RFC 8628)

### OAuth 2.1 Security Enforcement

- PKCE is **required** for all authorization code grants (no `plain`, only `S256`)
- No implicit grant (removed in 2.1)
- No resource owner password credentials grant (removed in 2.1)
- Redirect URI exact match (no pattern matching)
- Refresh token rotation is enforced

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
            ├── _token.ts             (~120 LoC: JWS AT signing, opaque RT generation, response formatting)
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

type ClientAuthMethod = "client_secret_post" | "client_secret_basic" | "none";

// --- Authorization code ---
interface AuthorizationCodeData {
  code: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  userId: string;
  expiresAt: number;
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

---

## 5. Endpoint APIs

### `defineOAuthAuthorize`

```ts
interface OAuthAuthorizeOptions {
  /** Authorization code lifetime. Required (security-critical). */
  codeLifetime: ExpiresIn;
  /** Allowed scopes. If omitted, any scope string is accepted. */
  scopes?: string[];
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    /**
     * Called with a valid, validated authorization request.
     * Developer authenticates user and obtains consent.
     *
     * Return { userId, scope } to approve.
     * Return { error } to deny (redirect with error params).
     * Return { redirect } to redirect to login/consent page.
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
    onSaveAuthorizationCode(args: { code: AuthorizationCodeData; event: HTTPEvent }): Promise<void>;
    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthAuthorize(
  options: OAuthAuthorizeOptions,
): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**

- Validates `response_type=code` (only one allowed in 2.1)
- Validates `redirect_uri` exact match against registered URIs
- Validates `code_challenge` presence and `code_challenge_method=S256`
- Validates scope against server/client allowed scopes
- Calls `onAuthorize` for user authentication/consent
- On approval: generates auth code via `secureGenerate`, calls `onSaveAuthorizationCode`, redirects with `?code=...&state=...`
- Errors before redirect_uri validation: returns error response (not redirect)
- Errors after redirect_uri validation: redirects with error params

### `defineOAuthToken`

```ts
interface OAuthTokenOptions {
  /** JWS signing key for access tokens. */
  accessToken: {
    key: JWK;
    maxAge: ExpiresIn;
    /** JWT issuer claim. */
    issuer?: string;
  };
  /** Refresh token lifetime. Required if refresh_token grant is supported. */
  refreshToken?: {
    maxAge: ExpiresIn;
  };
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];

    // --- Authorization code grant ---
    /** Find and consume (delete) an authorization code. Must be single-use. */
    onConsumeAuthorizationCode?(args: {
      code: string;
      clientId: string;
      event: HTTPEvent;
    }): Promise<AuthorizationCodeData | undefined>;

    // --- Refresh token grant ---
    /** Validate and consume a refresh token. Must implement rotation. */
    onConsumeRefreshToken?(args: {
      refreshToken: string;
      clientId: string;
      event: HTTPEvent;
    }): Promise<{ userId?: string; scope: string } | undefined>;

    // --- Refresh token storage (shared by auth code + refresh grants) ---
    /** Store a newly generated refresh token. */
    onSaveRefreshToken?(args: {
      refreshToken: string;
      clientId: string;
      userId?: string;
      scope: string;
      expiresAt: number;
      event: HTTPEvent;
    }): Promise<void>;

    // --- Device code grant ---
    /** Validate and consume a device code. */
    onConsumeDeviceCode?(args: {
      deviceCode: string;
      clientId: string;
      event: HTTPEvent;
    }): Promise<DeviceCodeData | undefined>;

    // --- Claims customization ---
    /** Customize access token JWT claims. Return additional claims to merge. */
    onAccessTokenClaims?(args: {
      clientId: string;
      userId?: string;
      scope: string;
      grantType: OAuthGrantType;
      event: HTTPEvent;
    }): Promise<Record<string, unknown>>;

    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthToken(options: OAuthTokenOptions): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**

- Extracts client credentials (Basic auth or POST body)
- Validates client via `onFindClient`
- Authenticates confidential clients via `onVerifyClientSecret`
- Dispatches to grant handler based on `grant_type`
- Grant types are enabled based on which hooks are provided:
  - `onConsumeAuthorizationCode` → `authorization_code`
  - `onConsumeRefreshToken` + `onSaveRefreshToken` → `refresh_token`
  - Client credentials → enabled for confidential clients (no extra hooks)
  - `onConsumeDeviceCode` → `urn:ietf:params:oauth:grant-type:device_code`
- Generates JWS access token with `unjwt/jws` `sign()`
- Generates opaque refresh token with `unsecure` `secureGenerate()`
- Returns JSON: `{ access_token, token_type, expires_in, scope, refresh_token? }`
- Headers: `Content-Type: application/json`, `Cache-Control: no-store`

**Runtime guards (throw at factory call time):**

- `accessToken.key` is required
- `accessToken.maxAge` is required
- `hooks.onFindClient` is required
- If `onConsumeRefreshToken` is provided, `onSaveRefreshToken` must also be provided (and vice versa)
- If `onConsumeRefreshToken` is provided, `refreshToken.maxAge` is required

### `defineOAuthDeviceAuthorization`

```ts
interface OAuthDeviceAuthorizationOptions {
  /** Device code lifetime. Required. */
  deviceCodeLifetime: ExpiresIn;
  /** Minimum polling interval in seconds. @default 5 */
  pollingInterval?: number;
  /** The verification URI where the user enters the user code. Required. */
  verificationUri: string;
  /** Optional verification URI that includes the user code (template with {user_code}). */
  verificationUriComplete?: string;
  /** Allowed scopes. */
  scopes?: string[];
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    /** Store the device code data for later polling. */
    onSaveDeviceCode(args: { deviceCode: DeviceCodeData; event: HTTPEvent }): Promise<void>;
    onError?(args: { error: unknown; event: HTTPEvent }): void | Promise<void>;
  };
}

function defineOAuthDeviceAuthorization(
  options: OAuthDeviceAuthorizationOptions,
): (event: HTTPEvent) => Promise<Response>;
```

**Behavior:**

- Validates client (public clients allowed)
- Generates `device_code` (long, opaque) and `user_code` (short, user-friendly, e.g., `ABCD-1234`)
- Calls `onSaveDeviceCode`
- Returns JSON: `{ device_code, user_code, verification_uri, verification_uri_complete?, expires_in, interval }`

### `defineOAuthRevocation`

```ts
interface OAuthRevocationOptions {
  /** JWS key for verifying access tokens (to identify them). Optional. */
  accessToken?: { key: JWK };
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    /** Revoke a token. Always called — implementation should be idempotent. */
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

**Behavior:**

- Authenticates client
- Calls `onRevokeToken`
- Always returns 200 (per RFC 7009)

### `defineOAuthIntrospection`

```ts
interface OAuthIntrospectionOptions {
  /** JWS key for verifying access tokens locally. */
  accessToken?: { key: JWK };
  hooks: {
    onFindClient: ClientHooks["onFindClient"];
    onVerifyClientSecret?: ClientHooks["onVerifyClientSecret"];
    /** Introspect a token. Return active status and metadata. */
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

**Behavior:**

- Authenticates client
- If `accessToken.key` is provided and `tokenTypeHint` is `"access_token"` (or no hint), attempts JWS verification first
- Falls back to `onIntrospectToken` hook for opaque tokens / refresh tokens
- Returns `{ active: false }` for invalid tokens

---

## 6. Internal Module Responsibilities

### `_errors.ts`

- `oauthJsonError(code, description, statusCode)` → `Response` with `{ error, error_description }` JSON body
- `oauthRedirectError(redirectUri, code, description, state)` → redirect `Response` with error params in query
- Status code mapping: 400 for most, 401 for `invalid_client`, 403 for `access_denied`

### `_pkce.ts`

- `verifyCodeChallenge(codeVerifier, codeChallenge)` → `Promise<boolean>`
- Uses `hash(codeVerifier, { algorithm: "SHA-256", returnAs: "base64url" })` from `unsecure`, then `secureCompare` against stored challenge
- Only `S256` (OAuth 2.1 removes `plain`)
- Validates `code_verifier` length (43–128 chars per spec)

### `_client-auth.ts`

- `extractClientCredentials(event)` → `{ clientId, clientSecret? }` or `undefined`
- Extracts from `Authorization: Basic` header or POST body (`client_secret_post`)
- Public clients: only `client_id` from POST body, no secret
- Returns parsed credentials; validation against client config is done by the endpoint

### `_token.ts`

- `signAccessToken(key, claims, maxAge)` → `Promise<string>` — uses `unjwt/jws` `sign()`
- `generateRefreshToken()` → `string` — uses `secureGenerate({ length: 48, specials: false })`
- `generateAuthorizationCode()` → `string` — uses `secureGenerate({ length: 32, specials: false })`
- `generateDeviceCode()` → `string` — uses `secureGenerate({ length: 48, specials: false })`
- `generateUserCode()` → `string` — generates `XXXX-XXXX` format (alphanumeric, no ambiguous chars)
- `formatTokenResponse(data)` → `Response` — JSON with `Cache-Control: no-store`

---

## 7. Import Strategy

Following the project's established pattern:

| Module                  | Import style           | Reason             |
| ----------------------- | ---------------------- | ------------------ |
| `unjwt/jws`             | Static                 | Regular dependency |
| `unsecure`              | Static                 | Regular dependency |
| `h3v2` (types)          | Static `import type`   | Erased at build    |
| `h3v2` (runtime values) | `await import("h3v2")` | Optional peer dep  |

---

## 8. OIDC Extensibility

The architecture accommodates future OIDC by:

1. `onAccessTokenClaims` can return an `id_token` field to the response
2. `onAuthorize` can be extended with OIDC-specific fields (`nonce`, `acr_values`)
3. A future `defineOIDCProvider` can compose the existing endpoint factories
4. The `scope` system already supports `openid` as a scope string

---

## 9. Implementation Sequence

### Phase 1: Foundation

Files: `_types.ts`, `_errors.ts`, `_pkce.ts`, `_client-auth.ts`, `_token.ts`

1. Define all shared types
2. Implement OAuth error response helpers
3. Implement PKCE verification (S256 only)
4. Implement client credential extraction
5. Implement JWS access token signing, opaque token generation, response formatting
6. Write unit tests for PKCE and error formatting

### Phase 2: Authorization Code Grant

Files: `authorize.ts`, `token.ts`, `_grant-authorization-code.ts`

1. Implement authorization endpoint (`defineOAuthAuthorize`)
2. Implement auth code grant handler
3. Implement token endpoint dispatcher (`defineOAuthToken`)
4. Write integration tests for the full auth code + PKCE flow

### Phase 3: Client Credentials + Refresh

Files: `_grant-client-credentials.ts`, `_grant-refresh-token.ts`

1. Implement client credentials grant
2. Implement refresh token grant with rotation
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
- **Error handling split:** Authorization endpoint errors before redirect_uri validation must NOT redirect (return error page). Errors after validation redirect with error params. Token endpoint errors always return JSON.
- **Device code user code:** Must be short, unambiguous, easy to type. Use `BCDFGHJKLMNPQRSTVWXZ` (no vowels to avoid offensive words) in `XXXX-XXXX` format.

---

## 11. Critical Files to Reference

- `src/base/h3v2/token-pair.ts` — pattern: hook-based factory, runtime guards, type exports
- `src/base/h3v2/csrf.ts` — pattern: dynamic h3v2 imports, `unsecure` usage
- `src/h3v2.ts` — barrel file structure
- `build.config.ts` — build entry configuration
- `package.json` — export map
