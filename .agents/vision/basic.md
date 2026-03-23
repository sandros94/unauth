# `unauth/basic` — Planning Document

> **Status:** Draft v2
> **Scope:** Core types + h3v2 adapter only
> **Dependencies:** `unjwt@^0.5.39`, `h3@^2.0.1` (peer), `unsecure` (WebCrypto-based utils for hmac, secure strings, etc.)

---

## 1. Design Principles

1. **Core is types-only.** `unauth/basic` exports zero runtime code — only `type` and `interface` declarations. All behavior lives in adapters.
2. **Adapters own the lifecycle.** Session caching, cookie management, hook execution, and context population are adapter concerns. The core never assumes a transport.
3. **No re-caching.** h3 adapters delegate entirely to `unjwt/adapters/h3v2` functions, which already cache resolved sessions on `event.context` with consistent internal keys and lazy promise resolution. `unauth` never introduces its own caching layer.
4. **Hooks are maximally informative.** Every hook receives the full context a developer might need — session managers, ids, expiry timestamps, framework context. We do not assume what they will or won't do.
5. **Adapters extend core types.** Core defines framework-agnostic hook shapes. Each adapter augments them with its own context (e.g., `H3Event`).
6. **Transparent session access.** Token pair composables expose the underlying unjwt session managers directly. Coordinated methods (`login`, `logout`) go through hooks; direct manager access is the escape hatch for advanced users.
7. **No hardcoded security policies.** Features like jti tracking, token family revocation, and replay detection are enabled through rich hook context — not built-in toggles. Developers implement these in application logic based on their project's requirements.
8. **Granular exports, optional barrel.** Each adapter utility (`token-pair`, `session`, `middleware`, `csrf`) is importable as a standalone sub-path with no sibling re-exports. A convenience barrel (`unauth/basic/h3v2`) is provided for quick prototyping and relies on `sideEffects: false` for production tree-shaking. This avoids the barrel file performance trap in Vite dev servers and environments where tree-shaking is unreliable.

---

## 2. Export Map

```jsonc
// package.json (relevant subset)
{
  "sideEffects": false,
  "exports": {
    // Types only — zero runtime bytes, barrel is fine here
    "./basic": {
      "types": "./dist/basic/index.d.ts",
    },
    // Adapter barrel — convenience re-export of all runtime utilities.
    // Consumers who want maximum tree-shaking can use the granular
    // sub-paths below instead.
    "./basic/h3v2": {
      "types": "./dist/basic/h3v2/index.d.ts",
      "import": "./dist/basic/h3v2/index.mjs",
    },
    // Granular sub-paths — avoid barrel overhead for consumers who
    // only need a specific utility. Each maps to a single module
    // with no re-exports of siblings.
    "./basic/h3v2/token-pair": {
      "types": "./dist/basic/h3v2/token-pair.d.ts",
      "import": "./dist/basic/h3v2/token-pair.mjs",
    },
    "./basic/h3v2/session": {
      "types": "./dist/basic/h3v2/session.d.ts",
      "import": "./dist/basic/h3v2/session.mjs",
    },
    "./basic/h3v2/middleware": {
      "types": "./dist/basic/h3v2/middleware.d.ts",
      "import": "./dist/basic/h3v2/middleware.mjs",
    },
    "./basic/h3v2/csrf": {
      "types": "./dist/basic/h3v2/csrf.d.ts",
      "import": "./dist/basic/h3v2/csrf.mjs",
    },
    // Future:
    // "./basic/h3v1": { ... }
    // "./basic/h3v1/token-pair": { ... }
    // "./oauth": { "types": ... }
    // "./oauth/h3v2": { ... }
    // "./oidc": { "types": ... }
    // "./oidc/h3v2": { ... }
  },
}
```

**Import guidance for consumers:**

```ts
// Option A: barrel import — convenient, relies on tree-shaking + sideEffects: false
import { defineTokenPair, requireAuth } from "unauth/basic/h3v2";

// Option B: granular import — zero barrel overhead, best for Vite dev server
//           and environments where tree-shaking is unreliable
import { defineTokenPair } from "unauth/basic/h3v2/token-pair";
import { requireAuth } from "unauth/basic/h3v2/middleware";
```

---

## 3. Core Types — `unauth/basic`

### 3.1 File Structure

```
src/basic/
├── types/
│   ├── session.ts
│   ├── token-pair.ts
│   ├── csrf.ts
│   ├── middleware.ts
│   └── shared.ts
└── index.ts            → barrel re-export of all types
```

### 3.2 Shared Types

```ts
// types/shared.ts

import type { ExpiresIn } from "unjwt/utils";

export type { ExpiresIn };

/**
 * Generic managed session interface.
 * Mirrors unjwt's SessionManager shape so adapters can return
 * the real unjwt session manager directly (transparent access).
 */
export interface ManagedSession<T> {
  /** jti — undefined if session was never initialized */
  readonly id: string | undefined;
  /** Session payload (excludes jti/iat/exp) */
  readonly data: T;
  /** iat in ms */
  readonly createdAt: number;
  /** exp in ms — undefined if no maxAge configured */
  readonly expiresAt: number | undefined;
  /** Raw JWT token string — undefined if session is empty */
  readonly token: string | undefined;
  /** Update session data, re-issue token, set cookie */
  update(data: Partial<T> | ((old: T) => Partial<T> | undefined)): Promise<ManagedSession<T>>;
  /** Clear session (delete cookie, reset state) */
  clear(): Promise<ManagedSession<T>>;
}
```

### 3.3 Single Session Types

```ts
// types/session.ts

import type { ExpiresIn, ManagedSession } from "./shared";

/**
 * Hooks for a single managed session with auto-refresh.
 * Adapters extend each callback's argument with framework context.
 */
export interface SessionHooks<T> {
  /**
   * Fires after the session is successfully read and validated.
   */
  onRead?(ctx: { session: ManagedSession<T> }): void | Promise<void>;

  /**
   * Fires after the session data is updated and persisted.
   * Receives both old and new snapshots for diffing/auditing.
   */
  onUpdate?(ctx: {
    session: ManagedSession<T>;
    oldSession: ManagedSession<T>;
  }): void | Promise<void>;

  /**
   * Fires when auto-refresh is triggered (session is past the
   * refresh threshold but not yet expired).
   *
   * Three outcomes:
   * - Return `T`          → refresh with the provided data
   * - Return void         → refresh with current data (sliding window)
   * - Throw               → abort refresh, current session preserved as-is,
   *                          error forwarded to onError
   */
  onRefresh?(ctx: {
    session: ManagedSession<T>;
  }): T | void | undefined | Promise<T | void | undefined>;

  /**
   * Fires when the session is explicitly cleared.
   * The session reflects the state BEFORE clearing.
   * Use to mark tokens as revoked in external storage.
   */
  onClear?(ctx: { session: ManagedSession<T> }): void | Promise<void>;

  /**
   * Fires when the session token is expired or missing entirely.
   */
  onExpire?(ctx: { error: unknown }): void | Promise<void>;

  /**
   * Fires on any non-expiry error during session operations
   * (decryption failure, malformed token, key mismatch, etc.).
   */
  onError?(ctx: { error: unknown }): void | Promise<void>;
}

export interface SessionConfig<T> {
  /** Session lifetime */
  maxAge?: ExpiresIn;
  /** Cookie/token name */
  name?: string;
  /**
   * When to auto-refresh the session, as a ratio of maxAge (0 to 1).
   * For example, 0.75 means refresh after 75% of the session's
   * lifetime has elapsed.
   *
   * Set to `false` to disable auto-refresh.
   * Default: 0.75
   */
  refreshAfter?: number | false;
  /** Lifecycle hooks */
  hooks?: SessionHooks<T>;
}
```

### 3.4 Token Pair Types

```ts
// types/token-pair.ts

import type { ExpiresIn, ManagedSession } from "./shared";

/**
 * Token pair hooks. All context includes the full session managers
 * so developers have everything they need for any use-case:
 * replay detection, jti tracking, family revocation, audit logging,
 * OpenTelemetry, external store sync, etc.
 */
export interface TokenPairHooks<TAccess, TRefresh> {
  /**
   * Fires when the access token is expired or missing and a valid
   * refresh token exists.
   *
   * Three outcomes:
   * - Return `TAccess`   → refresh succeeds, new AT issued, RT rotated
   * - Return `undefined`  → deliberate rejection, both tokens cleared
   *                          (user banned, family revoked, etc.)
   * - Throw               → abort without destroying state, RT preserved,
   *                          AT stays empty, error forwarded to onError
   *
   * The refresh session manager is provided in full — read .id,
   * .data, .expiresAt, .token for any decision-making you need.
   *
   * Common use-cases:
   * - Hydrate fresh permissions/roles from a database
   * - Check if the user/session/token-family has been revoked
   * - Validate device fingerprint, IP range, etc.
   * - Implement custom jti tracking against an external store
   */
  onRefresh(ctx: {
    /** The valid refresh session manager (full access) */
    refresh: ManagedSession<TRefresh>;
    /** The expired/empty access session manager */
    access: ManagedSession<TAccess>;
  }): Promise<TAccess | undefined> | TAccess | undefined;

  /**
   * Fires after a successful refresh cycle — the access token has
   * been re-issued and the refresh token has been rotated (consumed).
   * Both sessions reflect their NEW state after rotation.
   *
   * Common use-cases:
   * - Audit logging / OpenTelemetry spans
   * - Updating external session stores with new token ids
   * - Analytics (refresh frequency, token age at refresh)
   * - Storing the new access jti for replay detection
   */
  onAfterRefresh?(ctx: {
    access: ManagedSession<TAccess>;
    refresh: ManagedSession<TRefresh>;
    /** Snapshot of the access session BEFORE refresh (may be empty/expired) */
    previousAccess: {
      id: string | undefined;
      data: TAccess;
      createdAt: number;
      expiresAt: number | undefined;
    };
    /** Snapshot of the refresh session BEFORE rotation */
    previousRefresh: {
      id: string | undefined;
      data: TRefresh;
      createdAt: number;
      expiresAt: number | undefined;
    };
  }): void | Promise<void>;

  /**
   * Fires when both tokens are explicitly cleared (logout).
   * Sessions reflect the state BEFORE clearing.
   *
   * Common use-cases:
   * - Mark both token ids as revoked in external store
   * - Revoke entire token family
   * - Audit trail for logout events
   */
  onClear?(ctx: {
    access: ManagedSession<TAccess>;
    refresh: ManagedSession<TRefresh>;
  }): void | Promise<void>;

  /**
   * Fires on any non-expiry error during token pair operations.
   */
  onError?(ctx: {
    error: unknown;
    /** Which token the error originated from */
    source: "access" | "refresh";
  }): void | Promise<void>;
}

export interface TokenPairConfig<TAccess, TRefresh> {
  access: {
    maxAge: ExpiresIn;
    name?: string;
    // Key config is intentionally omitted — adapter-specific
  };
  refresh: {
    maxAge: ExpiresIn;
    name?: string;
  };
  hooks: TokenPairHooks<TAccess, TRefresh>;
}

/**
 * The resolved token pair.
 *
 * `access` and `refresh` are the underlying session managers exposed
 * directly — developers can call .update() and .clear() on them for
 * escape-hatch scenarios that bypass the coordinated hooks.
 *
 * `login()` and `logout()` are the coordinated methods that go through
 * the full hook lifecycle. Use these for standard flows.
 */
export interface TokenPair<TAccess, TRefresh> {
  /** The access token session manager (JWS, short-lived, client-readable) */
  readonly access: ManagedSession<TAccess>;
  /** The refresh token session manager (JWE, long-lived, encrypted) */
  readonly refresh: ManagedSession<TRefresh>;

  /**
   * Coordinated login: issues both tokens in the correct order.
   * The refresh token is issued first, then the access token.
   */
  login(accessData: TAccess, refreshData: TRefresh): Promise<void>;

  /**
   * Coordinated logout: captures pre-clear snapshots, clears both
   * tokens, then fires the onClear hook.
   */
  logout(): Promise<void>;
}
```

### 3.5 CSRF Types

```ts
// types/csrf.ts

export interface CsrfConfig {
  /** Cookie name for the CSRF token. Default: "csrf" */
  name?: string;
  /** Header name to validate against. Default: "x-csrf-token" */
  headerName?: string;
  /**
   * HTTP methods that require CSRF validation.
   * Default: ["POST", "PUT", "DELETE", "PATCH"]
   */
  protectedMethods?: string[];
}
```

### 3.6 Auth Middleware Types

```ts
// types/middleware.ts

import type { ManagedSession } from "./shared";

/**
 * The auth context that middleware populates on the request.
 * Adapters decide where this lives (e.g., event.context.auth for h3).
 */
export interface AuthContext<TAccess> {
  /** The access token session. Undefined if not authenticated. */
  session: ManagedSession<TAccess> | undefined;
  /** Shorthand: whether the request has a valid session */
  authenticated: boolean;
}

export interface AuthMiddlewareConfig<TAccess> {
  /**
   * Called when no valid session exists.
   * For requireAuth: throw an HTTP error.
   * For optionalAuth: no-op (return undefined).
   */
  onUnauthenticated?(): void | Promise<void>;

  /**
   * Called after successful authentication, before the route handler.
   * Use for additional authorization checks (role, permissions, etc.).
   * Throw to block the request.
   */
  onAuthenticated?(ctx: { session: ManagedSession<TAccess> }): void | Promise<void>;
}
```

---

## 4. h3v2 Adapter — `unauth/basic/h3v2`

### 4.1 File Structure

```
src/basic/h3v2/
├── token-pair.ts       → defineTokenPair() + re-exports generateJWK etc.
├── session.ts          → defineSession() + re-exports generateJWK etc.
├── middleware.ts        → createAuthMiddleware(), requireAuth(), optionalAuth()
├── csrf.ts             → defineCsrf()
└── index.ts            → barrel (re-exports all of the above)
```

Each file is a self-contained module. No file imports from siblings —
`middleware.ts` receives the `useAuth` composable as a parameter, not
by importing `token-pair.ts`. This ensures granular sub-paths have
zero cross-module overhead.

### 4.2 Re-exports

Each granular sub-path that involves key management re-exports the
relevant unjwt utilities so consumers don't need a separate import:

```ts
// token-pair.ts and session.ts both re-export:
export {
  generateJWK,
  importJWKFromPEM,
  exportJWKToPEM,
  deriveJWKFromPassword,
} from "unjwt/adapters/h3v2";
```

The barrel (`index.ts`) re-exports everything. Consumers who import
directly from `unjwt/adapters/h3v2` can skip the re-exports entirely.

### 4.3 Token Pair — `defineTokenPair`

#### Extended Types

```ts
import type { H3Event } from "h3";
import type { SessionConfigJWE, SessionConfigJWS, SessionManager } from "unjwt/adapters/h3v2";
import type { TokenPairConfig, TokenPair, ManagedSession } from "unauth/basic";

/**
 * h3v2-specific hooks — every callback receives the H3Event
 * so developers can access headers, IP, fingerprint, request context, etc.
 */
export interface H3TokenPairHooks<TAccess, TRefresh> {
  onRefresh(ctx: {
    refresh: ManagedSession<TRefresh>;
    access: ManagedSession<TAccess>;
    event: H3Event;
  }): Promise<TAccess | undefined> | TAccess | undefined;

  onAfterRefresh?(ctx: {
    access: ManagedSession<TAccess>;
    refresh: ManagedSession<TRefresh>;
    previousAccess: {
      id: string | undefined;
      data: TAccess;
      createdAt: number;
      expiresAt: number | undefined;
    };
    previousRefresh: {
      id: string | undefined;
      data: TRefresh;
      createdAt: number;
      expiresAt: number | undefined;
    };
    event: H3Event;
  }): void | Promise<void>;

  onClear?(ctx: {
    access: ManagedSession<TAccess>;
    refresh: ManagedSession<TRefresh>;
    event: H3Event;
  }): void | Promise<void>;

  onError?(ctx: {
    error: unknown;
    source: "access" | "refresh";
    event: H3Event;
  }): void | Promise<void>;
}

export interface H3TokenPairOptions<TAccess, TRefresh> {
  access: {
    /** JWS signing key */
    key: SessionConfigJWS<TAccess, string>["key"];
    maxAge: TokenPairConfig<TAccess, TRefresh>["access"]["maxAge"];
    name?: string;
    cookie?: SessionConfigJWS<TAccess, string>["cookie"];
    jws?: SessionConfigJWS<TAccess, string>["jws"];
  };
  refresh: {
    /** JWE encryption key */
    key: SessionConfigJWE<TRefresh, string>["key"];
    maxAge: TokenPairConfig<TAccess, TRefresh>["refresh"]["maxAge"];
    name?: string;
    cookie?: SessionConfigJWE<TRefresh, string>["cookie"];
    jwe?: SessionConfigJWE<TRefresh, string>["jwe"];
  };
  hooks: H3TokenPairHooks<TAccess, TRefresh>;
}
```

#### Factory Signature

```ts
/**
 * Creates a token pair composable bound to the provided configuration.
 * Returns a function that resolves both sessions per-request.
 *
 * The returned TokenPair exposes the underlying unjwt SessionManagers
 * directly as `access` and `refresh`. Coordinated operations (login,
 * logout) go through hooks; direct manager access bypasses hooks
 * intentionally for advanced use-cases.
 *
 * Delegates entirely to unjwt/adapters/h3v2 — no additional caching.
 */
export function defineTokenPair<TAccess, TRefresh>(
  options: H3TokenPairOptions<TAccess, TRefresh>,
): (event: H3Event) => Promise<TokenPair<TAccess, TRefresh>>;
```

#### Internal Implementation Notes

1. **Access token config** — Built as `SessionConfigJWS` with an `onExpire` hook:
   - Read RT via `getJWESession(event, rtConfig)`
   - If RT is empty (`!refresh.id`) → return, caller sees empty AT session
   - Capture pre-refresh snapshots of both sessions (id, data, createdAt, expiresAt)
   - Call `hooks.onRefresh({ refresh, access, event })` inside try/catch:
     - **Returns `TAccess`** → proceed with refresh (steps below)
     - **Returns `undefined`** → deliberate rejection: call `clearJWESession()` + `clearJWSSession()`, return
     - **Throws** → abort without destroying state: RT is preserved, AT stays empty, forward error to `hooks.onError({ error, source: "access", event })`, return
   - Call `updateJWSSession()` with the fresh access data
   - Call `updateJWESession()` with the same refresh data (rotates: new jti/iat/exp, consuming the old RT)
   - Call `hooks.onAfterRefresh()` with current sessions + previous snapshots

2. **Refresh token config** — Built as `SessionConfigJWE`, no custom hooks. Rotation is driven entirely from the AT's `onExpire`.

3. **`login()` method**:
   - Calls `refresh.update(refreshData)` first (so RT exists before AT is issued)
   - Calls `access.update(accessData)`
   - Both are the unjwt session manager methods directly

4. **`logout()` method**:
   - Captures snapshots of both sessions (pre-clear state)
   - Calls `access.clear()` then `refresh.clear()`
   - Fires `hooks.onClear({ access, refresh, event })` with pre-clear snapshots

5. **Transparent access** — `tokenPair.access` and `tokenPair.refresh` ARE the unjwt `SessionManager` instances returned by `useJWSSession` and `useJWESession`. Calling `.update()` or `.clear()` on them directly works but bypasses unauth hooks. This is documented as the intentional escape hatch for advanced users.

#### Usage Example

```ts
import { defineTokenPair, generateJWK } from "unauth/basic/h3v2";
import { H3, serve, HTTPError } from "h3";

const atKeys = await generateJWK("ES256");
const rtKey = await generateJWK("A256GCM");

const useAuth = defineTokenPair<
  { sub: string; permissions: string[] },
  { sub: string; family: string }
>({
  access: {
    key: atKeys,
    name: "at",
    maxAge: "15m",
    cookie: { httpOnly: false, secure: true, sameSite: "lax", path: "/" },
  },
  refresh: {
    key: rtKey,
    name: "rt",
    maxAge: "30D",
    cookie: { httpOnly: true, secure: true, sameSite: "lax", path: "/" },
  },
  hooks: {
    async onRefresh({ refresh, event }) {
      // Throw → abort, preserve RT (transient failure, try again next request)
      const user = await db.users.findById(refresh.data.sub).catch((err) => {
        throw err;
      }); // DB down? don't nuke the RT

      // Return undefined → deliberate rejection, clear both tokens
      if (!user || user.suspended) return undefined;

      // Check family revocation
      const familyRevoked = await db.isFamilyRevoked(refresh.data.family);
      if (familyRevoked) return undefined;

      // Return TAccess → refresh succeeds
      return { sub: user.id, permissions: user.permissions };
    },

    onAfterRefresh({ access, refresh, previousRefresh, event }) {
      logger.info("token_refresh", {
        sub: access.data.sub,
        newAtId: access.id,
        oldRtId: previousRefresh.id,
        newRtId: refresh.id,
        ip: event.req.headers.get("x-forwarded-for"),
      });

      // Example: store new AT jti for replay detection
      // This is application logic, not library logic.
      db.storeActiveJti(access.id, refresh.data.family);
    },

    async onClear({ access, refresh }) {
      if (access.id) await db.revokeToken(access.id);
      if (refresh.id) await db.revokeToken(refresh.id);
    },

    onError({ error, source, event }) {
      logger.error("auth_error", { source, error, path: event.url.pathname });
    },
  },
});

const app = new H3()
  .post("/login", async (event) => {
    const { username, password } = await readBody(event);
    const user = await authenticate(username, password);
    if (!user) throw new HTTPError("Invalid credentials", { status: 401 });

    const auth = await useAuth(event);
    await auth.login(
      { sub: user.id, permissions: user.permissions },
      { sub: user.id, family: crypto.randomUUID() },
    );
    return { ok: true };
  })

  .get("/me", async (event) => {
    const { access } = await useAuth(event);
    if (!access.id) throw HTTPError.status(401, "Unauthorized");
    return { user: access.data };
  })

  .post("/logout", async (event) => {
    const auth = await useAuth(event);
    await auth.logout();
    return { ok: true };
  });

serve(app, { port: 3000 });
```

#### Escape Hatch — Direct Session Manager Access

For advanced use-cases where the coordinated lifecycle is too restrictive:

```ts
app.post("/admin/force-refresh-access", async (event) => {
  const auth = await useAuth(event);

  // Bypass unauth hooks — update the AT directly via unjwt's session manager.
  // The refresh token is NOT rotated. The onRefresh/onAfterRefresh hooks
  // do NOT fire. The developer is in full control.
  await auth.access.update({
    sub: auth.access.data.sub,
    permissions: await db.getAdminPermissions(auth.access.data.sub),
  });

  return { ok: true };
});
```

### 4.4 Single Session — `defineSession`

An opinionated encrypted session cookie with auto-refresh.
Useful standalone, and as the future foundation for `unauth/oauth`
authentication sessions in monolithic backends.

#### Extended Types

```ts
import type { H3Event } from "h3";
import type { SessionConfigJWE } from "unjwt/adapters/h3v2";
import type { SessionConfig, ManagedSession } from "unauth/basic";

export interface H3SessionHooks<T> {
  onRead?(ctx: { session: ManagedSession<T>; event: H3Event }): void | Promise<void>;

  onUpdate?(ctx: {
    session: ManagedSession<T>;
    oldSession: ManagedSession<T>;
    event: H3Event;
  }): void | Promise<void>;

  /**
   * Fires when the session has crossed the refreshAfter threshold.
   *
   * Three outcomes:
   * - Return `T`  → refresh with provided data
   * - Return void → refresh with current data (sliding window)
   * - Throw       → abort refresh, current session preserved, error to onError
   */
  onRefresh?(ctx: {
    session: ManagedSession<T>;
    event: H3Event;
  }): T | void | undefined | Promise<T | void | undefined>;

  onClear?(ctx: { session: ManagedSession<T>; event: H3Event }): void | Promise<void>;
  onExpire?(ctx: { error: unknown; event: H3Event }): void | Promise<void>;
  onError?(ctx: { error: unknown; event: H3Event }): void | Promise<void>;
}

export interface H3SessionOptions<T> {
  key: SessionConfigJWE<T, string>["key"];
  maxAge?: SessionConfig<T>["maxAge"];
  name?: string;
  /**
   * When to auto-refresh, as a ratio of maxAge (0 to 1).
   * E.g., 0.75 = refresh after 75% of lifetime has elapsed.
   * Set to `false` to disable.
   * Default: 0.75
   */
  refreshAfter?: number | false;
  cookie?: SessionConfigJWE<T, string>["cookie"];
  jwe?: SessionConfigJWE<T, string>["jwe"];
  hooks?: H3SessionHooks<T>;
}
```

#### Factory Signature

```ts
/**
 * Returns the unjwt SessionManager directly (transparent access).
 * Auto-refresh is handled internally after read, before returning.
 */
export function defineSession<T>(
  options: H3SessionOptions<T>,
): (event: H3Event) => Promise<ManagedSession<T>>;
```

#### Opinionated Defaults

- Cookie: `httpOnly: true`, `secure: true`, `sameSite: "lax"`, `path: "/"`
- Session type: JWE (encrypted, not readable by client)
- Name: `"session"`
- `refreshAfter`: `0.75`

#### Auto-Refresh Logic

After reading a valid session, the adapter checks:

```
elapsed = Date.now() - session.createdAt
threshold = maxAge_in_ms * refreshAfter
if (elapsed >= threshold) → trigger refresh
```

The refresh flow:

1. Call `hooks.onRefresh({ session, event })` inside try/catch
2. If `onRefresh` returns data → use that as the new session data
3. If `onRefresh` returns void → re-issue with current `session.data`
4. Call `session.update(data)` → new jti/iat/exp, fresh cookie

If `onRefresh` throws, the current (still valid) session is returned as-is.
The error is forwarded to `hooks.onError`. The request proceeds normally
with the existing token.

#### Usage Example

```ts
import { defineSession, generateJWK } from "unauth/basic/h3v2";
import { H3, serve } from "h3";

const sessionKey = await generateJWK("A256GCM");

const useSession = defineSession<{ userId: string; cart: string[] }>({
  key: sessionKey,
  maxAge: "7D",
  refreshAfter: 0.75, // refresh after ~5.25 days
  hooks: {
    async onRefresh({ session }) {
      // Throw → abort refresh, keep current session (transient failure)
      const revoked = await db.isRevoked(session.id).catch((err) => {
        throw err;
      }); // DB down? don't lose the session

      // Throw → deliberate abort (session revoked, but session still valid until expiry)
      if (revoked) throw new Error("Session revoked");

      // Return void → re-issue with same data (sliding window)
    },
    onClear({ session }) {
      db.revokeSession(session.id);
    },
  },
});

const app = new H3()
  .get("/cart", async (event) => {
    const session = await useSession(event);
    return { cart: session.data.cart ?? [] };
  })
  .post("/cart/add", async (event) => {
    const { item } = await readBody(event);
    const session = await useSession(event);
    await session.update((old) => ({
      cart: [...(old.cart ?? []), item],
    }));
    return { ok: true };
  });
```

#### Future: OAuth Integration

`defineSession` is designed to serve as the authentication session
for `unauth/oauth` providers in monolithic backends:

```ts
// A monolithic app using both unauth/basic and unauth/oauth:
//
// unauth/basic/h3v2 — defineSession() for the auth provider's own session
//                      (tracks "who is logged in to the auth server itself")
//
// unauth/basic/h3v2 — defineTokenPair() for AT/RT issued to API consumers
//                      (the tokens the auth server issues to clients)
//
// unauth/oauth/h3v2 — the OAuth 2.1 grant logic, internally using
//                      defineSession for its auth session
//
// Different cookie names, different lifecycles, same server.
```

### 4.5 Auth Middleware — `createAuthMiddleware`

#### Signature

```ts
import type { H3Event } from "h3";
import type { TokenPair, AuthContext, ManagedSession } from "unauth/basic";

type UseAuth<TAccess, TRefresh> = (event: H3Event) => Promise<TokenPair<TAccess, TRefresh>>;

export interface H3AuthMiddlewareConfig<TAccess> {
  onUnauthenticated?(ctx: { event: H3Event }): void | Promise<void>;
  onAuthenticated?(ctx: { session: ManagedSession<TAccess>; event: H3Event }): void | Promise<void>;
}

export function createAuthMiddleware<TAccess, TRefresh>(
  useAuth: UseAuth<TAccess, TRefresh>,
  config?: H3AuthMiddlewareConfig<TAccess>,
): (event: H3Event) => Promise<void>;
```

#### Context Population

```ts
// After middleware runs:
event.context.auth = {
  session: access.id ? access : undefined,
  authenticated: !!access.id,
};
```

Type augmentation for consumers:

```ts
// types/h3.d.ts
import type { AuthContext } from "unauth/basic";

declare module "h3" {
  interface H3EventContext {
    auth: AuthContext<{ sub: string; permissions: string[] }>;
  }
}
```

#### Convenience Factories

```ts
/** Throws HTTPError 401 if no valid session */
export function requireAuth<TAccess, TRefresh>(
  useAuth: UseAuth<TAccess, TRefresh>,
  config?: Omit<H3AuthMiddlewareConfig<TAccess>, "onUnauthenticated">,
): (event: H3Event) => Promise<void>;

/** Allows unauthenticated requests (context.auth.authenticated = false) */
export function optionalAuth<TAccess, TRefresh>(
  useAuth: UseAuth<TAccess, TRefresh>,
  config?: Omit<H3AuthMiddlewareConfig<TAccess>, "onUnauthenticated">,
): (event: H3Event) => Promise<void>;
```

#### Usage with Per-Route Middleware

```ts
import { defineTokenPair, requireAuth, optionalAuth } from "unauth/basic/h3v2";

const useAuth = defineTokenPair<Access, Refresh>({
  /* ... */
});

const app = new H3()
  .get("/health", () => ({ ok: true }))

  .get(
    "/feed",
    async (event) => {
      const { auth } = event.context;
      if (auth.authenticated) {
        return getPersonalizedFeed(auth.session!.data.sub);
      }
      return getPublicFeed();
    },
    { middleware: [optionalAuth(useAuth)] },
  )

  .get(
    "/me",
    (event) => {
      return event.context.auth.session!.data;
    },
    { middleware: [requireAuth(useAuth)] },
  )

  .delete("/admin/users/:id", handler, {
    middleware: [
      requireAuth(useAuth, {
        onAuthenticated({ session }) {
          if (!session.data.permissions.includes("admin:users:delete")) {
            throw new HTTPError("Forbidden", { status: 403 });
          }
        },
      }),
    ],
  });
```

### 4.6 CSRF — `defineCsrf`

```ts
import type { H3Event } from "h3";
import type { CsrfConfig } from "unauth/basic";

export interface H3CsrfOptions extends CsrfConfig {
  /** Secret for HMAC-based token generation (uses unsecure internally) */
  secret: string;
  cookie?: {
    secure?: boolean;
    sameSite?: "strict" | "lax" | "none";
    path?: string;
  };
}

/**
 * CSRF middleware factory (double-submit cookie with HMAC).
 * - Safe methods (GET, HEAD, OPTIONS): sets CSRF cookie if absent.
 * - Protected methods (POST, PUT, DELETE, PATCH): validates header against cookie.
 */
export function defineCsrf(options: H3CsrfOptions): (event: H3Event) => Promise<void>;
```

---

## 5. Documentation Plan — Examples & Patterns

The following should live in the library documentation as dedicated guides.
They demonstrate how the hook surface enables advanced use-cases without
the library prescribing implementation details.

### 5.1 Token Family Revocation

Show how to use a `family` field in refresh data to group related tokens
and revoke the entire lineage on suspicious activity.

```ts
// In onRefresh: check family revocation
async onRefresh({ refresh }) {
  const familyRevoked = await db.isFamilyRevoked(refresh.data.family);
  if (familyRevoked) return undefined; // force re-auth
  // ...
}

// On a security event: revoke the family
await db.revokeFamily(refresh.data.family);
```

### 5.2 JTI Tracking / Replay Detection

Show how to use `onAfterRefresh` to store the current AT jti, and
`onRefresh` to verify it matches the last known value.

```ts
onAfterRefresh({ access, refresh }) {
  // Store: this RT's id → was used to mint this AT id
  db.recordRefreshUsage(refresh.id, access.id);
},

async onRefresh({ refresh, access }) {
  const lastKnownAtId = await db.getLastAtIdForRefresh(refresh.id);
  if (lastKnownAtId && lastKnownAtId !== access.id) {
    // Possible replay — RT was used to mint an AT we don't recognize
    await db.revokeFamily(refresh.data.family);
    return undefined;
  }
  // ...
}
```

### 5.3 Device Binding / Fingerprint Validation

Show how to use `getRequestFingerprint()` from h3 in `onRefresh` to
detect token usage from a different device.

```ts
import { getRequestFingerprint } from "h3";

async onRefresh({ refresh, event }) {
  const fp = await getRequestFingerprint(event);
  const storedFp = await db.getFingerprint(refresh.data.sub);
  if (storedFp && storedFp !== fp) {
    // Token used from different device
    logger.warn("device_mismatch", { sub: refresh.data.sub });
    return undefined; // or allow but flag
  }
  // ...
}
```

### 5.4 Concurrent Tab Handling

Explain why strict jti tracking can break multi-tab scenarios, and
show a grace-period pattern using timestamps instead of strict jti matching.

```ts
// Instead of exact jti match, allow a short grace window:
async onRefresh({ refresh }) {
  const lastRefresh = await db.getLastRefreshTime(refresh.id);
  if (lastRefresh && Date.now() - lastRefresh < 5_000) {
    // Another tab refreshed < 5s ago — allow this one too
    return { /* fresh claims */ };
  }
  // Normal flow
  db.recordRefreshTime(refresh.id, Date.now());
  return { /* fresh claims */ };
}
```

### 5.5 Escape Hatch Patterns

Document when and why to use direct session manager access:

- Updating AT claims without rotating the RT (e.g., mid-request permission escalation)
- Reading the raw token for forwarding to downstream services
- Implementing custom rotation strategies that differ from the default

### 5.6 Using `defineSession` with `unauth/oauth`

Preview of how the single session becomes the OAuth provider's
authentication session in a monolithic backend (see section 4.4).

---

## 6. Dependency Graph

```
unauth/basic              (types-only, zero deps)
  └── references unjwt types (ExpiresIn, JWK types)

unauth/basic/h3v2         (runtime)
  ├── peer: h3 ^2.0.1
  ├── peer: unjwt ^0.5.39
  ├── dep: unsecure (hmac, secure strings — used by CSRF)
  ├── imports: unjwt/adapters/h3v2 (session functions, key generation)
  └── imports: unauth/basic (types)
```

---

## 7. Summary — What Gets Built

| Export Path                    | Contents                                                    | Runtime |
| ------------------------------ | ----------------------------------------------------------- | ------- |
| `unauth/basic`                 | `ManagedSession`, `TokenPairConfig`, `TokenPairHooks`,      | No      |
|                                | `TokenPair`, `SessionConfig`, `SessionHooks`,               |         |
|                                | `CsrfConfig`, `AuthContext`, `AuthMiddlewareConfig`,        |         |
|                                | `ExpiresIn` (re-export)                                     |         |
| `unauth/basic/h3v2`            | Barrel: re-exports all granular sub-paths below             | Yes     |
| `unauth/basic/h3v2/token-pair` | `defineTokenPair()` + unjwt key utils re-exports            | Yes     |
| `unauth/basic/h3v2/session`    | `defineSession()` + unjwt key utils re-exports              | Yes     |
| `unauth/basic/h3v2/middleware` | `createAuthMiddleware()`, `requireAuth()`, `optionalAuth()` | Yes     |
| `unauth/basic/h3v2/csrf`       | `defineCsrf()`                                              | Yes     |
