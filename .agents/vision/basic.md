# `unauth` — Base Auth Utilities Planning Document

> **Status:** Draft v5 — reflects actual implementation as of 2026-03-23
> **Scope:** h3v2 adapter (h3v1 deferred)
> **Dependencies:** `unjwt` (JWE/JWS session management), `h3` (peer), `unsecure` (HMAC, secure compare), `cookie-es` (peer, cookie serialization)

---

## 1. Design Principles

1. **Types live where they're used.** No separate types package. If a type has only one consumer, it's defined in that file. The public API surface is the adapter barrel (`unauth/h3v2`).
2. **Thin layer over unjwt.** Exports `SessionManager<T>` as a type alias over unjwt's `BaseSessionManager<T, ExpiresIn>`. Unauth adds lifecycle coordination (refresh, token pairs, CSRF, middleware) on top of unjwt's session primitives.
3. **No re-caching.** Delegates entirely to `unjwt/adapters/h3v2` which caches sessions on `event.context`. Unauth never introduces its own caching layer.
4. **Hooks extend unjwt hooks.** `H3SessionHooks` extends `Omit<SessionHooksJWE, "onRead">` with augmented `onRead` (adds `clear`) and new `onRefresh` (adds `refresh` + `clear`). No parallel type hierarchy.
5. **Build-time h3 version aliasing.** Source imports `h3v2`/`cookie-esv2` dev aliases; `build.config.ts` uses `replacePlugin` to rewrite to `h3`/`cookie-es` at build time. This allows future h3v1 adapters with the same pattern.
6. **No internal barrels.** `src/base/h3v2/` has no `index.ts`. The public barrel is `src/h3v2.ts` which re-exports from individual files.
7. **`defineSession` and `defineTokenPair` are independent primitives.** They do not compose each other. They can be used together in a project (session = authentication, token pair = authorization, OAuth 2.0 style) but neither depends on the other internally.
8. **Middleware lives with its primitive.** `requireSession`/`optionalSession` are defined in `session.ts` alongside `defineSession`. Same pattern will apply to token pair middleware.
9. **`DefineSessionReturn<T>` as shared contract.** The return type of `defineSession` is exported as a named type alias so middleware can reference it.
10. **Static imports for deps, dynamic only for optional peer deps.** `unjwt`, `unsecure` are always statically imported. `h3`/`h3v2` (optional peer dep) uses `await import()` only where runtime values are needed (e.g., `HTTPError` in middleware, `getCookie`/`setCookie` in CSRF). Type-only imports from `h3` are always static.
11. **Event type distinction.** `HTTPEvent` is always present/read-only; `H3Event` is for write-capable events (e.g. set cookies). CSRF uses `H3Event` (sets cookies); session uses `HTTPEvent`. Full type alignment is pending upstream unjwt changes.

---

## 2. File Structure

```
src/
├── index.ts                → root barrel: export * as h3v2
├── h3v2.ts                 → public barrel: re-exports from base/h3v2/*
└── base/
    └── h3v2/
        ├── session.ts      → defineSession(), requireSession(), optionalSession(), type exports
        ├── csrf.ts          → defineCsrf()
        └── token-pair.ts   → defineTokenPair(), requireAuth(), optionalAuth() (planned)
```

```
test/
└── h3v2/
    ├── session.test.ts     → defineSession + requireSession + optionalSession tests
    └── csrf.test.ts        → defineCsrf tests
```

---

## 3. Export Map

```jsonc
{
  "sideEffects": false,
  "exports": {
    ".": {
      "types": "./dist/index.d.mts",
      "default": "./dist/index.mjs",
    },
    "./h3v2": {
      "types": "./dist/h3v2.d.mts",
      "import": "./dist/h3v2.mjs",
    },
  },
}
```

---

## 4. Build Configuration

`build.config.ts` uses obuild with `replacePlugin` for h3v1/v2 aliasing:

- `"h3v2"` → `"h3"`, `"h3v1"` → `"h3"`
- `"cookie-esv2"` → `"cookie-es"`, `"cookie-esv1"` → `"cookie-es"`
- Platform: `"neutral"`
- External: `h3v1`, `h3v2`, `h3`, `cookie-esv1`, `cookie-esv2`
- Entries: `["./src/index.ts", "./src/h3v2.ts"]`

---

## 5. Import Strategy

| Module                  | Import style           | Reason                                         |
| ----------------------- | ---------------------- | ---------------------------------------------- |
| `unjwt/adapters/h3v2`   | Static                 | Regular dependency, always available           |
| `unjwt/utils`           | Static                 | Regular dependency                             |
| `unsecure`              | Static                 | Regular dependency                             |
| `h3` / `h3v2` (types)   | Static `import type`   | Erased at build, no runtime cost               |
| `h3v2` (runtime values) | `await import("h3v2")` | Optional peer dep — defer failure to call site |
| `cookie-esv2` (types)   | Static `import type`   | Erased at build                                |

---

## 6. `defineSession` — Encrypted Session with Auto-Refresh

### Status: ✅ Implemented with tests

### API

```ts
type SessionManager<T extends SessionData> = BaseSessionManager<T, ExpiresIn>;
type DefineSessionReturn<T extends SessionData> = (event: HTTPEvent) => Promise<SessionManager<T>>;

function defineSession<T extends SessionData>(options: H3SessionOptions<T>): DefineSessionReturn<T>;
```

### Key types

- `SessionManager<T>` — type alias over unjwt's `BaseSessionManager<T, ExpiresIn>`, re-exported for consumers
- `DefineSessionReturn<T>` — the composable return type, used by middleware
- `H3SessionHooks<T>` — extends `Omit<SessionHooksJWE, "onRead">`, adds `onRead` with `clear()` and `onRefresh` with `refresh()` + `clear()`
- `H3SessionOptions<T>` — extends `Omit<SessionConfigJWE, "hooks">`, adds `refreshAfter` and typed `hooks`

### `onRefresh` — `refresh()` + `clear()` functions in context

The hook fires only when the session is past the `refreshAfter` threshold.
The `refresh()` function passes its argument directly to `updateJWESession` — accepts `SessionUpdate<T>` (partial object or `(oldData) => partial` callback).

```ts
onRefresh?(args: {
  session: SessionJWE<T, MaxAge>;
  event: HTTPEvent;
  config: SessionConfigJWE<T, MaxAge>;
  refresh(update?: SessionUpdate<T>): Promise<void>;
  clear(): Promise<void>;
}): void | Promise<void>;
```

`onRead` also receives a `clear()` function for non-refresh reads.

| Action                                             | Effect                                                    |
| -------------------------------------------------- | --------------------------------------------------------- |
| `await refresh()`                                  | Sliding window — re-issue with same data, new jti/iat/exp |
| `await refresh({ role: 'admin' })`                 | Update data — merge partial, re-issue                     |
| `await refresh(old => ({ count: old.count + 1 }))` | Callback update — compute from current data               |
| Don't call `refresh()`                             | Skip — session stays as-is, no re-issue                   |
| `await clear()`                                    | Destroy the session (from onRefresh or onRead)            |
| Throw                                              | Error path → forwarded to `onError`                       |

**Default (no `onRefresh` hook):** automatic sliding window via `updateJWESession`.

### Middleware — `requireSession` / `optionalSession`

Defined in the same file as `defineSession`. Accept `DefineSessionReturn<T>` for proper type inference.

```ts
function requireSession<T>(
  useSession: DefineSessionReturn<T>,
  config?,
): (event: HTTPEvent) => Promise<void>;
function optionalSession<T>(
  useSession: DefineSessionReturn<T>,
  config?,
): (event: HTTPEvent) => Promise<void>;
```

- `requireSession`: throws 401 if `!session.id` (dynamic `import("h3v2")` for `HTTPError`)
- `optionalSession`: allows unauthenticated requests
- Both accept optional `onAuthenticated` hook for authorization checks
- Does **not** manage `event.context` — unjwt handles that

### Defaults

- Name: `"auth-session"`
- MaxAge: `"7D"`
- RefreshAfter: `0.75`
- Cookie: `httpOnly: true, secure: true, sameSite: "lax", path: "/"`

---

## 7. `defineCsrf` — Double-Submit Cookie with HMAC

### Status: ✅ Implemented with tests

### API

```ts
function defineCsrf(options: H3CsrfOptions): (event: H3Event) => Promise<void>;
```

### Behavior

- **Safe methods** (GET, HEAD, OPTIONS): sets CSRF cookie if absent. Token = `HMAC(secret, randomUUID())`.
- **Protected methods** (POST, PUT, DELETE, PATCH): validates header matches cookie via `secureCompare`.
- Cookie is non-httpOnly (client JS reads it).
- Dynamic `import("h3v2")` for `getCookie`, `setCookie`, `HTTPError` (optional peer dep).

---

## 8. `defineTokenPair` — Access + Refresh Token Pair (Planned)

Access token (JWS, short-lived, client-readable) + refresh token (JWE, long-lived, encrypted).

**Built directly on unjwt's lower-level functions** — does NOT compose `defineSession`.
Middleware (`requireAuth`, `optionalAuth`) will live in the same file.

### Core mechanics

- AT config is `SessionConfigJWS` with `onExpire` hook wired to the refresh logic.
- Inside `onExpire`: read RT via `getJWESession`, call user's `onRefresh` hook, re-issue AT via `updateJWSSession`, rotate RT via `updateJWESession`.
- `login()` issues RT first then AT.
- `logout()` fires `onClear` hook then clears both.
- Direct access to underlying session managers is the escape hatch.

### `onRefresh` hook — `issue()` function pattern

```ts
onRefresh(args: {
  refresh: SessionManager<TRefresh>;
  access: SessionManager<TAccess>;
  event: HTTPEvent;
  issue(accessData: TAccess): Promise<void>;
}): void | Promise<void>;
```

| Action                              | Effect                                         |
| ----------------------------------- | ---------------------------------------------- |
| `await issue({ sub, permissions })` | AT re-issued, RT rotated (new jti/iat/exp)     |
| Don't call `issue()`                | No refresh — AT stays empty, RT preserved      |
| Throw                               | Error path → `onError`, RT preserved, AT empty |

---

## 9. Dependency Graph

```
unauth/h3v2 (runtime)
├── dep: unjwt (JWE/JWS session management) — static imports
├── dep: unsecure (HMAC, secureCompare) — static imports
├── peer: h3 (HTTP framework) — dynamic imports for runtime values
├── peer: cookie-es (cookie serialization) — type-only imports
└── imports: unjwt/adapters/h3v2, unjwt/utils
```

---

## 10. Summary

| Export        | Contents                                                                                                       | Status                  |
| ------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `unauth/h3v2` | `defineSession`, `requireSession`, `optionalSession`, `SessionManager<T>`, `DefineSessionReturn<T>`, key utils | ✅ Implemented + tested |
| `unauth/h3v2` | `defineCsrf`                                                                                                   | ✅ Implemented + tested |
| `unauth/h3v2` | `defineTokenPair`, `requireAuth`, `optionalAuth`                                                               | 🔲 Planned              |
