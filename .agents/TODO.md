# TODO

Current and next steps for project-specific implementations.
Remove completed items once they are committed — no need to track history here.

## `unauth/h3v2` — Planned

- [ ] `token-pair.ts` — `defineTokenPair()`, `requireAuth()`, `optionalAuth()`
  - Built directly on unjwt lower-level functions (no `defineSession` reuse)
  - `onRefresh` uses `issue(accessData)` function-in-context pattern
  - AT: JWS (short-lived, client-readable), RT: JWE (long-lived, encrypted)
  - Refresh triggered via unjwt's `onExpire` on the JWS config
  - `login()` / `logout()` coordinated methods
  - Middleware in the same file
- [ ] Tests for token pair + middleware
- [ ] Update `src/h3v2.ts` barrel with token pair exports
