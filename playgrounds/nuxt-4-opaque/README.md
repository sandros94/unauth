# Nuxt 4 playground: opaque sessions

> [!WARNING]
> Under development. The code is the reference; this README is not maintained yet.

`unauth/n` signs in; the application keeps its sessions in sqlite through `defineOpaqueSession` from `unauth/session`: the cookie carries a random token, the `sessions` table its hash and the data.

[`server/utils/session.ts`](./server/utils/session.ts) defines the session and its store, a `CacheDriver` over sqlite: `get` reads the row under the hash, `set` upserts it, `set(key, null)` deletes it. `data` is stored as JSON text, sqlite having no JSON column; use `jsonb` where the database has one. The manager matches `defineJWESession`'s, so routes read as in the `nuxt-4` playground, `id` telling a signed-in request from none.

Rolling measures from the last extension (`expiresAt - maxAge`), never from `createdAt`. Linking or unlinking an identity rotates the session: `rotate()` moves it under a new token and resets `createdAt`, the data stays. `data.family` is the application's own id across rotations, what `GET /sessions` lists per user. `revokeSessions(userId)` deletes the rows; the library sees hashes alone.

```sh
pnpm install
pnpm dev:prepare
pnpm dev:nuxt-opaque
```

Run from the repository root.
