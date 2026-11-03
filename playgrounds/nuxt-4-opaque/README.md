# Nuxt 4 playground: opaque sessions

> [!WARNING]
> Under development. The code is the reference; this README is not maintained yet.

`unauth/n` signs in; the application keeps users, identities and sessions in Postgres through drizzle-orm over `@electric-sql/pglite` (an embedded Postgres under `.data/pglite`). Sessions use `defineOpaqueSession` from `unauth/session`: the cookie carries a random token, the `sessions` table holds the session under the token's hash.

[`server/db/schema.ts`](./server/db/schema.ts) declares the tables and [`server/db/relations.ts`](./server/db/relations.ts) their relations (`defineRelations`), passed to `drizzle({ relations })` so `db.query` and every `Transaction` carry them: `Db` is `PgliteDatabase<Relations> | PgliteTransaction<Relations>`. `pnpm db:generate` (drizzle-kit) writes the SQL under [`server/db/migrations/`](./server/db/migrations), and [`server/plugins/migrate.ts`](./server/plugins/migrate.ts) applies it at server start, holding requests until it is done.

[`server/utils/session.ts`](./server/utils/session.ts) defines the session (`maxAge: "30D"` absolute, `idle: "7D"`) and `drizzleSessionStore(event)`, an `OpaqueSessionStore` over the `sessions` table: five verbs, one statement each. `find` selects by `token_hash`; `save` upserts; `touch` and `rekey` are an `UPDATE … WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now) RETURNING`, so a row that ended is not revived; `delete` deletes. Hashing the token is the store's choice (`hashOpaqueToken` from `unauth/token`), not the library's. `data` is a `jsonb` column; `user_id` is copied out of it to list and revoke per user; `id` is the library's stable session id, unchanged by `rotate()`, what `GET /sessions` lists. Times are ms since the epoch, `expires_at` nullable for a session without lifetimes.

The request event is the unit of work. [`server/utils/db.ts`](./server/utils/db.ts) has `useDB(event)`: the transaction the request is in, else the database. Every account and session helper takes the event first and goes through `useDB(event)`; so does the store factory, so a session write inside a transaction joins it. [`server/utils/transaction.ts`](./server/utils/transaction.ts) draws the boundary: `withTransaction(event, fn)` opens `db.transaction` and puts it on `event.context.transaction` for its duration; `defineTransactionalHandler(fn)` wraps a whole route in it. `/unlink` and `/delete` write the account and rotate or clear the session as one unit. The cookie is written when the session write returns, before the commit: write the session last in a transaction, so nothing that can fail follows it. `/auth/github` keeps the boundary narrow, around the link alone, since the provider round trip must not hold a transaction. Inside a transaction, pglite is one connection: a query that bypasses `useDB(event)` waits for the transaction to end.

`useAuthSession(event)` is synchronous and touches no store: `session.token` is the token the request carries, unverified. Reading `session.record` is the one store read of the request, shared by every later access: the stored row, or every field `undefined` without a live session, `id` telling the two apart; `requireAuthSession(event)` is that read with a 401. Routes that already query the database skip it: `sessionKey(event)` hashes the carried token the way the store does, and `/me`, `/sessions` and `/unlink` filter on `sessions.token_hash` inside their own query, through the relations (`user: { sessions: { tokenHash: key, … } }`), so the database verifies the session as part of the statement, one round trip, and an empty result is the 401. Such a statement never extends the session or drops a dead cookie; `session.data` does. This holds for any SQL store; a key-value store cannot join, and there the lookup stays.

Sign-in is `clear()` then `update(data)`, so the signed-in session gets a token nobody held before; `update()` creates nothing for an empty update, so a visitor who never signs in never gets a row. A read extends an idle session once half of `idle` has passed, through `touch` alone. `rotate()` moves the session under a new token in one `rekey`: `id` and `created_at` stay, the absolute end does not move.

```sh
pnpm install
pnpm dev:prepare
pnpm dev:nuxt-opaque
```

Run from the repository root. After changing `server/db/schema.ts`, run `pnpm db:generate` in this folder, remove `.data/pglite` and restart the server.
