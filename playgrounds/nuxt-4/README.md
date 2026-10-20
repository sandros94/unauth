# Nuxt 4 playground

An authentication session on Nuxt v4.6 with `unauth/n`, keyed from Nuxt's own `appSecret`. Nuxt v4.6 still runs on Nitro v2 and h3 v1, but a handler defined through `nuxt/server` receives the web-standard `RequestEvent` (`{ req, res, context }`), which `unauth/n` (through `unjwt/session`) takes as it is. No `h3` import, no alias, the same code on Nitro v3.

- [`server/utils/session.ts`](./server/utils/session.ts): the session definition, `useAppSession(event)`, `requireAppSession(event)` and the GitHub sign-in handler.
- [`server/routes/`](./server/routes/): `login`, `me`, `logout`, `throw-after-clear`, `auth/github`, and a WebSocket at `/ws`.
- [`shared/types/session.d.ts`](./shared/types/session.d.ts): `SessionData`, visible to the utils and the routes.
- [`app.vue`](./app.vue): one button per route, and a log of what each answered.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev:nuxt    # at the repository root, or `pnpm dev` here; a dev appSecret is generated into .nuxt/app-secret

NUXT_APP_SECRET=$(openssl rand -base64 32) pnpm build && pnpm start
```

## Handlers come from `nuxt/server`

```ts
// server/routes/me.get.ts
import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAppSession(event);

  return { id: session.id, ...session.data, expiresAt: session.expiresAt };
});
```

The import is the whole point. Nuxt's auto-imported `defineEventHandler` is still h3's, and its handler receives the raw h3 v1 event, whose `req` is Node's `IncomingMessage`. Every `nuxt/server` helper refuses that event, and so does the session:

```text
[unjwt/session] use() got an event whose "req" is not a web Request.
```

`readBody` and `createError` come from `nuxt/server` for the same reason.

## One definition, keyed from `appSecret`

```ts
// server/utils/session.ts
import { deriveSecret } from "nuxt/server";
import type { SessionContext } from "unjwt/session";
import { defineAuthSession } from "unauth/n";

const auth = defineAuthSession<SessionData>({
  key: sessionKey, // an A256GCM `oct` JWK from deriveSecret("unauth:session")
  maxAge: "1h",
  rolling: "15m",
});

export const useAppSession = (event: SessionContext) => auth.use(event);
```

Nuxt v4.6 reads `NUXT_APP_SECRET` (or `runtimeConfig.appSecret`) and generates a development one when unset; builds do not. `deriveSecret(purpose)` returns 32 HKDF-SHA256 bytes as hex, stable while `appSecret` is and distinct per purpose; the util turns two of them into `A256GCM` `oct` JWKs, one for the `__Host-unauth` session cookie and one for the `__Host-unauth-flow` cookie a sign-in travels in. It needs the runtime config, so the definitions are created on the first call, not at module load, and cached in the module.

`useAppSession` takes `SessionContext`, not only `RequestEvent`: the same util serves a route's event, a WebSocket upgrade request, and `{ token }` when a token arrives some other way. A `server/utils/` export named `useSession` would clash with the `useSession` Nuxt auto-imports, hence `useAppSession`.

`rolling: "15m"` reissues a token older than 15 minutes on the first read that sees it, over HTTP and at a WebSocket upgrade alike, so an active user never expires.

## Routes

`POST /login` reads `{ user }` and calls `authenticate()`, which sets `authenticatedAt`, mints the token under a new id and writes the cookie. `GET /me` goes through `requireAppSession`, that is `auth.require(event)`: the session typed as authenticated, or `ERR_AUTHN_UNAUTHENTICATED` with status 401. `POST /logout` calls `clear()`, which expires the cookie. `GET /throw-after-clear` clears and then throws a `401`: on Nitro 2 the `Set-Cookie` written before the throw stays on the Node response, so the client is signed out by the error response too.

`GET /auth/github` is both legs of the GitHub sign-in: the redirect to GitHub with a sealed flow cookie, then the callback that signs the user in through `onSuccess` and redirects home. The handler returns a `Response` for the redirect, which the `nuxt/server` handler sends as it is. Register an OAuth app at GitHub with `http://localhost:3000/auth/github` as its callback URL and set `NUXT_GITHUB_CLIENT_ID` and `NUXT_GITHUB_CLIENT_SECRET` (see [`.env.example`](./.env.example)).

## WebSockets

The session is read once, in `upgrade`, the only hook that can refuse; what the socket needs for its lifetime is copied onto `request.context`, the object crossws hands every later hook as `peer.context`. The headers `upgrade` returns travel on the `101` handshake, so a `Headers` passed as `res` lets the read roll the token or drop an expired cookie. See [`server/routes/ws.ts`](./server/routes/ws.ts).

`defineWebSocketHandler` is the one h3 import left: `nuxt/server` has no WebSocket API yet.
