# Nitro 3 playground

An authentication session on Nitro v3 with `unauth/n`. Nitro v3 runs on h3 v2, whose event is the web-standard `{ req, res, context }` that `unauth/n` (through `unjwt/session`) takes as it is. No `h3` import, no alias, the same route code as the Nuxt 4 playground.

- [`server/utils/session.ts`](./server/utils/session.ts): the session definition, `useAppSession(event)`, `requireAppSession(event)` (`auth.require`) and the GitHub sign-in handler.
- [`server/routes/`](./server/routes/): `login`, `me`, `logout`, `throw-after-clear`, `auth/github`, and a WebSocket at `/ws`.
- [`index.html`](./index.html): one button per route, and a log of what each answered. Nitro serves it for every unmatched route.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev:nitro   # at the repository root, or `pnpm dev` here

SESSION_PASSWORD=$(openssl rand -base64 32) pnpm build && pnpm start
```

## Imports come from `nitro`

```ts
// server/routes/me.get.ts
import { defineHandler } from "nitro";
import { defineSessionGuard } from "unauth/n";
import { auth, requireAppSession } from "../utils/session.ts";

export default defineHandler({
  middleware: [defineSessionGuard(auth)],
  async handler(event) {
    const session = await requireAppSession(event);
    return { id: session.id, ...session.data, expiresAt: session.expiresAt };
  },
});
```

Nitro v3 has no auto-imports: `defineHandler`, `defineWebSocketHandler` and `HTTPError` come from `nitro`, `readBody` from `nitro/h3`, and the session utils are imported by path.

## One definition, keyed from a password

```ts
// server/utils/session.ts
import { type SessionContext, deriveJWKFromPassword } from "unjwt/session";
import { defineAuthSession } from "unauth/n";

const auth = defineAuthSession<SessionData>({
  key: sessionKey,
  maxAge: "1h",
  rolling: "15m",
});

export const useAppSession = (event: SessionContext) => auth.use(event);
```

Two keys are derived once at module load from `SESSION_PASSWORD` (with a default for local use): one seals the `__Host-unauth` session cookie, the other the `__Host-unauth-flow` cookie a sign-in travels in.

`useAppSession` takes `SessionContext`, not only an `H3Event`: the same util serves a route's event, a WebSocket upgrade request, and `{ token }` when a token arrives some other way. The third generic of `defineAuthSession` could narrow `use()` and every hook's `context` to `H3Event`, as the h3 playground does; it is left open here for the upgrade.

`rolling: "15m"` reissues a token older than 15 minutes on the first read that sees it, over HTTP and at a WebSocket upgrade alike, so an active user never expires.

## Routes

`POST /login` reads `{ user }` and calls `authenticate()`, which sets `authenticatedAt`, mints the token under a new id and writes the cookie. `GET /me` goes through `defineSessionGuard(auth)`, which answers a `401` `Response` unless the session authenticated; the handler reads the same session with `auth.require(event)`, typed as authenticated. `POST /logout` calls `clear()`, which expires the cookie.

`GET /auth/github` is both legs of the GitHub sign-in: the redirect to GitHub with a sealed flow cookie, then the callback that signs the user in through `onSuccess` and redirects home. Register an OAuth app at GitHub with `http://localhost:3000/auth/github` as its callback URL and run with `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` set.

`GET /throw-after-clear` clears and then throws a `401`, and on Nitro v3 the client stays signed in: the `Set-Cookie` written before the throw is lost, because Nitro's error handler answers with a `Response` of its own and h3 sends that without the prepared headers. That is the reproduction this route exists for; the fix belongs upstream.

## WebSockets

The session is read once, in `upgrade`, the only hook that can refuse; what the socket needs for its lifetime is returned as `context`, which every later hook receives as `peer.context`. The headers `upgrade` returns travel on the `101` handshake, so a `Headers` passed as `res` lets the read roll the token or drop an expired cookie. See [`server/routes/ws.ts`](./server/routes/ws.ts).
