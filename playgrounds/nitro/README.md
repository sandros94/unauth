# Nitro 3 playground

The mid-level form of `unauth/n` on Nitro v3: one route file per provider with its options inline, and a session util that knows nothing about sign-in. Nitro v3 runs on h3 v2, whose event is the web-standard `{ req, res, context }` that `unauth/n` and `unjwt/session` take as it is. Nitro has no auto-imports: everything comes from `nitro`, `nitro/h3` and `nitro/runtime-config`, and utils are imported by path.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev:nitro   # at the repository root, or `pnpm dev` here

NITRO_AUTH_SECRET=$(openssl rand -base64 32) SESSION_PASSWORD=$(openssl rand -base64 32) pnpm build && pnpm start
```

## Files

- [`nitro.config.ts`](./nitro.config.ts): the runtime config. `authSecret` is the passphrase the sign-in flow key is derived from (its default is a development placeholder: set `NITRO_AUTH_SECRET`), `github` holds the OAuth app (`NITRO_GITHUB_CLIENT_ID`, `NITRO_GITHUB_CLIENT_SECRET`), `public.origin` is where the app is reached.
- [`server/utils/session.ts`](./server/utils/session.ts): the session alone. `SessionData` extends `AuthSessionData`, what a sign-in writes; one `defineJWESession` with a key derived from `SESSION_PASSWORD`, `maxAge: "1h"` and `rolling: "15m"`; `useAuthSession(event)` and `requireAuthSession(event)`, which answers `401` before sign-in. They take `WebSessionEvent`, not only Nitro's event, so the WebSocket upgrade can use them too.
- [`server/routes/auth/github.get.ts`](./server/routes/auth/github.get.ts): both legs of the GitHub sign-in on one route, `defineGitHubHandler` with the provider's options and the sign-in's side by side. Its `key` is a callback, `deriveKey(authSecret, { info: "unauth:flow" })` from `unauth/n`: the runtime config is read on the first request and the derived `A256GCM` key kept, the same on every instance that shares the secret. The callback is this route on `origin`; register it at GitHub as `http://localhost:3000/auth/github`. The handler is the route's default export as it is: Nitro takes a plain `(event) => …` function.
- [`server/utils/atproto.ts`](./server/utils/atproto.ts): the AT Protocol provider, defined once because two routes need it. Its identity is `/oauth-client-metadata.json` on `origin`; under `nitro dev` that is a `localhost` URL no server can fetch, so the provider uses the spec's development client, and `devHosts: ["localhost"]` moves a start on `localhost` to `127.0.0.1`, the loopback callback the atproto profile requires, then hands the result back to `localhost`.
- [`server/routes/auth/atproto.get.ts`](./server/routes/auth/atproto.get.ts): `defineAtprotoHandler` on that provider, its flow key derived the same way. `GET /auth/atproto?login=<handle, DID or server URL>` starts; the handler reads `login` from the query.
- [`server/routes/oauth-client-metadata.json.get.ts`](./server/routes/oauth-client-metadata.json.get.ts): the provider's `client.metadata`, the document published at its `clientId`; it is absent for the development client, so the route answers nothing there.
- [`server/routes/login.post.ts`](./server/routes/login.post.ts): a password login without a password, for trying the session: it clears the session and writes `{ provider: "password", subject, signedInAt }`, the replace-then-write a sign-in does.
- [`server/routes/me.get.ts`](./server/routes/me.get.ts): the protected route, through `requireAuthSession`. [`logout.post.ts`](./server/routes/logout.post.ts) clears the session.
- [`server/routes/ws.ts`](./server/routes/ws.ts): a WebSocket at `/ws`. The session is read once, in `upgrade`, the only hook that can refuse; what the socket needs is returned as `context`, which every later hook receives as `peer.context`, and the headers `upgrade` returns ride on the `101`, so a roll or an expired cookie's deletion reaches the browser.
- [`server/routes/throw-after-clear.get.ts`](./server/routes/throw-after-clear.get.ts): clears, then throws a `401`. On Nitro v3 the client stays signed in: Nitro's error handler answers with a `Response` of its own and the `Set-Cookie` written before the throw is lost. The route reproduces that; the fix belongs upstream.
- [`index.html`](./index.html): one button per route and a log of what each answered. Nitro serves it for every unmatched route.
