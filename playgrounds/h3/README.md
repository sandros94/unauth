# h3 playground

The low-level form of `unauth/n` on h3 v2, all in [`main.ts`](./main.ts): an `unjwt/session` definition used on the h3 event as it is, and each sign-in as `defineSignInHandler(provider, options)` with an explicit `onSuccess` that writes the session itself. No adapter: `unauth` has no `h3` dependency.

```sh
pnpm dev:prepare   # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev     # at the repository root, or here: runs main.ts under `node --watch`
```

```sh
curl -X POST localhost:3000/login -H 'content-type: application/json' -d '{"user":"alice"}' -c jar
curl localhost:3000/me -b jar
curl -X POST localhost:3000/logout -b jar
```

The session is an encrypted JWE cookie over a key derived once from a password (`SESSION_PASSWORD`, with a default for local use), with a one hour `maxAge` and `rolling: "15m"`: the first read on a token older than 15 minutes issues a fresh hour, so an active user never expires. The definition's third generic narrows `use()` to `H3Event`. `useAuthSession(event)` reads it, `requireAuthSession(event)` answers `401` before sign-in. `POST /login` writes `{ user }`, `GET /me` returns the session, `POST /logout` clears it. A second key, derived from the same password, seals the sign-in flow cookie.

## Sign in with GitHub

`GET /auth/github` is both legs of the sign-in: without `code` it redirects to GitHub with a sealed flow cookie (state, PKCE), and with one it completes the callback and hands the result to `onSuccess`, which writes the session and redirects home. Register an OAuth app at GitHub with `http://localhost:3000/auth/github` as its callback URL, then:

```sh
GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… pnpm dev
```

A failed flow is answered with a plain `Response` carrying the error's status; pass `onError` to answer it yourself.

## Sign in with AT Protocol

`GET /auth/atproto?login=<handle, DID or server URL>` is both legs too, `onStart` reading `login` from the query: the account's PDS and authorization server are discovered from the handle, the request is pushed (PAR, PKCE, DPoP) and the callback proves the account. No registration anywhere: the app's identity is `/oauth-client-metadata.json` on `ORIGIN`, served by the route of that name. In development that is a `localhost` URL no server can fetch, so the provider uses the spec's development client instead, whose callback must be a loopback IP (the atproto profile refuses `localhost`, RFC 8252 §8.3): `devHosts: ["localhost"]` registers the callback on `127.0.0.1` and moves a start on `localhost` there before any cookie is set, and after the callback hands the result back to `localhost` in a sealed one-minute token, so the session is created where you started.

```sh
open http://localhost:3000/auth/atproto?login=alice.bsky.social
```

## A handler that throws after a write

h3 sends a thrown handler's error with `res.errHeaders` only and discards the prepared `res.headers`, so `GET /throw-after-clear` leaves the client signed in: the `Set-Cookie` of the `clear()` is lost with the throw. Session hooks (`onUpdate`, `onClear`) that copy `res.headers`' cookies onto `res.errHeaders` keep them, as the unjwt h3 guide shows; the same goes for a `Response` of status 400 or more returned from a handler.
