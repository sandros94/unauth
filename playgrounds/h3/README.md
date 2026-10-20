# h3 playground

An authentication session over h3 v2 with `unauth/n`: one `defineAuthSession` at module scope, used on the h3 event as it is, a `defineSessionGuard` guard, and a GitHub sign-in on one route with `defineSignInHandler`. No adapter: `unauth` has no `h3` dependency. Everything is in [`main.ts`](./main.ts).

```sh
pnpm dev:prepare   # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev     # at the repository root, or here: runs main.ts under `node --watch`
```

```sh
curl -X POST localhost:3000/login -H 'content-type: application/json' -d '{"user":"alice"}' -c jar
curl localhost:3000/me -b jar
curl -X POST localhost:3000/logout -b jar
```

The session is an encrypted JWE cookie (`__Host-unauth`) over a key derived once from a password (`SESSION_PASSWORD`, with a default for local use), with a one hour `maxAge` and `rolling: "15m"`: the first read on a token older than 15 minutes issues a fresh hour, so an active user never expires. `POST /login` calls `authenticate()`, which sets `authenticatedAt` and reissues the token under a new id; `GET /me` goes through `defineSessionGuard(auth)`, which answers `401` with a `Response` unless the session authenticated, and the handler reads the same session with `auth.require(event)`, typed as authenticated.

## Sign in with GitHub

`GET /auth/github` is both legs of the sign-in: without `code` it redirects to GitHub with a sealed flow cookie (state, PKCE), and with one it completes the callback, signs the user in through `onSuccess` and redirects home. Register an OAuth app at GitHub with `http://localhost:3000/auth/github` as its callback URL, then:

```sh
GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… pnpm dev
```

A failed flow is answered with a plain `Response` carrying the error's status; pass `onError` to answer it yourself.

## A handler that throws after a write

h3 sends a thrown handler's error with `res.errHeaders` only and discards the prepared `res.headers`, so `GET /throw-after-clear` leaves the client signed in: the `Set-Cookie` of the `clear()` is lost with the throw. Two session hooks (`onUpdate`, `onClear`) that copy `res.headers`' cookies onto `res.errHeaders` keep them, as the unjwt h3 guide shows; the same goes for a `Response` of status 400 or more returned from a handler.
