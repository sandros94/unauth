# unauth

[![npm version](https://npmx.dev/api/registry/badge/version/unauth?name=true)](https://npmx.dev/package/unauth) [![npm downloads](https://npmx.dev/api/registry/badge/downloads/unauth)](https://npmx.dev/package/unauth) [![bundle size](https://npmx.dev/api/registry/badge/size/unauth)](https://npmx.dev/package/unauth)

A collection of low-level and high-level, server-agnostic, Authentication and Authorization utilities.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback. Expect breaking changes, as I prioritize usability and correctness over stability at this stage.

## Features

- **OAuth 2.1 and OpenID Connect** — `startFlow` / `completeFlow` over the Web `Request`, one handler for both legs, presets for GitHub, Google, Apple, Microsoft, Discord, GitLab, LinkedIn, Facebook, Twitch and X
- **AT Protocol** — sign in with a Bluesky or any other PDS account: handle resolution, PAR, PKCE and DPoP, the account verified against its PDS; and a `custom` provider kind for any protocol the engine does not run itself
- **One-time tokens** — signed, single-use, expiring tokens for invitations, password resets and magic links
- **Framework-free** — the event h3 v2, Nitro 3 and Nuxt's `nuxt/server` hand a handler is taken as it is; a `Request` and a `Headers` serve every other runtime
- **Authorization** — Planned

Built on top of minimal dependencies:

- [`unjwt`](https://github.com/sandros94/unjwt) — Low-level JWT (JWS/JWE/JWK) and cookie sessions via Web Crypto
- [`unsecure`](https://github.com/sandros94/unsecure) — Cryptographic utilities (HMAC, secure compare, etc.)

## Usage

Install the package and its `unjwt` peer:

```sh
npx nypm install unauth unjwt
```

### Session

The session is the application's own [`unjwt/session`](https://unjwt.s94.dev) definition, which a sign-in writes to; its options are in the unjwt docs. Its data extends `AuthSessionData`, what a sign-in writes by default.

```ts
import { type H3Event, HTTPError } from "h3";
import { defineJWESession } from "unjwt/session";
import type { AuthSessionData } from "unauth/n";

interface SessionData extends AuthSessionData {
  role?: string;
}

const session = defineJWESession<SessionData, "1h">({ key, maxAge: "1h", rolling: "15m" });

const useAuthSession = (event: H3Event) => session.use(event);
async function requireAuthSession(event: H3Event) {
  const current = await useAuthSession(event);
  if (!current.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  return current;
}
```

### Sign in with a provider

One route serves both legs of a sign-in: without `code` it answers the redirect to the provider with a sealed flow cookie (state, PKCE and, for OpenID Connect, a nonce); with one it completes the callback, writes the proven identity to the session and sends the browser on. Each preset has a handler that takes the provider's options and the sign-in's in one object:

```ts
import { defineGitHubHandler } from "unauth/n/providers/github";
import { deriveKey } from "unauth/n";

app.get(
  "/auth/github",
  defineGitHubHandler({
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    key: () => deriveKey(process.env.AUTH_SECRET!, { info: "unauth:flow" }), // seals the flow cookie
    origin: "https://app.example", // the callback is this route on this origin
    session: useAuthSession,
  }),
);
```

`key` takes a JWE key, or a callback returning one, called once per handler, on its first request, and its key kept from then on; an app that wants one key object across routes derives it in a util and passes it as `key`. `deriveKey(secret, { info })` turns a random secret of 32 characters or more (`openssl rand -base64 32`, never a passphrase: HKDF is not a password KDF) into an `A256GCM` key, the same for the same secret and `info` on every instance and restart; `"unauth:flow"` is the conventional `info` for the flow key. A runtime with its own purpose-bound derivation, such as Nuxt's `deriveSecret`, builds the `oct` key from that material in the callback instead of deriving again, and a PEM goes through unjwt's `importPEM(pem, alg)`.

`defineSignInHandler(provider, options)` is the same handler for any provider, one you built yourself included; the preset handler above is `defineSignInHandler` on `defineGitHubProvider`:

```ts
import { defineSignInHandler, deriveKey } from "unauth/n";

app.get(
  "/auth/sso",
  defineSignInHandler(sso, {
    key: () => deriveKey(process.env.AUTH_SECRET!, { info: "unauth:flow" }),
    origin: "https://app.example",
    session: useAuthSession,
  }),
);
```

The session receives `toSessionData(identity)`, an `AuthSessionData` (`provider`, `subject`, `name`, `email`, `emailVerified`, `avatar` and `signedInAt`), so its data is `AuthSessionData` or an interface extending it; `toSession` maps the identity to other data instead. A sign-in replaces the session, cleared then written, so nothing of whoever was signed in before carries over and the session id is a new one. The browser then lands on `redirect` (default `/`), or on the same-origin path the request asked for. `redirectUri` names the callback outright in place of `origin`.

`onSuccess` takes over the response: with `session` it runs after the write, and without `session` it is required and does the rest itself, as a link intent always needs it to:

```ts
onSuccess: async (event, { identity, redirect }) => {
  const session = await useAuthSession(event);
  await session.clear();
  await session.update({ ...toSessionData(identity, { now: Date.now() }), role: "member" });
  return new Response(null, { status: 302, headers: { location: redirect ?? "/" } });
},
```

The handler returns a `Response`, or what `onSuccess` returns, which h3 v2, Nitro 3 and `nuxt/server` send as they are. A failed flow is an `UnauthError` with a status: answered by `onError` when given, else with a plain `Response` carrying that status.

Generic providers come from `defineOAuth2Provider({ id, clientId, clientSecret, authorization, token, userinfo })` and `defineOidcProvider({ issuer, clientId, clientSecret })`, which reads the endpoints from the issuer's discovery document. The lower-level `startFlow(provider, request, options)` and `completeFlow(provider, request, options)` work on a Web `Request` on any runtime.

### Sign in with AT Protocol

An AT Protocol account (Bluesky, or any PDS) signs in from its handle, DID or server URL, which the handler reads from the request's `?login=` (an `onStart` that names a `login` wins). There is nothing to register: the app's identity is the URL of a client metadata document it publishes.

```ts
import { deriveKey } from "unauth/n";
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

app.get(
  "/auth/atproto",
  defineAtprotoHandler({
    clientId: "https://app.example/oauth-client-metadata.json",
    redirectUri: "https://app.example/auth/atproto",
    key: () => deriveKey(process.env.AUTH_SECRET!, { info: "unauth:flow" }),
    session: useAuthSession,
  }),
);
```

The provider carries the document to publish at its `clientId` as `client.metadata`, built from its config (`clientName`, `clientUri`, `logoUri`, `tosUri`, `policyUri`); it is absent for the development client, which publishes none. Two routes need the same provider, so an app defines it once with `defineAtprotoProvider` and hands it to the handler as `provider`:

```ts
import { defineAtprotoProvider } from "unauth/n/providers/atproto";

const atproto = defineAtprotoProvider({ clientId, redirectUri, clientName: "My app" });

app.get("/oauth-client-metadata.json", () => atproto.client.metadata);
app.get("/auth/atproto", defineAtprotoHandler({ provider: atproto, key, session: useAuthSession }));
```

The handle is resolved through DNS-over-HTTPS and the `/.well-known/atproto-did` document, the DID through `plc.directory` or the `did:web` host (both configurable), the PDS's authorization server is discovered and checked against the atproto profile, the request is pushed (PAR) with PKCE and a DPoP proof, and after the callback the token's `sub` is checked against the account the sign-in started from. The DPoP-bound tokens are not kept: this is sign-in only. In development the same config works unchanged: a `clientId` on `http://localhost` is one no server could fetch, so the provider uses the spec's development client instead, whose callback must be a loopback IP (the atproto profile refuses `localhost`, RFC 8252 §8.3); `devHosts: ["localhost"]` registers the callback on `127.0.0.1`, moves a sign-in started on `localhost` there before any cookie is set (the way the official browser client does), and once the callback completed sends the browser back to `localhost` with the result in a sealed, one-minute, single-use token, so `onSuccess` and the session live where you started. The identity is `identity.subject`, the DID, and `identity.profile` carries the verified handle, the PDS and the authorization server.

### Custom providers

A `kind: "custom"` provider brings its own two legs over the same engine: it receives the request, the sealed flow record and a `fetch`, returns the URL the user is sent to (with any `data` to keep until the callback), and later turns the callback's parameters into an identity. The engine keeps `state`, the return path, the link intent and the cookie, and `defineSignInHandler` serves it like any other provider; the AT Protocol provider is built on it.

```ts
import { defineProvider } from "unauth/n";

const magic = defineProvider<{ email: string }>({
  id: "magic",
  kind: "custom",
  start: async ({ record, redirectUri, login }) => ({
    url: `https://magic.example/send?email=${login}&state=${record.state}&return=${redirectUri}`,
    data: { email: login },
  }),
  complete: async ({ params, record }) => ({
    identity: {
      subject: String(record.data?.email),
      profile: { email: String(record.data?.email) },
    },
  }),
});
```

### Frameworks

The [`playgrounds/`](./playgrounds) directory runs the same application on h3 v2, Nitro 3 and Nuxt 4.6: a password login, the GitHub and AT Protocol sign-ins, a protected route and a WebSocket upgrade. On Nuxt the handlers come from `nuxt/server`, whose event is the web-standard one, and only the WebSocket handler from `h3`; on Nitro everything comes from `nitro`, without `h3` as a dependency.

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run `pnpm dev:prepare` once, then `pnpm dev` (h3), `pnpm dev:nitro` or `pnpm dev:nuxt`

</details>

## Why unauth?

I started by building `unjwt`, as I needed a cryptographically secure way to transmit sensitive information between various programming languages and servers. Not long after I started requiring some standardization, in particular on how to prepare and expect authorization data to be shared between parties (client and servers), but as I was testing various libraries I've never been satisfied by their DX (although most of them were great for someone that already knows the topic). So I started building `unauth` as a collection of low-level primitives that then can be wrapped in higher-level abstractions, via adapters, to provide a "batteries included" experience while retaining control and flexibility of using your preferred storage, database and web frameworks.

## Credits

- Thanks to [Vidbase, Inc.](https://github.com/vidbase) (in particular to [Van Nguyen](https://github.com/thegoleffect)) for the npm package name donation

## License

<!-- automd:contributors license=MIT -->

Published under the [MIT](https://github.com/sandros94/unauth/blob/main/LICENSE) license. Made by [community](https://github.com/sandros94/unauth/graphs/contributors) 💛 <br><br> <a href="https://github.com/sandros94/unauth/graphs/contributors"> <img src="https://contrib.rocks/image?repo=sandros94/unauth" /> </a>

<!-- /automd -->

<!-- automd:with-automd -->

---

_🤖 auto updated with [automd](https://automd.unjs.io)_

<!-- /automd -->
