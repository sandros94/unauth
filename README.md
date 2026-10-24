# unauth

[![npm version](https://npmx.dev/api/registry/badge/version/unauth?name=true)](https://npmx.dev/package/unauth) [![npm downloads](https://npmx.dev/api/registry/badge/downloads/unauth)](https://npmx.dev/package/unauth) [![bundle size](https://npmx.dev/api/registry/badge/size/unauth)](https://npmx.dev/package/unauth)

A collection of low-level and high-level, server-agnostic, Authentication and Authorization (soon) utilities.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback. Expect breaking changes.

## Features

- **OAuth 2.1 and OpenID Connect** — one handler for both legs of a sign-in, presets for GitHub, Google, Apple, Microsoft, Discord, GitLab, LinkedIn, Facebook, Twitch, X, Spotify, TikTok, Netlify, Vercel and Cloudflare Access, generic `defineOAuth2Provider` and `defineOidcProvider`
- **AT Protocol** — sign in with any PDS account: handle resolution, PAR, PKCE, DPoP, the account verified against its PDS automatically
- **Custom providers** — any protocol over the same engine, with `start` and `complete` legs
- **One-time tokens** — signed, single-use, expiring tokens
- **Web-standard** — handlers take a request event `{ req, res: { headers } }`; `startFlow` and `completeFlow` take a `Request`
- **unjwt included** — `unauth/jwk`, `unauth/jws`, `unauth/jwe`, `unauth/utils` and `unauth/session` are unjwt's subpaths, one dependency to install

Built on:

- [`unjwt`](https://github.com/sandros94/unjwt) — JWT (JWS/JWE/JWK) and cookie sessions via Web Crypto
- [`unsecure`](https://github.com/sandros94/unsecure) — cryptographic utilities

## Usage

```sh
npx nypm install unauth
```

### Session

The session is the application's own `unauth/session` definition (unjwt's `defineJWESession`, re-exported). A sign-in writes to it in `onSuccess`.

```ts
import { defineJWESession } from "unauth/session";

const session = defineJWESession<SessionData, "1h">({ key, maxAge: "1h", rolling: "15m" });
export const useAuthSession = (event: WebSessionEvent) => session.use(event);
```

### Sign in with a provider

One route serves both legs: without `code` or `error` it redirects to the provider with a sealed flow cookie; with one it completes the callback and calls `onSuccess` with the proven identity.

```ts
import type { H3Event } from "h3";
import { deriveKey } from "unauth/n";
import { defineGitHubHandler } from "unauth/n/providers/github";

app.get(
  "/auth/github",
  defineGitHubHandler({
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    key: () => deriveKey(process.env.AUTH_SECRET!, { info: "unauth:flow" }),
    origin: "https://app.example",
    onSuccess: async (event: H3Event, { identity }) => {
      const session = await useAuthSession(event);
      await session.clear();
      await session.update({ provider: identity.provider, subject: identity.subject });
    },
  }),
);
```

- `key`: a JWE key, or a callback returning one, called once on the first request. `deriveKey(secret, { info })` derives an `A256GCM` key from a random secret of 32+ characters. A PEM goes through `importPEM(pem, alg)` from `unauth/jwk`.
- `origin`: the callback is this route on that origin; `redirectUri` names it outright instead.
- `onStart(event)`: optional; returns `{ redirect, link, login, scopes, params }` for this request.
- `onSuccess(event, result)`: required; `result` holds `identity`, `tokens`, `link` and `redirect`. Returning nothing answers a `302` to `result.redirect`, else the `redirect` option, else `/`; returning a `Response` or a value answers that.
- `onError(event, error)`: optional; `error` is an `UnauthError` with `code`, `cause` and `status`. Without it the failure is answered with a plain `Response` of that status.
- Annotate the `event` of the first hook you write with the framework's event type: every hook and the handler take it, `result` and `link` stay inferred.
- `defineSignInHandler(provider, options)` is the same handler for any provider.

### Linking another account

`onStart` returns `link` when a session is signed in; it comes back as `result.link`, sealed. `onSuccess` decides what to do with it.

```ts
onStart: async (event: H3Event) => {
  const session = await useAuthSession(event);
  return session.id ? { link: { userId: session.data.userId } } : undefined;
},
onSuccess: async (event, { identity, link }) => {
  if (link) return linkIdentity(link.userId, identity);
  // a plain sign-in otherwise
},
```

### Sign in with AT Protocol

```ts
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

app.get(
  "/auth/atproto",
  defineAtprotoHandler({
    clientId: "https://app.example/oauth-client-metadata.json",
    redirectUri: "https://app.example/auth/atproto",
    key,
    onSuccess,
  }),
);
```

- The handler reads the account from `?login=` (a handle, a DID or a server URL).
- The provider's `client.metadata` is the document to serve at `clientId`; define the provider once with `defineAtprotoProvider` and pass it as `provider` to share it with that route.
- A `clientId` on `http://localhost` is the development client; its callback must be on a loopback IP. `devHosts: ["localhost"]` maps a `localhost` callback to `127.0.0.1` and returns the result to `localhost`.

### Custom providers

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

The [`playgrounds/`](./playgrounds) run the same application on h3, Nitro 3 and Nuxt 4.

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

I started by building `unjwt`, as I needed a cryptographically secure way to transmit sensitive information between various programming languages and servers. Not long after I started requiring some standardization, in particular on how to handle authentication flows, but as I was testing various libraries I've never been satisfied by their DX (either too basic or too complex to maintain). So I started building `unauth` as a collection of low-level primitives that get wrapped in high-level abstractions for every day use.

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
