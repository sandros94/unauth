# unauth

[![npm version](https://npmx.dev/api/registry/badge/version/unauth?name=true)](https://npmx.dev/package/unauth) [![npm downloads](https://npmx.dev/api/registry/badge/downloads/unauth)](https://npmx.dev/package/unauth) [![bundle size](https://npmx.dev/api/registry/badge/size/unauth)](https://npmx.dev/package/unauth)

A collection of low-level and high-level, server-agnostic, Authentication and Authorization (soon) utilities.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback. Expect breaking changes.

## Features

- **OAuth 2.1 and OpenID Connect** — one handler for both legs of a sign-in, presets for GitHub, Google, Apple, Microsoft, Discord, GitLab, LinkedIn, Facebook, Twitch, X, Spotify, TikTok, Netlify, Vercel and Cloudflare Access, generic `defineOAuth2Provider` and `defineOidcProvider`
- **AT Protocol** — sign in with any PDS account: handle resolution, PAR, PKCE, DPoP, the account verified against its PDS automatically
- **Custom providers** — any protocol over the same engine, with `start` and `complete` legs
- **Sessions** — `unauth/session` is unjwt's cookie sessions plus `defineOpaqueSession`: a random token in the cookie or a bearer header, the record in your store, same manager as the JWE session
- **One-time tokens** — `unauth/token`: signed, single-use, expiring tokens, and opaque tokens with their hash
- **Web-standard** — handlers take a request event `{ req, res: { headers } }`; `startFlow` and `completeFlow` take a `Request`
- **unjwt included** — `unauth/jwk`, `unauth/jws`, `unauth/jwe`, `unauth/utils`, `unauth/session` and `unauth/dpop` are unjwt's subpaths, one dependency to install

Built on:

- [`unjwt`](https://github.com/sandros94/unjwt) — JWT (JWS/JWE/JWK) and cookie sessions via Web Crypto
- [`unsecure`](https://github.com/sandros94/unsecure) — cryptographic utilities

## Usage

```sh
npx nypm install unauth
```

### Session

unauth never reads or writes the application's session. `onSuccess(event, result)` gets the request event and the proven `result.identity`, and the application saves whatever session it wants. Two ways to write the `createSession` and `useAuthSession` the examples below call:

A JWE cookie session with `unauth/session` (unjwt's `defineJWESession`, re-exported):

```ts
import type { H3Event } from "h3";
import { defineJWESession } from "unauth/session";

const sessions = defineJWESession<{ userId: string }, "1h">({ key, maxAge: "1h", rolling: "15m" });

export async function createSession(event: H3Event, { userId }: { userId: string }) {
  const session = await sessions.use(event);
  await session.clear();
  await session.update({ userId });
}

export async function useAuthSession(event: H3Event) {
  const session = await sessions.use(event);
  return session.id ? { userId: session.data.userId } : undefined;
}
```

An opaque session with `defineOpaqueSession`: the cookie carries a random token, a store of yours (five verbs over a table, or `kvSessionStore` over any `CacheDriver`) holds the session under it, so sessions can be listed and revoked. Unlike the JWE manager, whose data travels in the cookie, this one reads the store only when asked: `use()` is synchronous, `record` is a promise.

```ts
import type { H3Event } from "h3";
import { defineOpaqueSession } from "unauth/session";

const sessions = defineOpaqueSession<{ userId: string }>({ store, maxAge: "30D", idle: "7D" });

export async function createSession(event: H3Event, { userId }: { userId: string }) {
  const session = sessions.use(event);
  await session.clear();
  await session.update({ userId });
}

export async function useAuthSession(event: H3Event) {
  const { data } = await sessions.use(event).record;
  return data;
}
```

`maxAge` is the absolute lifetime, `idle` ends a session left alone, either or both. `rotate()` moves a session under a new token, `issue(data)` mints one without a request, `sessionHeader: true` also reads a `Bearer` token. The store may be a function of the request event, so a session write joins the transaction the request opened. A route that queries the database anyway can skip the session read and filter on the carried `session.token` (hashed as the store hashes it) inside its own query; [`playgrounds/nuxt-4-opaque`](./playgrounds/nuxt-4-opaque) does both over drizzle.

The full versions, with lifetimes, rotation and sign-out, are [`playgrounds/nuxt-4`](./playgrounds/nuxt-4) and [`playgrounds/nuxt-4-opaque`](./playgrounds/nuxt-4-opaque).

### Sign in with a provider

One route serves both legs: without `code` or `error` it redirects to the provider with a sealed flow cookie; with one it completes the callback and calls `onSuccess` with the proven identity.

```ts
import type { H3Event } from "h3";
import { deriveJWK } from "unauth/n";
import { defineGitHubHandler } from "unauth/n/providers/github";

app.all(
  "/auth/github",
  defineGitHubHandler({
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    key: () => deriveJWK(process.env.AUTH_SECRET!, { info: "unauth:flow" }),
    origin: "https://app.example",
    onSuccess: async (event: H3Event, { identity }) => {
      const user = await findOrCreateUser(identity);
      await createSession(event, { userId: user.id });
    },
  }),
);
```

- `key`: the key that seals the sign-in's flow cookie, or a callback returning it, called once on the first request. `deriveJWK(secret, { info })` turns a random secret of 32+ characters into one. Any symmetric JWE key works, the shapes unjwt's JWE sessions take: an `oct` JWK, a secret `CryptoKey`, or a JWK Set whose first key seals and every key opens, to rotate. A key naming no algorithm needs `jwe: { alg, enc }`; `onKeyLookup` picks the opening key from a token's header. A key pair is refused, since a token sealed to a public key could be minted by anyone holding it.
- `origin`: the callback is this route on that origin, and its forms may start a sign-in that links an account or names it; a request on any other origin is refused with a `421`. `redirectUri` names the callback outright instead. With `origin` too, both are where the sign-in runs.
- `onStart(event)`: optional; returns `{ redirect, memo, loginHint, scopes, params }` for this request. `memo` is anything the application wants back at the callback, sealed; `loginHint` names the account (OAuth's `login_hint`, an AT Protocol handle). A start that returns either `memo`, or `loginHint` for a custom provider, is taken only as a `POST` from the application's own origin (`ERR_AUTHN_CROSS_SITE_START`, a `403`, otherwise): start those sign-ins from a form, and return them only when `event.req.method === "POST"`.
- `onSuccess(event, result)`: required; `result` holds `identity`, `tokens`, `memo` and `redirect`. Returning nothing answers a `302` to `result.redirect`, else the `redirect` option, else `/`; returning a `Response` or a value answers that.
- Headers the application sets on `event.res.headers` in `onStart` or `onSuccess` (its session cookie), and the expiry of the consumed flow cookie, reach the browser because the framework sends them with whatever the handler returns, as h3, Nitro and Nuxt do; an adapter for another framework must apply them.
- `fetch`: optional; replaces the global `fetch` for every request a sign-in makes to a provider, where a deployment refuses private network ranges.
- `onError(event, error)`: optional; `error` is an `UnauthError` with `code`, `cause` and `status`, an `UnauthError` thrown by `onStart` or `onSuccess` included. Without it, or when it returns nothing, the failure is answered with a plain `Response` of that status: answer the codes you care about, return nothing for the rest.
- Annotate the `event` of the first hook you write with the framework's event type: every hook and the handler take it, `result` and `memo` stay inferred.
- `defineSignInHandler(provider, options)` is the same handler for any provider. It answers `GET` and `POST` and refuses other methods with a `405`: mount it without a method filter (`app.all(...)`, a `routes/auth/github.ts` rather than `.get.ts`).

### Linking another account

`onStart` notes the signed-in user in `memo`; it comes back as `result.memo`, sealed, and `onSuccess` decides what to do with it. Such a start comes from a form, never from a link: a link proves nothing about who chose it, a form on the application's own page does. `onStart` returns the memo only for a `POST`, so a signed-in user following a sign-in link signs in as usual instead of meeting a `403`.

```ts
onStart: async (event: H3Event) => {
  if (event.req.method !== "POST") return;
  const session = await useAuthSession(event);
  return session ? { memo: { userId: session.userId } } : undefined;
},
onSuccess: async (event, { identity, memo }) => {
  if (memo) return linkIdentity(memo.userId, identity);
  // a plain sign-in otherwise
},
```

```html
<form method="post" action="/auth/github"><button>Link a GitHub account</button></form>
```

### Sign in with AT Protocol

```ts
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

app.all(
  "/auth/atproto",
  defineAtprotoHandler({
    clientId: "https://app.example/oauth-client-metadata.json",
    redirectUri: "https://app.example/auth/atproto",
    key,
    onStart: async (event: H3Event) => ({ loginHint: (await event.req.formData()).get("login") }),
    onSuccess,
  }),
);
```

- `onStart` names the account (a handle, a DID or a server URL) as `loginHint`; the handler reads nothing from the request. Naming the account picks the server the sign-in is pushed to, so the start is a `POST` form from the application's own pages (`ERR_AUTHN_CROSS_SITE_START` otherwise).
- The provider's `client.metadata` is the document to serve at `clientId`; define the provider once with `defineAtprotoProvider` and pass it as `provider` to share it with that route.
- A `clientId` on `http://localhost` is the development client; its callback must be on a loopback IP. `devOrigins: ["http://localhost:3000"]` maps a `localhost:3000` callback to `127.0.0.1:3000` and returns the result, or its failure, to `http://localhost:3000`, where `onSuccess` or `onError` runs.

### Custom providers

A custom provider runs its own two legs over the engine's flow. `state` and the flow cookie only prove that the callback came back to the browser that started the sign-in, and that browser may be anyone's: `complete` must take the identity from a proof the provider issued and verifies there, never from what `start` was told. A magic link, with the proof a one-time token sent to the address:

```ts
import { UnauthError, defineProvider } from "unauth/n";
import { defineOneTimeToken } from "unauth/token";

const magicLinks = defineOneTimeToken<{ email: string; state: string }>({
  key: signingKey,
  maxAge: "15m",
  purpose: "magic-link",
  consume: ({ jti, expiresAt }) => usedLinks.add(jti, expiresAt),
});

const magic = defineProvider<{ email: string }>({
  id: "magic",
  kind: "custom",
  start: async ({ record, redirectUri, loginHint }) => {
    if (!loginHint) {
      throw new UnauthError("Enter your email to sign in.", "ERR_AUTHN_LOGIN_HINT_REQUIRED", {
        status: 400,
      });
    }
    const link = new URL(redirectUri);
    link.searchParams.set("state", record.state);
    link.searchParams.set(
      "code",
      await magicLinks.issue({ email: loginHint, state: record.state }),
    );
    await sendMail(loginHint, link.href);
    return { url: new URL("/check-your-inbox", redirectUri) };
  },
  complete: async ({ params, record }) => {
    const claim = await magicLinks.open(params.code ?? "");
    if (claim.state !== record.state) {
      throw new UnauthError("This link belongs to another sign-in.", "ERR_AUTHN_STATE_MISMATCH", {
        status: 401,
        cause: { provider: "magic" },
      });
    }
    return {
      identity: {
        subject: claim.email,
        email: claim.email,
        emailVerified: true,
        profile: { email: claim.email },
      },
    };
  },
});
```

- `start` sends the user somewhere and may seal `data` in the record for `complete`; it is the application's input, sealed, not a proof. Here the proof is the token: only the inbox receives it, and it names the `state` of the sign-in it was issued for.
- `complete` receives the callback's `params` with `state` already checked against the record, and returns the identity it verified. A callback without a usable proof must throw: the engine never completes on its own.
- `consume` records each token's `jti` until `expiresAt` and answers whether this was its first use; `usedLinks` is whatever store the deployment has.

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
