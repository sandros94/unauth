# unauth

[![npm version](https://npmx.dev/api/registry/badge/version/unauth?name=true)](https://npmx.dev/package/unauth) [![npm downloads](https://npmx.dev/api/registry/badge/downloads/unauth)](https://npmx.dev/package/unauth) [![bundle size](https://npmx.dev/api/registry/badge/size/unauth)](https://npmx.dev/package/unauth)

A collection of low-level and high-level, server-agnostic, Authentication and Authorization utilities.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback. Expect breaking changes, as I prioritize usability and correctness over stability at this stage.

## Features

- **Authentication session** — an encrypted (JWE) or signed (JWS) cookie session from [`unjwt/session`](https://unjwt.s94.dev/frameworks/session), plus `authenticate()`, `authenticatedAt`, revocation, refresh on roll and sign-in/sign-out events
- **OAuth 2.1 and OpenID Connect** — `startFlow` / `completeFlow` over the Web `Request`, one handler for both legs, presets for GitHub, Google, Apple, Microsoft, Discord, GitLab, LinkedIn, Facebook, Twitch and X
- **Sign-in resolution** — `signIn()` maps a proven identity to your user and identity records, linking included
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

The authentication session is an `unjwt/session` definition with authentication on top: `authenticate()` sets `authenticatedAt` and reissues the token under a new id; `require(event)` returns the session once it authenticated, typed as such, or throws `ERR_AUTHN_UNAUTHENTICATED` (401); `isAuthenticated(session)` narrows one already in hand.

```ts
import { H3 } from "h3";
import { generateJWK } from "unjwt/session";
import { defineAuthSession, defineSessionGuard } from "unauth/n";

const key = await generateJWK("A256GCM"); // load a persisted key in production

const auth = defineAuthSession<{ userId: string; role: string }>({
  key,
  maxAge: "7D",
  hooks: {
    // Runs once per request on a session read from its token; `true` clears it.
    isRevoked: async ({ session }) => !(await db.users.exists(session.data.userId)),
    onSignIn: ({ session }) => audit("sign-in", session.data.userId),
    onSignOut: ({ oldSession, reason }) => audit("sign-out", oldSession.data.userId, reason),
  },
});

const app = new H3()
  .post("/login", async (event) => {
    const session = await auth.use(event);
    await session.authenticate({ userId: "u1", role: "admin" });
    return { ok: true };
  })
  .get("/me", async (event) => (await auth.require(event)).data, {
    middleware: [defineSessionGuard(auth)],
  })
  .post("/logout", async (event) => {
    await (await auth.use(event)).clear();
    return { ok: true };
  });
```

`use()` takes what `unjwt/session` takes: the `{ req, res, context }` event of h3 v2, Nitro 3 and a `nuxt/server` handler, a request by its headers (a WebSocket upgrade), or `{ token }` for a token in hand. A third generic (`defineAuthSession<Data, H3Event>`) narrows `use()` and every hook's `context` to a framework's own event.

The cookie is `__Host-unauth` (secure, `httpOnly`, `SameSite=Lax`), `__Secure-unauth` when a `domain` or `path` rules the `__Host-` prefix out, `unauth` without `secure`. The session is reissued on read once the token is three quarters of `maxAge` old, so `exp` slides with activity; tune it with `rolling`: a duration is the age a token must reach, `true` reissues on every read, `false` never. A roll fires unjwt's `onUpdate` with `trigger: "rolling"` and the `refresh` hook, which can merge data into the session or clear it.

Every [unjwt session hook](https://unjwt.s94.dev/frameworks/hooks) passes through: `session` is the live manager, so `onRead` can `update()` or `clear()` the session it is looking at.

### Sign in with a provider

One route serves both legs of a sign-in: without `code` it answers the redirect to the provider with a sealed flow cookie (state, PKCE and, for OpenID Connect, a nonce); with one it completes the callback and hands the proven identity to `onSuccess`.

```ts
import { defineSignInHandler, signIn } from "unauth/n";
import { defineGitHubProvider } from "unauth/n/providers/github";

const github = defineGitHubProvider({
  clientId: process.env.GITHUB_CLIENT_ID!,
  clientSecret: process.env.GITHUB_CLIENT_SECRET!,
});

app.get(
  "/auth/github",
  defineSignInHandler(github, {
    key: flowKey, // seals the flow cookie
    redirectUri: "https://app.example/auth/github",
    onSuccess: async (event, { identity, redirect }) => {
      const { user } = await signIn(identity, { identities });
      const session = await auth.use(event);
      await session.authenticate({ userId: user.id, role: user.role });
      return new Response(null, { status: 302, headers: { location: redirect ?? "/" } });
    },
  }),
);
```

The handler returns a `Response` for the redirect and what `onSuccess` returns for the callback, which h3 v2, Nitro 3 and `nuxt/server` send as they are. A failed flow is an `UnauthError` with a status: answered by `onError` when given, else with a plain `Response` carrying that status. `signIn()` resolves the identity against your `IdentityStore` (find by provider account, create, link) and never matches accounts by email.

Generic providers come from `defineOAuth2Provider({ id, clientId, clientSecret, authorization, token, userinfo })` and `defineOidcProvider({ issuer, clientId, clientSecret })`, which reads the endpoints from the issuer's discovery document. The lower-level `startFlow(provider, request, options)` and `completeFlow(provider, request, options)` work on a Web `Request` on any runtime.

### Guard

`defineSessionGuard(auth)` is a middleware answering a `401` `Response` unless the request carries an authenticated session; the handler behind it reads the same session with `auth.require(event)`. `onAuthenticated` runs with the authenticated session and the context before the handler, where a throw refuses the request:

```ts
import { HTTPError } from "h3";
import { defineSessionGuard } from "unauth/n";

app.delete("/admin/users/:id", handler, {
  middleware: [
    defineSessionGuard(auth, {
      onAuthenticated({ session }) {
        if (session.data.role !== "admin") throw new HTTPError({ status: 403 });
      },
    }),
  ],
});
```

### Frameworks

The [`playgrounds/`](./playgrounds) directory runs the same application on h3 v2, Nitro 3 and Nuxt 4.6: a password login, the GitHub sign-in, a guarded route and a WebSocket upgrade. On Nuxt the handlers come from `nuxt/server`, whose event is the web-standard one; on Nitro everything comes from `nitro`. Neither needs `h3` as a dependency.

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
