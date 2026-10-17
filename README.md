# unauth

[![npm version](https://npmx.dev/api/registry/badge/version/unauth?name=true)](https://npmx.dev/package/unauth) [![npm downloads](https://npmx.dev/api/registry/badge/downloads/unauth)](https://npmx.dev/package/unauth) [![bundle size](https://npmx.dev/api/registry/badge/size/unauth)](https://npmx.dev/package/unauth)

A collection of low-level and high-level, server-agnostic, Authentication and Authorization utilities.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback. Expect breaking changes, as I prioritize usability and correctness over stability at this stage.

## Features

- **Session management** — Encrypted JWE sessions with rolling expiry
- **Token pairs** — Access (JWS) + Refresh (JWE) token lifecycle with coordinated login/logout
- **CSRF protection** — Double-submit cookie pattern with HMAC
- **Middleware** — `requireSession`, `optionalSession`, `requireAuth`, `optionalAuth`
- **Runtime-agnostic** — Built on Web Crypto API
- **OAuth 2.1 and OIDC** — Planned

Built on top of minimal dependencies:

- [`unjwt`](https://github.com/sandros94/unjwt) — Low-level JWT (JWS/JWE/JWK) via Web Crypto
- [`unsecure`](https://github.com/sandros94/unsecure) — Cryptographic utilities (HMAC, secure compare, etc.)

## Usage

Install the package:

```sh
npx nypm install unauth
```

### Session

Encrypted session cookies (JWE) with rolling expiry.

```ts
import { defineSession, generateJWK, requireSession } from "unauth/base/h3";

const sessionKey = await generateJWK("A256GCM");

const useSession = defineSession<{ userId: string; role: string }>({
  key: sessionKey,
  maxAge: "7D",
  hooks: {
    async onRead({ session }) {
      // The live session manager: sync it with your database, or end it
      const user = await db.users.findById(session.data.userId);
      if (!user) return session.clear();
      if (user.role !== session.data.role) await session.update({ role: user.role });
    },
  },
});

const app = new H3()
  .post("/login", async (event) => {
    const session = await useSession(event);
    await session.update({ userId: "u1", role: "admin" });
    return { ok: true };
  })
  .get(
    "/me",
    async (event) => {
      const session = await useSession(event);
      return { user: session.data };
    },
    { middleware: [requireSession(useSession)] },
  )
  .post("/logout", async (event) => {
    const session = await useSession(event);
    await session.clear();
    return { ok: true };
  });
```

The session is reissued on read once less than a quarter of `maxAge` remains, so `exp` slides with activity. Tune it with `rolling`: a duration (`rolling: "1D"`) sets the remaining-time window, `true` reissues on every read, `false` never. A roll fires `onUpdate` with `trigger: "rolling"`.

Hooks are [unjwt's session hooks](https://unjwt.s94.dev/adapters/hooks), `session` is the live manager, so `onRead` can `update()` or `clear()` the session it is looking at.

### Token Pair

Access token (JWS, short-lived, client-readable) + refresh token (JWE, long-lived, encrypted) with coordinated lifecycle.

```ts
import { defineTokenPair, generateJWK, requireAuth } from "unauth/base/h3";

const atKeys = await generateJWK("ES256");
const rtKey = await generateJWK("A256GCM");

const useAuth = defineTokenPair<
  { sub: string; permissions: string[] },
  { sub: string; family: string }
>({
  access: { key: atKeys, maxAge: "15m" },
  refresh: { key: rtKey, maxAge: "30D" },
  hooks: {
    async onRefresh({ refresh, issue }) {
      const user = await db.users.findById(refresh.data.sub);
      if (!user || user.suspended) return; // don't issue — AT stays empty
      await issue({
        accessData: { sub: user.id, permissions: user.permissions },
        // refreshData is optional — omit to rotate with current data
      });
    },
    onAfterRefresh({ access, refresh, previousRefresh }) {
      logger.info("token_refresh", {
        sub: access.data.sub,
        newAtId: access.id,
        oldRtId: previousRefresh.id,
        newRtId: refresh.id,
      });
    },
  },
});

const app = new H3()
  .post("/login", async (event) => {
    const auth = await useAuth(event);
    await auth.issue({
      accessData: { sub: user.id, permissions: user.permissions },
      refreshData: { sub: user.id, family: crypto.randomUUID() },
    });
    return { ok: true };
  })
  .get(
    "/me",
    async (event) => {
      const { access } = await useAuth(event);
      return { user: access.data };
    },
    { middleware: [requireAuth(useAuth)] },
  )
  .post("/logout", async (event) => {
    const auth = await useAuth(event);
    await auth.revoke();
    return { ok: true };
  });
```

When the access token expires:

- `onRefresh` fires with the valid refresh token
- Call `issue({ accessData, refreshData? })` to re-issue the AT and rotate the RT
- Call `revoke()` to clear both tokens (e.g., user banned, family revoked)
- Don't call either to skip (AT stays empty, RT preserved)
- Throw to forward errors to `onError` without destroying tokens

`onReadAccess` fires whenever a valid access token is read, with or without a refresh token beside it: `refresh` is `undefined` when the refresh cookie is missing, so a revocation check there cannot be bypassed by dropping that cookie.

Both `access` and `refresh` are unjwt session managers exposed directly — call `.update()` or `.clear()` on them for escape-hatch scenarios that bypass hooks.

### CSRF

Double-submit cookie pattern with HMAC-generated tokens.

```ts
import { defineCsrf } from "unauth/base/h3";

const csrf = defineCsrf({ secret: process.env.CSRF_SECRET! });

const app = new H3()
  .get("/form", handler, { middleware: [csrf] })
  .post("/form", handler, { middleware: [csrf] });
```

### Middleware

Separate middleware for sessions and token pairs:

```ts
import { requireSession, optionalSession, requireAuth, optionalAuth } from "unauth/base/h3";

// Session middleware
app.get("/me", handler, { middleware: [requireSession(useSession)] });
app.get("/feed", handler, { middleware: [optionalSession(useSession)] });

// Token pair middleware
app.get("/me", handler, { middleware: [requireAuth(useAuth)] });
app.get("/feed", handler, { middleware: [optionalAuth(useAuth)] });

// With authorization checks
app.delete("/admin/users/:id", handler, {
  middleware: [
    requireAuth(useAuth, {
      onAuthenticated({ session }) {
        if (!session.data.permissions.includes("admin:users:delete")) {
          throw new HTTPError("Forbidden", { status: 403 });
        }
      },
    }),
  ],
});
```

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run interactive tests using `pnpm dev`

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
