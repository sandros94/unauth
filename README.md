# unauth

<!-- automd:badges bundlephobia style="flat" color="FFDC3B" -->

[![npm version](https://img.shields.io/npm/v/unauth?color=FFDC3B)](https://npmjs.com/package/unauth)
[![npm downloads](https://img.shields.io/npm/dm/unauth?color=FFDC3B)](https://npm.chart.dev/unauth)
[![bundle size](https://img.shields.io/bundlephobia/minzip/unauth?color=FFDC3B)](https://bundlephobia.com/package/unauth)

<!-- /automd -->

`unauth` Low-level OIDC utilities

## Usage

Install the package:

```sh
# ✨ Auto-detect (supports npm, yarn, pnpm, deno and bun)
npx nypm install unauth
```

Import:

**ESM** (Node.js, Bun, Deno)

```js
// Main functions
import { OAuthProvider } from "unauth/oauth";
import { OIDCProvider } from "unauth/oidc";
```

**CDN** (Deno, Bun and Browsers)

```js
// Main functions
import { OAuthProvider } from "https://esm.sh/unauth/oauth";
import { OIDCProvider } from "https://esm.sh/unauth/oidc";
```

### Quick start (OIDC)

```ts
import { OIDCProvider } from "unauth/oidc";

// Configure the provider once during startup.
const oidc = new OIDCProvider({
  issuer: "https://auth.example.com",
  authorizationCodeOptions: {
    privateKey: process.env.AUTH_CODE_SECRET!,
  },
  refreshTokenOptions: {
    privateKey: process.env.REFRESH_SECRET!,
  },
  accessTokenOptions: {
    privateKey: ACCESS_TOKEN_PRIVATE_JWK,
    publicKey: ACCESS_TOKEN_PUBLIC_JWK,
  },
  idTokenOptions: {
    privateKey: ID_TOKEN_PRIVATE_JWK,
    publicKey: ID_TOKEN_PUBLIC_JWK,
  },
});

// In your authorize endpoint
const authorize = oidc.validateAuthorizeRequest(req.query);
if (!authorize.success) {
  return redirectWithError(authorize.error);
}

const code = await oidc.issueAuthorizationCode({
  ...authorize.value,
  subject: "user-123",
  redirect_uri: authorize.value.redirect_uri ?? DEFAULT_REDIRECT_URI,
});

// In your token endpoint
const normalized = oidc.validateTokenRequest(req.body);
if (!normalized.success) {
  return sendError(normalized.error);
}

const grant = await oauth.issueTokenGrant(validation.value);
if (!grant.success) {
  return sendError(grant.error);
}

const idToken = await oidc.introspectIdToken(grant.value.id_token);
```

### Quick start (OAuth only)

```ts
import { OAuthProvider } from "unauth/oauth";

const oauth = new OAuthProvider({
  issuer: "https://auth.example.com",
  authorizationCodeOptions: {
    privateKey: process.env.AUTH_CODE_SECRET!,
  },
  refreshTokenOptions: {
    privateKey: process.env.REFRESH_SECRET!,
  },
  accessTokenOptions: {
    privateKey: ACCESS_TOKEN_PRIVATE_JWK,
    publicKey: ACCESS_TOKEN_PUBLIC_JWK,
  },
});

const validation = oauth.validateTokenRequest(req.body);
if (!validation.success) {
  return sendError(validation.error);
}

const grant = await oauth.issueTokenGrant(validation.value);
if (!grant.success) {
  return sendError(grant.error);
}

// Later, verify tokens issued by the provider
const accessClaims = await oauth.introspectAccessToken(
  grant.value.access_token,
);
```

> **Note**
> For advanced use-cases you can import the lower-level helpers directly, e.g. `import { issueAuthorizationCode } from "unauth/oauth"` or `import { buildUserInfo } from "unauth/oidc"`, to compose custom flows while keeping the same core primitives.

### Adapters

- **H3 v1**: For use with [H3 v1](https://v1.h3.dev)

#### Minimal H3 v1 Example

```ts
import { createApp, createRouter, defineEventHandler, getQuery } from "h3";
import { generateJWK, useOIDCProvider } from "unauth/h3";

// Create an app instance
export const app = createApp();

// Create a new router and register it in app
const router = createRouter();
app.use(router);

const [atJwk, idJwk] = await Promise.all([
  generateJWK("RS256", { kid: "at-rsa-1" }),
  generateJWK("RS256", { kid: "id-rsa-1" }),
]);
const provider = useOIDCProvider({
  issuer: "http://localhost:3000",
  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: atJwk,
  idTokenOptions: idJwk,
});

// OpenID Provider Configuration (Discovery)
router.get(
  "/.well-known/openid-configuration",
  defineEventHandler(() => {
    return provider.discovery();
  }),
);

// JWKS (public keys)
router.get(
  "/.well-known/jwks.json",
  defineEventHandler(() => provider.jwkSet),
);

// Simple callback endpoint for manual testing
router.get(
  "/callback",
  defineEventHandler((event) => {
    const q = getQuery<{ code?: string; state?: string }>(event);
    return `Callback received. code=${q.code ?? "<none>"} state=${q.state ?? "<none>"}`;
  }),
);

router.get(
  "/authorize",
  defineEventHandler(async (event) => {
    return provider.authorize(event, async (input, validateRedirectUri) => {
      const redirect_uri = validateRedirectUri(input.redirect_uri, [
        "http://localhost:3000/callback",     // The client must request one of these redirect URIs
        "http://localhost:3000/alt-callback",
      ]);

      return {
        subject: "user-123", // in a real app, you'd determine this from the user's session
        redirect_uri,
      };
    });
  }),
);

router.post(
  "/token",
  defineEventHandler(async (event) => {
    return provider.token(event);
  }),
);

router.get(
  "/userinfo",
  defineEventHandler(async (event) => {
    return provider.userInfo(event);
  }),
);
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

## Credits

- Thanks to [Vidbase, Inc.](https://github.com/vidbase) (in particular to [Van Nguyen](https://github.com/thegoleffect)) for the npm package name donation

## License

<!-- automd:contributors license=MIT -->

Published under the [MIT](https://github.com/sandros94/unauth/blob/main/LICENSE) license.
Made by [community](https://github.com/sandros94/unauth/graphs/contributors) 💛
<br><br>
<a href="https://github.com/sandros94/unauth/graphs/contributors">
<img src="https://contrib.rocks/image?repo=sandros94/unauth" />
</a>

<!-- /automd -->

<!-- automd:with-automd -->

---

_🤖 auto updated with [automd](https://automd.unjs.io)_

<!-- /automd -->
