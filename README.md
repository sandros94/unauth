# unauth

<!-- automd:badges bundlephobia style="flat" color="FFDC3B" -->

[![npm version](https://img.shields.io/npm/v/unauth?color=FFDC3B)](https://npmjs.com/package/unauth)
[![npm downloads](https://img.shields.io/npm/dm/unauth?color=FFDC3B)](https://npm.chart.dev/unauth)
[![bundle size](https://img.shields.io/bundlephobia/minzip/unauth?color=FFDC3B)](https://bundlephobia.com/package/unauth)

<!-- /automd -->

A collection of low-level, and high-level server-agnostic, OAuth 2.1 and OpenID Connect utilities based on JWT ([`unjwt`](https://github.com/sandros94/unjwt)). Adapters for popular frameworks are available.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback.
> Expect breaking changes, as I prioritize usability and correctness over stability at this stage.

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
import { generateJWK } from "unauth/utils";

// Configure the provider once during startup.
const [atJwk, idJwk] = await Promise.all([
  generateJWK("RS256", { kid: "at-rsa-1" }),
  generateJWK("RS256", { kid: "id-rsa-1" }),
]);
const oidc = useOIDCProvider({
  issuer: "https://auth.example.com",
  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: atJwk,
  idTokenOptions: idJwk,
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
import { generateJWK } from "unauth/utils";

// Configure the provider once during startup.
const atJwk = await generateJWK("RS256", { kid: "at-rsa-1" });
const oauth = useOAuthProvider({
  issuer: "https://auth.example.com",
  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: atJwk,
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

> [!NOTE]
> For advanced use-cases you can import the lower-level helpers directly, e.g. `import { issueAuthorizationCode } from "unauth/oauth"` or `import { buildUserInfo } from "unauth/oidc"`, to compose custom flows while keeping the same core primitives.

### Adapters

- **H3 v1**: For use with [H3 v1](https://v1.h3.dev)

#### Minimal H3 v1 Example

In the following example instead of using `useOIDCProvider` or `useOAuthProvider`, we use `createOIDCRouter` (or `createOAuthRouter`) which creates an H3 router with all the necessary endpoints that can be mounted as a sub-app. We also provide an `authorize` hook to validate the client and redirect URI.

```ts
import {
  createApp,
  createRouter,
  defineEventHandler,
  getQuery,
  useBase,
} from "h3";
import { createOIDCRouter, validateRedirectUri } from "unauth/h3/oidc";
import { generateJWK } from "unauth";

const [atJwk, idJwk] = await Promise.all([
  generateJWK("RS256", { kid: "at-rsa-1" }),
  generateJWK("RS256", { kid: "id-rsa-1" }),
]);

// If the first argument is a string, it will return a handler with a base
const oidcRouter = createOIDCRouter({
  issuer: "http://localhost:3000",
  discovery: {
    // the base path where the OIDC endpoints will be served
    // (e.g. /oidc/v1/.well-known/openid-configuration)
    base: "/oidc/v1",
    // you can also override individual endpoints here, e.g.:
    // authorization_endpoint: "/oidc/v1/authorize",
  },

  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: atJwk, // we can directly pass keys and use default options
  idTokenOptions: idJwk, // same as accessTokenOptions

  // Hook that is called when the /authorize endpoint is hit
  authorize: async (input) => {
    // in a real app, you'd look up the client_id and allowed redirect URIs in your database
    if (input.client_id !== "test-client") {
      return {
        error: "invalid_client",
        error_description: "Unknown client",
      };
    }
    const validRedirectUri = validateRedirectUri(input.redirect_uri, [
      "http://localhost:3000/callback", // this is the one requested
      "http://localhost:3000/alt-callback",
    ]);
    if (!validRedirectUri.success) {
      return validRedirectUri.error;
    }

    // in a real app, you'd determine this from the user's login session
    const subject = "user-123";

    return {
      subject,
      redirect_uri: validRedirectUri.value,
    };
  },
});

// Create an H3 app instance
export const app = createApp();
const router = createRouter();

// Simple callback endpoint for manual testing; used by the scripted test (which intercepts the Location header)
router.get(
  "/callback",
  defineEventHandler((event) => {
    const q = getQuery<{ code?: string; state?: string }>(event);
    return `Callback received. code=${q.code ?? "<none>"} state=${q.state ?? "<none>"}`;
  }),
);

// Use the same base as used in `createOIDCRouter`
router.use("/oidc/v1/**", useBase("/oidc/v1", oidcRouter.handler));

app.use(router);
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
