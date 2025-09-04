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
import { OAuthProvider, OIDCProvider } from "unauth";
```

**CDN** (Deno, Bun and Browsers)

```js
// Main functions
import { OAuthProvider, OIDCProvider } from "https://esm.sh/unauth";
```

### Providers overview

- OIDCProvider: Full OpenID Connect on top of OAuth 2.1. Use this if you need ID Tokens, OpenID discovery, and a complete OIDC-compliant flow. Using OIDCProvider alone gives you full control over both OIDC and OAuth.
- OAuthProvider: Focused OAuth 2.1 utilities (authorization code, refresh token, client credentials, token introspection/revocation, discovery). Useful for advanced/custom scenarios where you don't want OIDC.

Both providers are unopinionated and framework-agnostic. You wire them into your HTTP handlers and provide your own storage/auth checks via small callbacks.

### Quick start (OIDC)

```ts
import { OIDCProvider, generateJwk } from "unauth";

// Minimal JWK generation. In production, load from secure storage and rotate.
const [accessKey, idKey] = await Promise.all([
  generateJwk("Ed25519", { params: { kid: "at-1" } }),
  generateJwk("Ed25519", { params: { kid: "id-1" } }),
]);
const refreshKey = "a-strong-secret"; // can also be a JWK

const oidc = new OIDCProvider({
  issuer: "https://auth.example.com",
  accessToken: { privateKey: accessKey.privateKey },
  refreshToken: { privateKey: refreshKey },
  idToken: { privateKey: idKey.privateKey },
  defaultScope: "openid profile email",
  availableScopes: ["openid", "profile", "email"],
  jwks: [accessKey.publicKey, idKey.publicKey],
});

// 1) Authorization endpoint (PKCE required)
//    - Validate the request and build an authorization code (JWE)
//    - Provide user context in the callback (at least `sub`)
async function authorizeHandler(req) {
  const result = await oidc.authorize(req.query, async (_req) => ({
    sub: "user-123", // the authenticated user id
  }));

  // Redirect user-agent back to client with ?code=...
  const redirect = oidc.buildAuthorizeRedirect(req.query.redirect_uri, result, {
    iss: oidc.issuer,
  });

  return { status: 302, headers: { Location: redirect.toString() } };
}

// 2) Token endpoint (authorization_code)
async function tokenAuthorizationCodeHandler(body) {
  const tokens = await oidc.tokenAuthorizationCode(body, async (_claims) => ({
    accessTokenClaims: { aud: body.resource || "api://default" },
    refreshTokenClaims: {},
    onCodeUsed: async (jti) => {
      // Mark this authorization code as used in your DB (optional)
    },
  }));

  // Optional: build an ID Token for OIDC flows
  const id_token = await oidc.buildIdToken({
    subject: "user-123",
    audience: body.client_id,
    nonce: body.nonce,
    access_token: tokens.access_token, // enables at_hash
  });

  return { status: 200, json: { ...tokens, id_token } };
}

// 3) Token endpoint (client_credentials)
async function tokenClientCredentialsHandler(body) {
  const tokens = await oidc.tokenClientCredentials(body, async (opts) => ({
    // Authenticate your client here (client_id/secret, mTLS, etc.)
    aud: body.aud || body.resource || "api://default",
    scope: body.scope || opts.defaultScope,
  }));

  return { status: 200, json: tokens };
}

// 4) Token endpoint (refresh_token)
async function tokenRefreshHandler(body) {
  const tokens = await oidc.tokenRefreshToken(body, async (_claims) => ({
    accessTokenClaims: {},
    refreshTokenClaims: {},
    onRefreshUsed: async (jti) => {
      // Invalidate old refresh token jti in your DB (optional)
    },
  }));

  return { status: 200, json: tokens };
}

// 5) Introspection (verify tokens)
async function introspectHandler(token) {
  const at = await oidc.introspectAccessToken(token);
  const rt = await oidc.introspectRefreshToken(token);
  const id = await oidc.introspectIdToken(token);

  return { at, rt, id };
}

// 6) Discovery and JWKS endpoints
//    - Serve these at standard paths:
//      /.well-known/openid-configuration
//      /.well-known/jwks.json
const openidConfiguration = oidc.getDiscoveryDocument({
  authorization_endpoint: "https://auth.example.com/authorize",
  token_endpoint: "https://auth.example.com/token",
  userinfo_endpoint: "https://auth.example.com/userinfo",
});
const jwks = oidc.getPublicJwks(); // { keys: [...] }
```

### Quick start (OAuth only)

```ts
import { OAuthProvider } from "unauth";

const oauth = new OAuthProvider({
  issuer: "https://auth.example.com",
  accessToken: {
    privateKey: {
      /* JWK */
    },
  },
  refreshToken: { privateKey: "a-strong-secret" },
  defaultScope: "basic",
  availableScopes: ["basic", "admin"],
});

// Authorization code
await oauth.authorize(req.query, async () => ({ sub: "user-123" }));

// Token: client_credentials
await oauth.tokenClientCredentials(body, async (opts) => ({
  // Authenticate client and provide claims
  aud: body.aud || "api://default",
  scope: body.scope || opts.defaultScope,
}));

// Token: authorization_code
await oauth.tokenAuthorizationCode(body, async (claims) => ({
  accessTokenClaims: { aud: body.resource || claims.resource },
  refreshTokenClaims: {},
}));

// Token: refresh_token
await oauth.tokenRefreshToken(body, async (claims) => ({
  accessTokenClaims: { aud: body.resource || claims.resource },
  refreshTokenClaims: {},
}));

// Introspection
await oauth.introspectAccessToken("at.jwt");
await oauth.introspectRefreshToken("rt.jwe");

// Discovery
const oauthConfig = oauth.getDiscoveryDocument({
  authorization_endpoint: "https://auth.example.com/authorize",
  token_endpoint: "https://auth.example.com/token",
});
```

Notes

- PKCE is enforced for authorization_code.
- You decide how to authenticate clients and users in the callbacks.
- Use setJwks/rotateAccessKey/rotateRefreshKey/rotateIDKey for key rotation; serve getPublicJwks() publicly.
- For beginners, start with OIDCProvider. For advanced/custom needs (no ID Tokens), OAuthProvider alone is enough.

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
