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

const grant = await oidc.issueAuthorizationCodeGrant({
	...normalized.value,
	subject: "user-123",
});
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

const grant = await oauth.issueAuthorizationCodeGrant({
	...validation.value,
	subject: "client-123",
});
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

- **H3**: For use with [H3](https://h3.dev)

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
