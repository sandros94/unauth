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
- OAuthProvider: Focused OAuth 2.1 utilities (authorization code, refresh token, client credentials, token introspection, discovery). Useful for advanced/custom scenarios where you don't want OIDC.

Both providers are unopinionated and framework-agnostic. You wire them into your HTTP handlers and provide your own storage/auth checks via small callbacks.

### Quick start (OIDC)

### Quick start (OAuth only)

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
