# unauth

<!-- automd:badges bundlephobia style="flat" color="FFDC3B" -->

[![npm version](https://img.shields.io/npm/v/unauth?color=FFDC3B)](https://npmjs.com/package/unauth)
[![npm downloads](https://img.shields.io/npm/dm/unauth?color=FFDC3B)](https://npm.chart.dev/unauth)
[![bundle size](https://img.shields.io/bundlephobia/minzip/unauth?color=FFDC3B)](https://bundlephobia.com/package/unauth)

<!-- /automd -->

A collection of low-level and high-level, server-agnostic, Authentication and Authorization utilities.

> [!WARNING]
> This package is in active development. It is not recommended for production use yet unless you are willing to help with testing and feedback.
> Expect breaking changes, as I prioritize usability and correctness over stability at this stage.

## Features

-

Built on top of minimal dependencies:

- [`unjwt`](https://github.com/sandros94/unjwt)
- [`unsecure`](https://github.com/sandros94/unsecure)

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
import {} from "unauth";
```

**CDN** (Deno, Bun and Browsers)

```js
// Main functions
import {} from "https://esm.sh/unauth";
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

I started by building `unjwt`, as I needed a cryptographically secure way to transmit sensitive information between various programming languages and servers. Not long after I started requiring some standardization, in particular on how to prepare and expect authorization data to be shared between parties (client and servers), but as I was testing various libraries I've never been satisfied by their DX (although most of them were great for someone that already knows the topic).
So I started building `unauth` as a collection of low-level primitives that then can be wrapped in higher-level abstractions, via adapters, to provide a "batteries included" experience while retaining control and flexibility of using your preferred storage, database and web frameworks.

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
