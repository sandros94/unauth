# Changelog

## v0.0.5

[compare changes](https://github.com/sandros94/unauth/compare/v0.0.4...v0.0.5)

### 🚀 Enhancements

- **h3:** Global hooks ([aa39f0a](https://github.com/sandros94/unauth/commit/aa39f0a))
- **h3:** Simplified sub-router creation ([fb06187](https://github.com/sandros94/unauth/commit/fb06187))

### 🩹 Fixes

- **adapter:** Use object create ([5b78361](https://github.com/sandros94/unauth/commit/5b78361))
- Discovery utility ([aa8b53d](https://github.com/sandros94/unauth/commit/aa8b53d))
- **oauth:** Force `redirect_uri` missing check ([b4a1d0b](https://github.com/sandros94/unauth/commit/b4a1d0b))
- **h3:** Error handling ([dcd54fc](https://github.com/sandros94/unauth/commit/dcd54fc))
- **h3:** Standardize exports ([2644a0e](https://github.com/sandros94/unauth/commit/2644a0e))
- Issuer and discovery document propagation ([7f627db](https://github.com/sandros94/unauth/commit/7f627db))

### 📖 Documentation

- Update h3 example ([5d68080](https://github.com/sandros94/unauth/commit/5d68080))

### 🏡 Chore

- Update deps ([ec481fa](https://github.com/sandros94/unauth/commit/ec481fa))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.4

[compare changes](https://github.com/sandros94/unauth/compare/v0.0.3...v0.0.4)

### 🩹 Fixes

- **h3:** Store tokens in cookies by default ([fdb3741](https://github.com/sandros94/unauth/commit/fdb3741))

### 📖 Documentation

- Support `generateJWK` example ([39c1a6a](https://github.com/sandros94/unauth/commit/39c1a6a))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.3

[compare changes](https://github.com/sandros94/unauth/compare/v0.0.2...v0.0.3)

### 🩹 Fixes

- Simplify token grant utility ([65979d0](https://github.com/sandros94/unauth/commit/65979d0))

### 📖 Documentation

- Basic use ([582a95e](https://github.com/sandros94/unauth/commit/582a95e))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.2

### 🚀 Enhancements

- **oauth:** Implement `authorize` utils ([1c52f48](https://github.com/sandros94/unauth/commit/1c52f48))
- **oidc:** Initial implementation ([7d098de](https://github.com/sandros94/unauth/commit/7d098de))
- Initial class implementation for providers ([1bbc0c2](https://github.com/sandros94/unauth/commit/1bbc0c2))
- Add resource indicators support per RFC 8707 ([7954ec7](https://github.com/sandros94/unauth/commit/7954ec7))
- Add `generateJwk` utility ([327f7be](https://github.com/sandros94/unauth/commit/327f7be))
- Re-export `importJWKFromPEM` ([477e200](https://github.com/sandros94/unauth/commit/477e200))
- **OAuth:** Error class ([661fc15](https://github.com/sandros94/unauth/commit/661fc15))
- **oauth:** Token introspection utils ([89b07c8](https://github.com/sandros94/unauth/commit/89b07c8))
- **oidc:** Provider options ([a422241](https://github.com/sandros94/unauth/commit/a422241))
- Basic class providers ([b90aaed](https://github.com/sandros94/unauth/commit/b90aaed))
- **adapters:** New h3 adapter ([ca6a53a](https://github.com/sandros94/unauth/commit/ca6a53a))

### 🩹 Fixes

- **oauth:** Improve `token` utils based on spec ([fe6e56d](https://github.com/sandros94/unauth/commit/fe6e56d))
- Always dedupe `normalizeScope` ([d9bb368](https://github.com/sandros94/unauth/commit/d9bb368))
- Extra claims in auth code jwe ([d38d9e6](https://github.com/sandros94/unauth/commit/d38d9e6))
- **oidc:** Non-required options ([2dc053e](https://github.com/sandros94/unauth/commit/2dc053e))
- **oidc:** BuildUserInfo non-standard claims support and prevent prototype pollution ([ef98170](https://github.com/sandros94/unauth/commit/ef98170))
- Various fixes ([b326214](https://github.com/sandros94/unauth/commit/b326214))
- Various fixes ([3b94094](https://github.com/sandros94/unauth/commit/3b94094))
- Always check for `client_id`, `typ` and `maxTokenAge` ([ceefb72](https://github.com/sandros94/unauth/commit/ceefb72))
- Also return iat and exp in token revocation ([03e5bef](https://github.com/sandros94/unauth/commit/03e5bef))
- Code challange method and default maxTokenAge ([c4de587](https://github.com/sandros94/unauth/commit/c4de587))
- Intentionally default to `typ: "at+jwt"` ([d5ef465](https://github.com/sandros94/unauth/commit/d5ef465))
- Missing OIDCProvider implementation ([719bc4f](https://github.com/sandros94/unauth/commit/719bc4f))
- Streamline OIDC key management and prevent duplicates in JWKS ([b42041e](https://github.com/sandros94/unauth/commit/b42041e))
- **oidc:** Missing buildUserInfo method ([a5831fc](https://github.com/sandros94/unauth/commit/a5831fc))
- Remove introspect utility ([c75542f](https://github.com/sandros94/unauth/commit/c75542f))
- Don't alter alg casing ([4f74923](https://github.com/sandros94/unauth/commit/4f74923))
- Use default values for discovery documents ([7d7a1c0](https://github.com/sandros94/unauth/commit/7d7a1c0))
- Introspection fallback ([b64b19a](https://github.com/sandros94/unauth/commit/b64b19a))
- **oauth:** Hook options ([8a3204d](https://github.com/sandros94/unauth/commit/8a3204d))
- **oauth:** Simplify introspect utils options ([31772ca](https://github.com/sandros94/unauth/commit/31772ca))
- **oauth:** Authorize utils explicitly picking up active keys ([be8fb6f](https://github.com/sandros94/unauth/commit/be8fb6f))
- **oauth:** Fallback to privateKey available in options ([ec5503e](https://github.com/sandros94/unauth/commit/ec5503e))
- **oauth:** Hooks ([e6287b7](https://github.com/sandros94/unauth/commit/e6287b7))
- **oauth:** Default population of `currentDate` ([38c0c24](https://github.com/sandros94/unauth/commit/38c0c24))
- **oauth:** Remove unused getters ([5e78645](https://github.com/sandros94/unauth/commit/5e78645))
- Missing resource for client credentials ([3dead70](https://github.com/sandros94/unauth/commit/3dead70))
- Build ([0e9025d](https://github.com/sandros94/unauth/commit/0e9025d))
- Add public keys for access and id tokens ([76ff9f6](https://github.com/sandros94/unauth/commit/76ff9f6))
- **oauth:** `currentDate` propagation ([54f1c41](https://github.com/sandros94/unauth/commit/54f1c41))
- **oidc:** `currentDate` propagation ([5f54940](https://github.com/sandros94/unauth/commit/5f54940))
- **oauth:** Types and default options ([de2281b](https://github.com/sandros94/unauth/commit/de2281b))
- **oidc:** Token validation ([d4147c4](https://github.com/sandros94/unauth/commit/d4147c4))
- Provider api ([32fe09b](https://github.com/sandros94/unauth/commit/32fe09b))
- Providers token introspection for ac and rt ([ed09e02](https://github.com/sandros94/unauth/commit/ed09e02))
- Ac and rt validation ([0084a24](https://github.com/sandros94/unauth/commit/0084a24))
- **oidc:** Mark nonce as optional, since OAuth 2.1 already mitigates CSRF ([a47a330](https://github.com/sandros94/unauth/commit/a47a330))
- Only return payload from introspections ([0e7aed3](https://github.com/sandros94/unauth/commit/0e7aed3))
- Token endpoint utils ([fd3f444](https://github.com/sandros94/unauth/commit/fd3f444))
- Make redirect_uri optional in authorization request ([1d69280](https://github.com/sandros94/unauth/commit/1d69280))
- **h3:** Discovery document not working ([00e06e5](https://github.com/sandros94/unauth/commit/00e06e5))

### 💅 Refactors

- Code structure ([bb8612c](https://github.com/sandros94/unauth/commit/bb8612c))
- **oauth:** Centralize default values ([eb29076](https://github.com/sandros94/unauth/commit/eb29076))
- Discovery utilities ([85878c3](https://github.com/sandros94/unauth/commit/85878c3))
- Project structure ([4ce4877](https://github.com/sandros94/unauth/commit/4ce4877))
- AuthorizationCode ([652f34e](https://github.com/sandros94/unauth/commit/652f34e))
- **oauth:** Error class and authorize utils ([bb31844](https://github.com/sandros94/unauth/commit/bb31844))
- **oauth:** Token utils implementation ([03540dd](https://github.com/sandros94/unauth/commit/03540dd))
- **oauth:** Provider implementation ([b12ad9e](https://github.com/sandros94/unauth/commit/b12ad9e))
- Oidc implementation ([59e4820](https://github.com/sandros94/unauth/commit/59e4820))
- Utility only oauth provider ([e116c9d](https://github.com/sandros94/unauth/commit/e116c9d))
- Oidc provider ([2185850](https://github.com/sandros94/unauth/commit/2185850))
- Authorize error handling ([69c4cd2](https://github.com/sandros94/unauth/commit/69c4cd2))
- **token:** Error handling ([77c4a39](https://github.com/sandros94/unauth/commit/77c4a39))
- Simplify providers api ([02a6fdc](https://github.com/sandros94/unauth/commit/02a6fdc))
- Authorize and token flows ([7398397](https://github.com/sandros94/unauth/commit/7398397))
- Provider classes ([6da88ee](https://github.com/sandros94/unauth/commit/6da88ee))
- Project structure ([c6b6b6e](https://github.com/sandros94/unauth/commit/c6b6b6e))

### 📖 Documentation

- Init ([3f6a208](https://github.com/sandros94/unauth/commit/3f6a208))
- Fix `generateJwk` example ([1519197](https://github.com/sandros94/unauth/commit/1519197))
- Fix missing jwks ([cc04dd7](https://github.com/sandros94/unauth/commit/cc04dd7))

### 🏡 Chore

- Init ([ef50dfc](https://github.com/sandros94/unauth/commit/ef50dfc))
- Update `unjwt` dep ([f4cc418](https://github.com/sandros94/unauth/commit/f4cc418))
- Init oauth token endpoint utils ([3848d8a](https://github.com/sandros94/unauth/commit/3848d8a))
- Add vscode tasks ([cda0123](https://github.com/sandros94/unauth/commit/cda0123))
- Update deps ([e26ab8d](https://github.com/sandros94/unauth/commit/e26ab8d))
- Update `unjwt` ([7a24ab0](https://github.com/sandros94/unauth/commit/7a24ab0))
- Change project name ([4ee5a38](https://github.com/sandros94/unauth/commit/4ee5a38))
- Fix pnpm-lock file ([3b4be93](https://github.com/sandros94/unauth/commit/3b4be93))
- Set ignore builds ([618381b](https://github.com/sandros94/unauth/commit/618381b))
- Add sub-entries ([ab31a64](https://github.com/sandros94/unauth/commit/ab31a64))
- Update playground ([a07b23c](https://github.com/sandros94/unauth/commit/a07b23c))
- Playground fix id_token key and error logging ([104e2ea](https://github.com/sandros94/unauth/commit/104e2ea))
- **playground:** Basic openid-client manual tests ([019f164](https://github.com/sandros94/unauth/commit/019f164))
- Update deps ([bc3039b](https://github.com/sandros94/unauth/commit/bc3039b))
- Update deps and fix `typ` ([eea3fdd](https://github.com/sandros94/unauth/commit/eea3fdd))
- Update deps ([bb5483c](https://github.com/sandros94/unauth/commit/bb5483c))
- Update deps ([0289d09](https://github.com/sandros94/unauth/commit/0289d09))
- Add h3 peerDep ([43afebd](https://github.com/sandros94/unauth/commit/43afebd))

### ✅ Tests

- Init oauth utils ([22c4f0d](https://github.com/sandros94/unauth/commit/22c4f0d))
- Rename file ([accd21d](https://github.com/sandros94/unauth/commit/accd21d))
- Init tests for main implementation ([e0604a9](https://github.com/sandros94/unauth/commit/e0604a9))
- **oauth:** OAuthProvider class ([5b20884](https://github.com/sandros94/unauth/commit/5b20884))
- Init ([6623f8a](https://github.com/sandros94/unauth/commit/6623f8a))
- Explicit throw message check ([ea42a96](https://github.com/sandros94/unauth/commit/ea42a96))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))
- Sandros94 ([@sandros94](https://github.com/sandros94))
