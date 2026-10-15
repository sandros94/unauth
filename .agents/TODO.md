# TODO

Current and next steps for project-specific implementations. Remove completed items once they are committed — no need to track history here.

- **`onReadAccess` with a missing refresh cookie** — the hook fires whenever the access token is valid (it must: a stripped RT cookie cannot bypass revocation checks), but the `refresh` snapshot type promises an `id: string` that is `undefined` in that case. Decide the contract (`refresh?: SessionSnapshot`, a dedicated flag, or a separate hook) and drop the `oxlint-disable` in both `token-pair.ts` adapters.
- **Migrate to unjwt 0.8** — sessions change contract (`typ: "session+jwt"`, `exp` in data no longer sets lifetime, string keys refused, `rolling` option). Follow `unjwt/docs/0.getting-started/4.migration/1.to-0.8.md`; the `patches/unjwt@*.patch` test alias only needs regenerating per version.
