# unauth/z examples

Reference platforms built on `unauth/z` the way a downstream application builds them, each as an H3 application over `node:sqlite`. This is not a test suite for the engine: that lives in `test/z` and in `src/z/conformance`.

## Layout

- `application/`: the wiring every platform shares: the database on the request, the session, sign-in, the guard, the checks before a write. The application decides in `session.ts`, where grants leave the session: grants holding a preset that is no longer the catalog's, or refused for another catalog, are issued again with the function the platform hands to `createApp`, and saved in the session.
- `storage/`: the tables every platform keeps and the SQL over them. `statements.ts` reads what a question or an issue of grants needs, in one query. `ask.ts` answers a question inside SQL.
- `platforms/<name>/`: one platform. Its catalog (`authz.ts`), its own tables and rules, its routes, its seed data, and `walkthrough.ts`, which calls the application and asserts the responses the platform documents.
- `platforms/client.ts`: how a walkthrough calls an application.
- `platforms/check.ts`: how a walkthrough checks that the SQL answers every question as `ask` does.

Platforms: `github`, `wordpress`, and `appendix-a1`, case A.1 of the model's Appendix A.

## Run

From the repository root, after `pnpm dev:prepare`:

```sh
pnpm exec vitest run --config spec/examples/vitest.config.ts
pnpm exec tsc -p spec/examples/tsconfig.json
```
