<!-- ⚠️  MAINTENANCE NOTICE
  This file is the **single source of truth** for any AI agent working on
  this project. It MUST be kept up-to-date whenever the project structure,
  conventions, or tooling change. If you change something in the codebase
  that invalidates information here, update this file in the same PR.
  Plans and design notes live in the agent's own memory, not in the repo. -->

## Core Principle — Ask First

**When in doubt, ask before acting.** It is always more important to understand the vision and the request than to assume. There is no shame or wasted time in asking clarifying questions — this applies to every conversation and every task in this project.

## First-time Setup for Development

- Run `pnpm install` to install dependencies.
- Run `pnpm dev:prepare` to stub the library and prepare type support.

## Key Scripts

- `pnpm dev:prepare` — stubs the library build and installs the `simple-git-hooks` pre-commit hook (stub + lint + typecheck).
- `pnpm dev` — starts the playground with a dev server.
- `pnpm prepack` — builds the library for publishing.
- `pnpm lint` — lint the codebase.
- `pnpm fmt` — automatically fix lint issues.
- `pnpm test` — run all tests.
- `pnpm test:coverage` — run tests with coverage reporting.
- `pnpm typecheck` — type-check the library and its tests.
- `pnpm typecheck:playgrounds` — type-check the three playgrounds (h3 and nitro with the root TypeScript, nuxt with its own `nuxt typecheck`).

Each script is independent — `test` does **not** run lint or type-check. **Always run** `pnpm fmt` and `pnpm typecheck` after making changes. After adding or renaming a Nuxt server util, run `pnpm dev:prepare` (it runs `nuxt prepare`) before `pnpm lint`, or the type-aware lint cannot see the auto-import.

## Repository Structure

- `.github/` — GitHub configuration (funding, workflows).
- `src/` — Library source code.
- `test/` — Tests (unit, nuxt environment, e2e).
- `playground/` — App for manual testing and development of the library.
- `docs/` — Documentation site (planned, not started: the API still shifts).

## Testing Strategy

- `pnpm test` — Run all vitest tests.
- `pnpm test:coverage` — Run tests with coverage reporting.
- `pnpm typecheck` — Type-check only.

## Development Workflow

### Making Changes

1. Make changes in `src/`.
2. Run `pnpm fmt`.
3. Run `pnpm typecheck`.
4. Run `pnpm test`.

## Contribution Principles

- Prefer **minimal, targeted changes** over large refactors.
- Be mindful of **bundle size** — this is a library shipped to users. Check build output with `pnpm prepack`.
- Never modify files outside the scope of the requested change.

## Common Gotchas

- **Don't use runtime-specific APIs** — Library runtime code may run in multiple runtimes (Node, Deno, Bun, workers, edge).
- **Bundle size matters** — Every dependency added to `dependencies` impacts consuming apps.

## Error & Logging Guidelines

- Prefer explicit errors over silent failures.
- Use warnings for recoverable situations; throw for invalid states.
- Include actionable context in error messages.
- Errors are structured content for downstream application logic: a stable `code`, a `cause` whose shape `UnauthErrorCauseMap` declares (what a UI translates), and a `status` hint. The message is for logs, never the only carrier of meaning.

## Documentation Requirements

- Update types and JSDoc for API changes.

## Code Conventions

- Use **ESM** and modern JavaScript.
- Avoid barrel files (`index.ts` re-exports); import directly from specific modules.
- Place non-exported/internal helpers at the end of the file.
- For multi-arg functions, use an options object as the second parameter.
- Split logic across files; avoid long single-file modules (>200 LoC). Use `_*` prefix for internal files.
- Prefer **Web APIs** over Node.js APIs where possible.
- Do not add comments explaining what the line does unless prompted.
- Before adding new code, study surrounding patterns, naming conventions, and architectural decisions.
- Use existing UnJS utilities and dependencies before adding new packages.
- Keep runtime code minimal and fast.

## Commit Conventions

- Use **semantic commit messages**, lower-case (e.g., `fix(runtime): resolve svg render issue`).
- Prefer to include scope (e.g., `feat(runtime):`, `fix(composables):`, `docs:`, `test:`).
- Add a short description in a new line when helpful.
