import { fileURLToPath } from "node:url";
import { configDefaults, defineConfig, type TestProjectInlineConfiguration } from "vitest/config";

/**
 * Each `test/env-<name>/` is a private workspace package installing one framework world (for h3:
 * `h3`, `cookie-es` and an `unjwt` whose peers resolve to that h3 major). Its vitest project
 * resolves those packages from there instead of the root, so source and tests import them by their
 * real names and still get the exact tree a consumer on that major would.
 *
 * Suites bound to an env live under `test/**\/<name>/`; everything else is framework-agnostic.
 */
const ENVS = ["h3v1", "h3v2"];
const ENV_PACKAGES = /^(h3|cookie-es|unjwt)(\/|$)/;

export default defineConfig({
  test: {
    slowTestThreshold: 1000,
    coverage: {
      include: ["src/**/*.ts"],
    },
    projects: [
      {
        test: {
          name: "base",
          include: ["test/**/*.test.ts"],
          exclude: [...configDefaults.exclude, ...ENVS.map((env) => `test/**/${env}/**`)],
        },
      },
      ...ENVS.map((env) => envProject(env)),
    ],
  },
});

function envProject(env: string): TestProjectInlineConfiguration {
  const pkg = fileURLToPath(new URL(`./test/env-${env}/package.json`, import.meta.url));

  return {
    plugins: [
      {
        name: `unauth:env-${env}`,
        enforce: "pre",
        resolveId(source, _importer, options) {
          if (!ENV_PACKAGES.test(source)) return null;
          // Resolve as if imported from the env package, so Node walks its node_modules.
          return this.resolve(source, pkg, { ...options, skipSelf: true });
        },
      },
    ],
    test: {
      name: env,
      include: [`test/**/${env}/**/*.test.ts`],
    },
  };
}
