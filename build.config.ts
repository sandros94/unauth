import { defineBuildConfig } from "obuild/config";

/** One entry per provider preset (`unauth/n/providers/<id>`), so an app bundles only the ones it imports. */
const PROVIDERS = [
  "apple",
  "discord",
  "facebook",
  "github",
  "gitlab",
  "google",
  "linkedin",
  "microsoft",
  "twitch",
  "x",
];

/**
 * A single bundle for every public entry, so rolldown splits what they share (`src/**\/_internal/**`)
 * into `dist/_chunks/` once instead of inlining a copy per entry. `dependencies` and
 * `peerDependencies` are external by default. Declarations come from isolated declarations (see
 * `tsconfig.base.json`), which never resolve `h3`, so one build serves both h3 majors.
 */
export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/n/index.ts",
        "./src/n/h3v1/index.ts",
        "./src/n/h3v2/index.ts",
        ...PROVIDERS.map((id) => `./src/n/providers/${id}.ts`),
      ],
      dts: { tsconfig: "./tsconfig.base.json" },
      rolldown: { platform: "neutral" },
    },
  ],
});
