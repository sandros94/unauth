import { defineBuildConfig } from "obuild/config";

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
      input: ["./src/base/h3v1/index.ts", "./src/base/h3v2/index.ts"],
      dts: { tsconfig: "./tsconfig.base.json" },
      rolldown: { platform: "neutral" },
    },
  ],
});
