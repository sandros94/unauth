import { defineBuildConfig } from "obuild/config";

/** One entry per provider preset (`unauth/n/providers/<id>`), so an app bundles only the ones it imports. */
const PROVIDERS = [
  "apple",
  "atproto",
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
 * A single bundle for every public entry, so rolldown splits what they share into `dist/_chunks/`
 * once instead of inlining a copy per entry. `dependencies` and `peerDependencies` are external
 * by default.
 */
export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: ["./src/n/index.ts", ...PROVIDERS.map((id) => `./src/n/providers/${id}.ts`)],
      rolldown: { platform: "neutral" },
    },
  ],
});
