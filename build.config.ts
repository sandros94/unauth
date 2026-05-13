import { defineBuildConfig } from "obuild/config";
import { replacePlugin } from "rolldown/plugins";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: ["./src/base/h3v1/index.ts"],
      rolldown: {
        platform: "neutral" as const,
        external: ["h3v1", "cookie-esv1", "unjwt", "unsecure"],
        plugins: [
          replacePlugin(
            {
              '"h3v1"': '"h3"',
              '"cookie-esv1"': '"cookie-es"',
            },
            {
              delimiters: ["", ""],
            },
          ),
        ],
      },
    },
    {
      type: "bundle",
      input: ["./src/base/h3v2/index.ts"],
      rolldown: {
        platform: "neutral" as const,
        external: ["h3v2", "cookie-esv3", "unjwt", "unsecure"],
        plugins: [
          replacePlugin(
            {
              '"h3v2"': '"h3"',
              '"cookie-esv3"': '"cookie-es"',
            },
            {
              delimiters: ["", ""],
            },
          ),
        ],
      },
    },
  ],
});
