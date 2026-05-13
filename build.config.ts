import { defineBuildConfig } from "obuild/config";
import { replacePlugin } from "rolldown/plugins";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: ["./src/base/h3v1/index.ts", "./src/base/h3v2/index.ts"],
      rolldown: {
        platform: "neutral",
        external: ["h3v1", "h3v2", "cookie-esv1", "cookie-esv3", "unjwt", "unsecure"],
        plugins: [
          replacePlugin(
            {
              '"h3v1"': '"h3"',
              '"h3v2"': '"h3"',
              '"cookie-esv1"': '"cookie-es"',
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
