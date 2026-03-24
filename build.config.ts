import { defineBuildConfig } from "obuild/config";
import { replacePlugin } from "rolldown/plugins";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: ["./src/index.ts", "./src/h3v2.ts"],
      rolldown: {
        platform: "neutral",
        external: ["h3v1", "cookie-esv1", "h3v2", "cookie-esv2", "h3"],
        plugins: [
          replacePlugin(
            {
              '"h3v1': '"h3',
              '"h3v2': '"h3',
              "cookie-esv1": "cookie-es",
              "cookie-esv2": "cookie-es",
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
