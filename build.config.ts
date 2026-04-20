import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: ["./src/base/h3/index.ts"],
      rolldown: {
        platform: "neutral",
      },
    },
  ],
});
