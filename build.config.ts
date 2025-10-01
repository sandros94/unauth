import { defineBuildConfig } from "unbuild";
import { readdir, rm } from "node:fs/promises";
import { join } from "node:path";

export default defineBuildConfig({
  entries: [
    "./src/index",
    {
      input: "./src/core/oauth",
      outDir: "./dist/oauth",
      name: "oauth",
    },
    {
      input: "./src/core/oidc",
      outDir: "./dist/oidc",
      name: "oidc",
    },
    {
      input: "./src/utils",
      outDir: "./dist/utils",
      name: "utils",
    },
    {
      input: "./src/adapters/h3",
      outDir: "./dist/h3",
      name: "h3",
    },
    {
      input: "./src/adapters/h3/oauth",
      outDir: "./dist/h3/oauth",
      name: "h3/oauth",
    },
    {
      input: "./src/adapters/h3/oidc",
      outDir: "./dist/h3/oidc",
      name: "h3/oidc",
    },
  ],
  declaration: true,
  hooks: {
    async "build:done"() {
      await removeDtsFiles("dist");
    },
  },
});

async function removeDtsFiles(directory: string) {
  try {
    const items = await readdir(directory, { recursive: true });
    for (const item of items) {
      const itemPath = join(directory, item);

      if (item.endsWith(".d.ts")) {
        await rm(itemPath);
      }
    }
  } catch (error) {
    if ((error as any).code === "ENOENT" || (error as any).code === "ENOTDIR") {
      return;
    }
    console.error(`Error processing ${directory}: ${error}`);
  }
}
