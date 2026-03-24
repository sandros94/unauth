import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: ["src/h3v2.ts", "dist/**", "test/**"],
    },
  },
});
