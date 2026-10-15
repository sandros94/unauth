import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    slowTestThreshold: 1000,
    coverage: {
      exclude: ["dist/**", "test/**", "playground/**", "*.config.ts"],
    },
  },
});
