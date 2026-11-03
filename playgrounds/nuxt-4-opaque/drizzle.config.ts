import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  driver: "pglite",
  dbCredentials: { url: "./.data/pglite" },
  schema: "./server/db/schema.ts",
  out: "./server/db/migrations",
});
