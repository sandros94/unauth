import { useRuntimeConfig } from "nuxt/server";
import { migrate } from "drizzle-orm/pglite/migrator";

export default defineNitroPlugin((nitroApp) => {
  const ready = migrate(db, { migrationsFolder: useRuntimeConfig().db.migrations });
  nitroApp.hooks.hook("request", async () => {
    await ready;
  });
});
