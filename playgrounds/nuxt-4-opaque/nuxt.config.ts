import { fileURLToPath } from "node:url";

export default defineNuxtConfig({
  compatibilityDate: "2026-10-01",

  runtimeConfig: {
    github: {
      clientId: "",
      clientSecret: "",
    },
    db: {
      dataDir: fileURLToPath(new URL("./.data/pglite", import.meta.url)),
      migrations: fileURLToPath(new URL("./server/db/migrations", import.meta.url)),
    },
    public: {
      origin: "http://localhost:3000",
    },
  },
});
