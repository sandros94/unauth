import { defineConfig } from "nitro";

export default defineConfig({
  serverDir: "./server",

  runtimeConfig: {
    /** Seals the sign-in flow cookie; set `NITRO_AUTH_SECRET` outside development. */
    authSecret: "dev-only-placeholder-auth-secret-change-me",
    github: {
      clientId: "",
      clientSecret: "",
    },
    public: {
      origin: "http://localhost:3000",
    },
  },

  features: { websocket: true },

  experimental: { database: true },
  database: {
    default: { connector: "node-sqlite", options: { name: "accounts" } },
  },
});
