import { defineConfig } from "nitro";

export default defineConfig({
  serverDir: "./server",

  runtimeConfig: {
    github: {
      clientId: "",
      clientSecret: "",
    },
    public: {
      origin: "http://localhost:3000",
    },
  },

  features: { websocket: true },
});
