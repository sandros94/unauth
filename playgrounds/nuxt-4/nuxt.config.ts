export default defineNuxtConfig({
  compatibilityDate: "2026-10-01",

  runtimeConfig: {
    github: {
      clientId: "",
      clientSecret: "",
    },
    public: {
      origin: "http://localhost:3000",
    },
  },

  nitro: {
    experimental: { websocket: true },
  },
});
