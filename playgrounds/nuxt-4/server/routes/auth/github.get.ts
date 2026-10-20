import { defineEventHandler } from "nuxt/server";

export default defineEventHandler((event) => useGitHubSignIn(event));
