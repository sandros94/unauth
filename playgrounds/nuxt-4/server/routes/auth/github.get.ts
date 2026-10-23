import { defineEventHandler, deriveSecret, useRuntimeConfig } from "nuxt/server";
import { base64UrlStringify } from "unjwt/utils";
import { defineGitHubHandler } from "unauth/n/providers/github";

export default defineEventHandler(
  defineGitHubHandler({
    clientId: useRuntimeConfig().github.clientId,
    clientSecret: useRuntimeConfig().github.clientSecret,
    key: async () => {
      const hex = await deriveSecret("unauth:flow");
      const bytes = Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16));
      return { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" } as const;
    },
    origin: useRuntimeConfig().public.origin,
    session: useAuthSession,
  }),
);
