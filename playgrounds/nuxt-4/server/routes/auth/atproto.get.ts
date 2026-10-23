import { defineEventHandler, deriveSecret } from "nuxt/server";
import { base64UrlStringify } from "unjwt/utils";
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

export default defineEventHandler(
  defineAtprotoHandler({
    provider: atproto,
    key: async () => {
      const hex = await deriveSecret("unauth:flow");
      const bytes = Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16));
      return { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" } as const;
    },
    session: useAuthSession,
  }),
);
