import {
  type RequestEvent,
  createError,
  defineEventHandler,
  deriveSecret,
  useRuntimeConfig,
} from "nuxt/server";
import { base64UrlStringify } from "unauth/utils";
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
    onStart: async (event: RequestEvent) => {
      const session = await useAuthSession(event);
      return session ? { memo: { userId: session.userId } } : undefined;
    },
    onSuccess: async (event, { identity, memo }) => {
      if (memo) {
        const session = await useAuthSession(event);
        if (session?.userId !== memo.userId) {
          throw createError({ statusCode: 401, message: "The session changed during the link" });
        }
        await linkIdentity(memo.userId, identity);
        return;
      }

      const user = await findOrCreateUser(identity);
      await createSession(event, { userId: user.id });
    },
  }),
);
