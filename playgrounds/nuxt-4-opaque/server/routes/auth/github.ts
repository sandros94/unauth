import {
  type RequestEvent,
  createError,
  defineEventHandler,
  deriveSecret,
  useRuntimeConfig,
} from "nuxt/server";
import { isUnauthError } from "unauth/n";
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
      const { data } = await useAuthSession(event).record;
      return data ? { memo: { userId: data.userId } } : undefined;
    },
    onSuccess: async (event, { identity, memo }) => {
      const session = useAuthSession(event);

      if (memo) {
        const { data } = await session.record;
        if (data?.userId !== memo.userId) {
          throw createError({ statusCode: 401, message: "The session changed during the link" });
        }
        await withTransaction(event, async () => {
          await linkIdentity(event, memo.userId, identity);
          await session.rotate();
        });
        return;
      }

      const user = await findOrCreateUser(event, identity);
      await session.clear();
      await session.update({
        userId: user.id,
        ...(identity.name ? { name: identity.name } : {}),
        signedInAt: Date.now(),
      });
    },
    onError: (_event, error) => {
      if (isUnauthError(error, "ERR_AUTHN_CROSS_SITE_START") && error.cause.reason === "method") {
        return new Response(null, {
          status: 302,
          headers: { "location": "/?notice=use-link-button", "cache-control": "no-store" },
        });
      }
      return;
    },
  }),
);
