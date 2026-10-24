import {
  type RequestEvent,
  createError,
  defineEventHandler,
  deriveSecret,
  readBody,
} from "nuxt/server";
import { base64UrlStringify } from "unauth/utils";
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

export default defineEventHandler(
  defineAtprotoHandler({
    provider: atproto,
    key: async () => {
      const hex = await deriveSecret("unauth:flow");
      const bytes = Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16));
      return { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" } as const;
    },
    onStart: async (event: RequestEvent) => {
      const session = await useAuthSession(event);
      const body: { login?: unknown } | undefined =
        event.req.method === "POST" ? await readBody(event) : undefined;
      const loginHint = body?.login;
      return {
        ...(typeof loginHint === "string" && loginHint ? { loginHint } : {}),
        ...(session.id ? { memo: { userId: session.data.userId } } : {}),
      };
    },
    onSuccess: async (event, { identity, memo }) => {
      const session = await useAuthSession(event);
      if (memo) {
        if (session.data.userId !== memo.userId) {
          throw createError({ statusCode: 401, message: "The session changed during the link" });
        }
        await linkIdentity(memo.userId, identity);
        return;
      }
      const user = await findOrCreateUser(identity);
      await session.clear();
      await session.update({
        userId: user.id,
        ...(identity.name ? { name: identity.name } : {}),
        signedInAt: Date.now(),
      });
    },
  }),
);
