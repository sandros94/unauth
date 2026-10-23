import { type RequestEvent, createError, defineEventHandler, deriveSecret } from "nuxt/server";
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
      return session.id ? { link: { userId: session.data.userId } } : undefined;
    },
    onSuccess: async (event, { identity, link }) => {
      const session = await useAuthSession(event);
      if (link) {
        if (session.data.userId !== link.userId) {
          throw createError({ statusCode: 401, message: "The session changed during the link" });
        }
        await linkIdentity(link.userId, identity);
        return;
      }
      const user = await findOrCreateUser(identity);
      await session.clear();
      await session.update({
        userId: user.id,
        provider: identity.provider,
        subject: identity.subject,
        ...(identity.name ? { name: identity.name } : {}),
        signedInAt: Date.now(),
      });
    },
  }),
);
