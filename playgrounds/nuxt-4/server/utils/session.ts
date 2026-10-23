import { createError, deriveSecret } from "nuxt/server";
import {
  type SessionDefinition,
  type SessionManager,
  type WebSessionEvent,
  defineJWESession,
} from "unjwt/session";
import { base64UrlStringify } from "unjwt/utils";

let definition: Promise<SessionDefinition<SessionData, "1h", WebSessionEvent>> | undefined;

/**
 * `deriveSecret` needs the Nuxt runtime config, so the definition is created on first use, not at
 * import time. The purpose's 32 HKDF bytes are an A256GCM key as an `oct` JWK.
 */
async function define(): Promise<SessionDefinition<SessionData, "1h", WebSessionEvent>> {
  const secret = await deriveSecret("unauth:session");
  const bytes = Uint8Array.from(secret.match(/../g)!, (pair) => Number.parseInt(pair, 16));

  // Not narrowed to Nuxt's `RequestEvent`: the WebSocket upgrade hands a request by its headers.
  return defineJWESession<SessionData, "1h">({
    key: { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" },
    name: "unauth-playground",
    maxAge: "1h",
    rolling: "15m",
  });
}

export async function useAuthSession(
  event: WebSessionEvent,
): Promise<SessionManager<SessionData, "1h">> {
  return (definition ??= define()).then((session) => session.use(event));
}

/** The session once signed in; a 401 otherwise. */
export async function requireAuthSession(
  event: WebSessionEvent,
): Promise<SessionManager<SessionData, "1h">> {
  const session = await useAuthSession(event);
  if (!session.id) throw createError({ statusCode: 401, message: "Sign in first" });
  return session;
}
