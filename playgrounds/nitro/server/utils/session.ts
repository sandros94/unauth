import { HTTPError } from "nitro";
import {
  type SessionManager,
  type WebSessionEvent,
  defineJWESession,
  deriveJWKFromPassword,
} from "unjwt/session";

import type { AuthSessionData } from "unauth/n";

export interface SessionData extends AuthSessionData {}

const password = process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";

const sessionKey = await deriveJWKFromPassword(password, {
  alg: "PBES2-HS256+A128KW",
  salt: "unauth-playground-nitro:session",
  iterations: 600_000,
});

// Not narrowed to Nitro's `H3Event`: the WebSocket upgrade hands a request by its headers.
const definition = defineJWESession<SessionData, "1h">({
  key: sessionKey,
  name: "unauth-playground",
  maxAge: "1h",
  rolling: "15m",
});

export function useAuthSession(event: WebSessionEvent): Promise<SessionManager<SessionData, "1h">> {
  return definition.use(event);
}

/** The session once signed in; a 401 otherwise. */
export async function requireAuthSession(
  event: WebSessionEvent,
): Promise<SessionManager<SessionData, "1h">> {
  const session = await useAuthSession(event);
  if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  return session;
}
