import { HTTPError } from "nitro";
import {
  type SessionManager,
  type WebSessionEvent,
  defineJWESession,
  deriveJWKFromPassword,
} from "unauth/session";

export interface SessionData {
  userId: string;
  name?: string;
  signedInAt: number;
}

const password = process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";

const sessionKey = await deriveJWKFromPassword(password, {
  alg: "PBES2-HS256+A128KW",
  salt: "unauth-playground-nitro:session",
  iterations: 600_000,
});

const definition = defineJWESession<SessionData, "1h">({
  key: sessionKey,
  name: "unauth-playground",
  maxAge: "1h",
  rolling: "15m",
});

export function useAuthSession(event: WebSessionEvent): Promise<SessionManager<SessionData, "1h">> {
  return definition.use(event);
}

export async function requireAuthSession(
  event: WebSessionEvent,
): Promise<SessionManager<SessionData, "1h">> {
  const session = await useAuthSession(event);
  if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  return session;
}
