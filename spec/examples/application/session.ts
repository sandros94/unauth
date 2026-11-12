import { type H3Event, HTTPError } from "h3";
import { isUnauthError } from "unauth/error";
import { type OpaqueSession, defineOpaqueSession } from "unauth/session";
import type { Authz, Grants } from "unauth/z";
import { assertGrants } from "unauth/z";
import { type SessionData, sqliteSessionStore } from "../storage/sessions.ts";
import { useDB } from "./db.ts";

declare module "h3" {
  interface H3EventContext {
    grantsOf?: GrantsOf;
  }
}

export type GrantsOf = (subject: string, bases?: readonly string[]) => Grants;

export interface SignedIn {
  subject: string;
  grants?: Grants;
}

const sessions = defineOpaqueSession<SessionData, H3Event>({
  store: (event) => sqliteSessionStore(useDB(event)),
  maxAge: "8h",
  idle: "1h",
});

export function useAuthSession(event: H3Event): OpaqueSession<SessionData> {
  return sessions.use(event);
}

export async function startSession(event: H3Event, signedIn: SignedIn): Promise<void> {
  const session = useAuthSession(event);
  await session.clear();
  await session.update(signedIn);
}

export async function findAuthSession(event: H3Event, authz: Authz): Promise<SignedIn | undefined> {
  const session = useAuthSession(event);
  const { data } = await session.record;
  if (data === undefined) return undefined;
  const { subject, grants } = data;
  if (grants === undefined) return { subject };
  try {
    assertGrants(authz.catalog, grants);
    if (!authz.diverged(grants)?.presets.length) return { subject, grants };
  } catch (error) {
    if (!isUnauthError(error) || !error.code.startsWith("ERR_AUTHZ_")) throw error;
    if (error.code !== "ERR_AUTHZ_GRANTS_CATALOG") return undefined;
  }
  const grantsOf = event.context.grantsOf;
  if (grantsOf === undefined) throw new Error("The application issues no grants.");
  const issued = grantsOf(subject, basesOf(grants));
  await session.update({ grants: issued });
  return { subject, grants: issued };
}

export async function requireAuthSession(event: H3Event, authz: Authz): Promise<SignedIn> {
  const session = await findAuthSession(event, authz);
  if (session === undefined) throw new HTTPError({ status: 401, message: "Sign in first." });
  return session;
}

function basesOf(grants: unknown): string[] | undefined {
  if (typeof grants !== "object" || grants === null || !("bs" in grants)) return undefined;
  const { bs } = grants;
  return Array.isArray(bs)
    ? bs.filter((base): base is string => typeof base === "string")
    : undefined;
}
