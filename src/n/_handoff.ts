import { type SessionConfigJWE, defineJWESession } from "unjwt/session";
import type { FlowResult } from "./flow/complete-flow.ts";

/** The query parameter carrying a sealed sign-in result back to the host the user started on. */
export const HANDOFF_PARAM = "unauth_handoff";

/** Seals a sign-in result for one host and opens it on another. */
export interface HandoffCarrier<TProfile> {
  issue: (result: FlowResult<TProfile>) => Promise<string>;
  take: (token: string) => Promise<FlowResult<TProfile>>;
}

/**
 * Seals a sign-in result for the host the user started on, under the flow key with its own
 * `typ`; a token opens once, within a minute, in this process. Relocations are a development
 * affair (`devHosts`), so the used ids are kept in memory.
 */
export function handoffCarrier<TProfile>(key: SessionConfigJWE["key"]): HandoffCarrier<TProfile> {
  const tokens = defineJWESession<{ result: FlowResult<TProfile> }, typeof HANDOFF_MAX_AGE>({
    key,
    name: "unauth-handoff",
    maxAge: HANDOFF_MAX_AGE,
    cookie: false,
    sessionHeader: false,
    jwe: { encryptOptions: { protectedHeader: { typ: HANDOFF_TYP } } },
  });
  const used = new Map<string, number>();
  return {
    issue: (result) => tokens.issue({ result }),
    take: async (token) => {
      const opened = await tokens.open(token);
      const now = Date.now();
      for (const [id, expiresAt] of used) if (expiresAt < now) used.delete(id);
      if (used.has(opened.id)) throw new Error("handoff token already used");
      used.set(opened.id, opened.expiresAt);
      return opened.data.result;
    },
  };
}

/** The handoff token's `typ`: never a session or flow token. */
const HANDOFF_TYP = "unauth-handoff+jwt";
/** How long a handoff token may take to arrive. */
const HANDOFF_MAX_AGE = "1m";
