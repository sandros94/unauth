import { type SessionConfigJWE, defineJWESession } from "unjwt/session";

/** Seals a value for another request and opens it there, once. */
export interface SealedCarrier<T> {
  issue: (value: T) => Promise<string>;
  /** The sealed value; throws when the token does not open, is expired, or was already taken. */
  take: (token: string) => Promise<T>;
}

/**
 * Seals values under the flow key with the given `typ`: a carrier never opens another carrier's,
 * a session's or a flow's token. A token opens once, within a minute; used ids are kept in this
 * process's memory until they expire.
 */
export function sealedCarrier<T>(
  key: SessionConfigJWE["key"],
  options: { typ: string; name: string },
): SealedCarrier<T> {
  const tokens = defineJWESession<{ value: T }, typeof MAX_AGE>({
    key,
    name: options.name,
    maxAge: MAX_AGE,
    cookie: false,
    sessionHeader: false,
    jwe: { encryptOptions: { protectedHeader: { typ: options.typ } } },
  });
  return {
    issue: (value) => tokens.issue({ value }),
    take: async (token) => {
      const opened = await tokens.open(token);
      const now = Date.now();
      for (const [id, expiresAt] of used) if (expiresAt < now) used.delete(id);
      if (used.has(opened.id)) throw new Error("sealed token already used");
      used.set(opened.id, opened.expiresAt);
      return opened.data.value;
    },
  };
}

/** How long a sealed token may take to arrive. */
const MAX_AGE = "1m";
/** The ids of the tokens taken in this process, until they expire. */
const used = new Map<string, number>();
