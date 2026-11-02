import { defineJWESession } from "unjwt/session";
import {
  type FlowEvent,
  type FlowKey,
  type FlowKeyAlgorithms,
  type FlowKeyLookup,
  flowSessionOptions,
} from "../../../_internal/flow-key.ts";
import { definedSession, keyLookupFailure } from "../../../../_internal/session-error.ts";

/** A sealed token taken: its value, or why it was refused. */
export type SealedTake<T> = { ok: true; value: T } | { ok: false; refused: unknown };

/** Seals a value for another request and opens it there, once. */
export interface SealedCarrier<T> {
  issue: (value: T) => Promise<string>;
  /**
   * The sealed value, or why the token is refused: it does not open, is expired, or was already
   * taken. What `onKeyLookup` throws rejects as it is, and a key it returns that cannot open the
   * token rejects with unjwt's `ERR_JWK_INVALID`.
   */
  take: (token: string) => Promise<SealedTake<T>>;
}

/**
 * Seals values under the flow key with the given `typ`: a carrier never opens another carrier's,
 * a session's or a flow's token. A token opens once, within a minute; used ids are kept in this
 * process's memory until they expire; `onKeyLookup`, when given, picks the key that opens one.
 * `ERR_UNAUTH_CONFIG_INVALID` for a key naming no algorithm without `jwe`, or a key unjwt refuses.
 */
export function sealedCarrier<T>(
  key: FlowKey,
  options: { typ: string; name: string; jwe?: FlowKeyAlgorithms; onKeyLookup?: FlowKeyLookup },
): SealedCarrier<T> {
  const tokens = definedSession(
    () =>
      defineJWESession<{ value: T }, typeof MAX_AGE, FlowEvent>({
        key,
        name: options.name,
        maxAge: MAX_AGE,
        cookie: false,
        sessionHeader: false,
        ...flowSessionOptions(key, options),
      }),
    { prefix: "[unauth/n]" },
  );
  return {
    issue: (value) => tokens.issue({ value }),
    take: async (token) => {
      let opened: Awaited<ReturnType<typeof tokens.open>>;
      try {
        opened = await tokens.open(token);
      } catch (error) {
        const failure = keyLookupFailure(error);
        if (failure) throw failure.error;
        return { ok: false, refused: error };
      }
      const now = Date.now();
      for (const [id, expiresAt] of used) if (expiresAt < now) used.delete(id);
      if (used.has(opened.id))
        return { ok: false, refused: new Error("sealed token already used") };
      used.set(opened.id, opened.expiresAt);
      return { ok: true, value: opened.data.value };
    },
  };
}

/** How long a sealed token may take to arrive. */
const MAX_AGE = "1m";
/** The ids of the tokens taken in this process, until they expire. */
const used = new Map<string, number>();
