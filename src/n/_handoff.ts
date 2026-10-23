import type { SessionConfigJWE } from "unjwt/session";
import { type SealedCarrier, sealedCarrier } from "./flow/_sealed-carrier.ts";
import type { FlowResult } from "./flow/complete-flow.ts";

/** The query parameter carrying a sealed sign-in result back to the host the user started on. */
export const HANDOFF_PARAM = "unauth_handoff";

/** Seals a sign-in result for one host and opens it on another. */
export type HandoffCarrier<TProfile, TLink> = SealedCarrier<FlowResult<TProfile, TLink>>;

/**
 * Seals a sign-in result for the host the user started on, under the flow key with its own
 * `typ`; a token opens once, within a minute, in this process.
 */
export function handoffCarrier<TProfile, TLink>(
  key: SessionConfigJWE["key"],
): HandoffCarrier<TProfile, TLink> {
  return sealedCarrier<FlowResult<TProfile, TLink>>(key, {
    typ: HANDOFF_TYP,
    name: "unauth-handoff",
  });
}

/** The handoff token's `typ`: never a session, flow or intent token. */
const HANDOFF_TYP = "unauth-handoff+jwt";
