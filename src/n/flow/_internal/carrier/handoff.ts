import { secureCompare } from "unsecure/compare";
import type { FlowKey } from "../../../_internal/flow-key.ts";
import { UnauthError } from "../../../../error.ts";
import { type SealedCarrier, sealedCarrier } from "./sealed.ts";
import { type FlowCarrierOptions, takeFlow } from "./transient.ts";
import type { FlowResult, Provider } from "../../types.ts";

/** The query parameter carrying a sealed sign-in result back to the host the user started on. */
export const HANDOFF_PARAM = "unauth_handoff";

/** What a handoff carries: the completed sign-in, and the `state` of the flow the origin host keeps. */
export interface Handoff<TProfile, TMemo> {
  result: FlowResult<TProfile, TMemo>;
  state: string;
}

/** Seals a sign-in result for one host and opens it on another. */
export type HandoffCarrier<TProfile, TMemo> = SealedCarrier<Handoff<TProfile, TMemo>>;

/**
 * Seals a sign-in result for the host the user started on, under the flow key with its own
 * `typ`; a token opens once, within a minute, in this process.
 */
export function handoffCarrier<TProfile, TMemo>(key: FlowKey): HandoffCarrier<TProfile, TMemo> {
  return sealedCarrier<Handoff<TProfile, TMemo>>(key, {
    typ: HANDOFF_TYP,
    name: "unauth-handoff",
  });
}

/**
 * The result a handoff token brings back to the host the sign-in started on, redeemed as a
 * callback is: the flow this browser recorded there is taken (its cookie expired on `headers`,
 * whatever the outcome), and the token must open and name that flow's provider and `state`.
 * `ERR_AUTHN_FLOW_EXPIRED` without a flow or for a token that does not open;
 * `ERR_AUTHN_STATE_MISMATCH` for a token of another flow or provider.
 */
export async function redeemHandoff<TProfile, TMemo>(
  provider: Provider<TProfile>,
  request: Request,
  context: {
    token: string;
    carrier: HandoffCarrier<TProfile, TMemo>;
    headers: Headers;
    options: FlowCarrierOptions;
  },
): Promise<FlowResult<TProfile, TMemo>> {
  const { token, carrier, headers, options } = context;
  const taken = await takeFlow({ request, headers, provider, options });
  if (!taken.record) {
    throw new UnauthError(
      taken.reason === "missing"
        ? "[unauth/n] Finish the sign-in in the browser it was started in."
        : "[unauth/n] No sign-in in progress: it expired or was already completed.",
      "ERR_AUTHN_FLOW_EXPIRED",
      { status: 401, cause: { reason: taken.reason } },
    );
  }
  let handoff: Handoff<TProfile, TMemo>;
  try {
    handoff = await carrier.take(token);
  } catch (error) {
    throw new UnauthError(
      "[unauth/n] The sign-in handed over to this host is invalid, expired or already used.",
      "ERR_AUTHN_FLOW_EXPIRED",
      { status: 401, cause: { reason: "consumed", error } },
    );
  }
  const { record } = taken;
  if (record.provider !== provider.id || !secureCompare(record.state, handoff.state)) {
    throw new UnauthError(
      "[unauth/n] The sign-in handed over to this host does not belong to the one in progress.",
      "ERR_AUTHN_STATE_MISMATCH",
      { status: 401, cause: { provider: record.provider } },
    );
  }
  return handoff.result;
}

/** The handoff token's `typ`: never a session, flow or intent token. */
const HANDOFF_TYP = "unauth-handoff+jwt";
