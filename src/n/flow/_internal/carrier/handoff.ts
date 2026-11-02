import { secureCompare } from "unsecure/compare";
import type { FlowKey } from "../../../_internal/flow-key.ts";
import { UnauthError } from "../../../../error.ts";
import { type SealedCarrier, sealedCarrier } from "./sealed.ts";
import { type FlowCarrierOptions, openFlow } from "./transient.ts";
import type { FlowResult, Provider } from "../../types.ts";

/** The query parameter carrying a sealed sign-in result back to the host the user started on. */
export const HANDOFF_PARAM = "unauth_handoff";

/**
 * What a handoff carries: the completed sign-in or its failure, and the `state` of the flow the
 * origin host keeps.
 */
export type Handoff<TProfile, TMemo> = { state: string } & (
  | { result: FlowResult<TProfile, TMemo> }
  | { failure: HandoffFailure }
);

/** An `UnauthError` as a handoff carries it, its `cause` reduced to what survives JSON. */
export interface HandoffFailure {
  code: string;
  message: string;
  status?: number;
  cause?: unknown;
}

/** An `UnauthError` of a relocated leg, with the host it is handed back to and the `state` of the flow that host keeps. */
export interface RelocatedFailure {
  error: UnauthError;
  returnHost: string;
  state: string;
}

/** Seals a sign-in result for one host and opens it on another. */
export type HandoffCarrier<TProfile, TMemo> = SealedCarrier<Handoff<TProfile, TMemo>>;

/**
 * Seals a sign-in result for the host the user started on, under the flow key with its own
 * `typ`; a token opens once, within a minute, in this process, under the key `onKeyLookup` picks
 * when it is given. `ERR_UNAUTH_CONFIG_INVALID` for a key naming no algorithm without `jwe`.
 */
export function handoffCarrier<TProfile, TMemo>(
  key: FlowKey,
  options: Pick<FlowCarrierOptions, "jwe" | "onKeyLookup"> = {},
): HandoffCarrier<TProfile, TMemo> {
  return sealedCarrier<Handoff<TProfile, TMemo>>(key, {
    typ: HANDOFF_TYP,
    name: "unauth-handoff",
    jwe: options.jwe,
    onKeyLookup: options.onKeyLookup,
  });
}

/**
 * The result a handoff token brings back to the host the sign-in started on, redeemed as a
 * callback is: the token must open and name the provider and `state` of the flow this browser
 * recorded there, which is then consumed (its cookie expired on `headers`); a handed-back failure
 * is thrown as the `UnauthError` it was.
 * `ERR_AUTHN_FLOW_EXPIRED` without a flow or for a token that does not open;
 * `ERR_AUTHN_STATE_MISMATCH` for a token of another flow or provider. A refused token leaves a
 * cookie-carried flow alive; a store-backed one is taken on opening, whatever the token. What
 * `onKeyLookup` throws propagates as it is.
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
  const opened = await openFlow({ request, headers, provider, options });
  if (!opened.record) {
    throw new UnauthError(
      opened.reason === "missing"
        ? "[unauth/n] Finish the sign-in in the browser it was started in."
        : "[unauth/n] No sign-in in progress: it expired or was already completed.",
      "ERR_AUTHN_FLOW_EXPIRED",
      { status: 401, cause: { reason: opened.reason } },
    );
  }
  const taken = await carrier.take(token);
  if (!taken.ok) {
    throw new UnauthError(
      "[unauth/n] The sign-in handed over to this host is invalid, expired or already used.",
      "ERR_AUTHN_FLOW_EXPIRED",
      { status: 401, cause: { reason: "consumed", error: taken.refused } },
    );
  }
  const { record } = opened;
  const handoff = taken.value;
  if (record.provider !== provider.id || !secureCompare(record.state, handoff.state)) {
    throw new UnauthError(
      "[unauth/n] The sign-in handed over to this host does not belong to the one in progress.",
      "ERR_AUTHN_STATE_MISMATCH",
      { status: 401, cause: { provider: record.provider } },
    );
  }
  await opened.consume();
  if ("failure" in handoff) {
    const { failure } = handoff;
    throw new UnauthError(failure.message, failure.code, {
      status: failure.status,
      cause: failure.cause,
    });
  }
  return handoff.result;
}

/** `error` as a handoff carries it: its `cause` through JSON, an `Error` in it as its `name` and `message`, dropped when it does not serialise. */
export function handoffFailure(error: UnauthError): HandoffFailure {
  const failure: HandoffFailure = { code: error.code, message: error.message };
  if (error.status !== undefined) failure.status = error.status;
  const cause = jsonSafe(error.cause);
  if (cause !== undefined) failure.cause = cause;
  return failure;
}

/** The handoff token's `typ`: never a session, flow or intent token. */
const HANDOFF_TYP = "unauth-handoff+jwt";

function jsonSafe(value: unknown): unknown {
  try {
    const json = JSON.stringify(value, (_key, member: unknown) =>
      member instanceof Error ? { name: member.name, message: member.message } : member,
    );
    return json === undefined ? undefined : (JSON.parse(json) as unknown);
  } catch {
    return undefined;
  }
}
