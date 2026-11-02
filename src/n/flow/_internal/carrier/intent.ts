import { UnauthError } from "../../../../error.ts";
import { originOf, untrustedOrigin } from "../redirect.ts";
import { type SealedCarrier, sealedCarrier } from "./sealed.ts";
import type { StartFlowOptions } from "../../start-flow.ts";
import type { FlowRecord } from "../../types.ts";

/** The query parameter carrying a request's sealed intent to the host a start is relocated to. */
const INTENT_PARAM = "unauth_intent";

/** The members of `startFlow`'s options that are the request's own intent. */
export const INTENT_KEYS = ["redirect", "memo", "loginHint", "scopes", "params"] as const;

/** What a request asks of its sign-in, as `startFlow` takes it. */
export type StartIntent<TMemo> = Pick<StartFlowOptions<TMemo>, (typeof INTENT_KEYS)[number]>;

/**
 * What a relocation seals: the request's intent, the host it was made on, and the provider and
 * `state` of the flow recorded there, for the relocated start to continue.
 */
interface SealedIntent<TMemo> {
  intent: StartIntent<TMemo>;
  returnHost: string;
  provider: string;
  state: string;
}

/** What a resumed intent adds to a relocated start: the options and, from the origin host, its flow's binding. */
export type ResumedIntent<TMemo> =
  | { options: StartFlowOptions<TMemo>; returnHost?: undefined; state?: undefined }
  | { options: StartFlowOptions<TMemo>; returnHost: string; state: string };

/** Whether `request` is a relocated start: its URL carries a sealed intent, opened or not. */
export function carriesIntent(request: Request): boolean {
  return new URL(request.url).searchParams.has(INTENT_PARAM);
}

/**
 * `url` with the intent of `options`, the hostname of `request` (the start being relocated) and
 * the provider and `state` of `record`, the flow that host keeps, sealed into
 * {@link INTENT_PARAM}, for the relocated start to read back. The completed sign-in is returned
 * to that host, so the request's origin must be one of `trustedOrigins`:
 * `ERR_AUTHN_ORIGIN_UNTRUSTED` (421) otherwise, and nothing is sealed.
 */
export async function withSealedIntent<TMemo>(
  url: URL,
  context: { request: Request; options: StartFlowOptions<TMemo>; record: FlowRecord<TMemo> },
): Promise<URL> {
  const { request, options, record } = context;
  const from = new URL(request.url);
  const trusted = (options.trustedOrigins ?? []).some((origin) => originOf(origin) === from.origin);
  if (!trusted) throw untrustedOrigin(from.origin);
  const sealed = new URL(url);
  const token = await carrierOf<TMemo>(options).issue({
    intent: definedIntent(options),
    returnHost: from.hostname,
    provider: record.provider,
    state: record.state,
  });
  sealed.searchParams.set(INTENT_PARAM, token);
  return sealed;
}

/**
 * `options` with the intent a relocation sealed into `request`'s URL merged over them, member by
 * member, the sealed member winning where both have a value; beside them, the host the relocated
 * start was made on and the `state` of the flow it keeps. `ERR_AUTHN_FLOW_EXPIRED` when the token
 * does not open, expired or was already used; `ERR_AUTHN_STATE_MISMATCH` when it was sealed for
 * another provider. What `onKeyLookup` throws propagates as it is.
 */
export async function resumeIntent<TMemo>(
  request: Request,
  context: { provider: string; options: StartFlowOptions<TMemo> },
): Promise<ResumedIntent<TMemo>> {
  const { provider, options } = context;
  const token = new URL(request.url).searchParams.get(INTENT_PARAM);
  if (token === null) return { options };
  const taken = await carrierOf<TMemo>(options).take(token);
  if (!taken.ok) {
    throw new UnauthError(
      "[unauth/n] The sign-in relocated to this host is invalid, expired or already used: start it again.",
      "ERR_AUTHN_FLOW_EXPIRED",
      { status: 401, cause: { reason: "consumed", error: taken.refused } },
    );
  }
  const sealed = taken.value;
  if (sealed.provider !== provider) {
    throw new UnauthError(
      "[unauth/n] The sign-in relocated to this host belongs to another provider.",
      "ERR_AUTHN_STATE_MISMATCH",
      { status: 401, cause: { provider: sealed.provider } },
    );
  }
  return {
    options: { ...options, ...definedIntent(sealed.intent) },
    returnHost: sealed.returnHost,
    state: sealed.state,
  };
}

/** The intent token's `typ`: never a session, flow or handoff token. */
const INTENT_TYP = "unauth-intent+jwt";

function carrierOf<TMemo>(
  options: Pick<StartFlowOptions<TMemo>, "key" | "jwe" | "onKeyLookup">,
): SealedCarrier<SealedIntent<TMemo>> {
  return sealedCarrier<SealedIntent<TMemo>>(options.key, {
    typ: INTENT_TYP,
    name: "unauth-intent",
    jwe: options.jwe,
    onKeyLookup: options.onKeyLookup,
  });
}

/** The members of `from`'s intent that have a value. */
export function definedIntent<TMemo>(from: StartIntent<TMemo>): StartIntent<TMemo> {
  const intent: Record<string, unknown> = {};
  for (const key of INTENT_KEYS) {
    if (from[key] !== undefined) intent[key] = from[key];
  }
  return intent;
}
