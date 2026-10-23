import type { SessionConfigJWE } from "unjwt/session";
import { UnauthError } from "../../_internal/error.ts";
import { type SealedCarrier, sealedCarrier } from "./_sealed-carrier.ts";
import type { StartFlowOptions } from "./start-flow.ts";

/** The query parameter carrying a request's sealed intent to the host a start is relocated to. */
const INTENT_PARAM = "unauth_intent";

/** The members of `startFlow`'s options that are the request's own intent. */
export const INTENT_KEYS = ["redirect", "link", "login", "scopes", "params"] as const;

/** What a request asks of its sign-in, as `startFlow` takes it. */
export type StartIntent<TLink> = Pick<StartFlowOptions<TLink>, (typeof INTENT_KEYS)[number]>;

/** What a relocation seals: the request's intent, and the host it was made on. */
interface SealedIntent<TLink> {
  intent: StartIntent<TLink>;
  returnHost: string;
}

/**
 * `url` with the intent of `options` and the hostname of `request`, the start being relocated,
 * sealed into {@link INTENT_PARAM}, for the relocated start to read back.
 */
export async function withSealedIntent<TLink>(
  url: URL,
  context: { request: Request; options: StartFlowOptions<TLink> },
): Promise<URL> {
  const { request, options } = context;
  const sealed = new URL(url);
  const token = await carrierOf<TLink>(options.key).issue({
    intent: definedIntent(options),
    returnHost: new URL(request.url).hostname,
  });
  sealed.searchParams.set(INTENT_PARAM, token);
  return sealed;
}

/**
 * `options` with the intent a relocation sealed into `request`'s URL merged over them, member by
 * member, the sealed member winning where both have a value; beside them, the host the relocated
 * start was made on. `ERR_AUTHN_FLOW_EXPIRED` when the token does not open, expired or was already
 * used.
 */
export async function resumeIntent<TLink>(
  request: Request,
  options: StartFlowOptions<TLink>,
): Promise<{ options: StartFlowOptions<TLink>; returnHost?: string }> {
  const token = new URL(request.url).searchParams.get(INTENT_PARAM);
  if (token === null) return { options };
  let sealed: SealedIntent<TLink>;
  try {
    sealed = await carrierOf<TLink>(options.key).take(token);
  } catch (error) {
    throw new UnauthError(
      "[unauth/n] The sign-in relocated to this host is invalid, expired or already used: start it again.",
      "ERR_AUTHN_FLOW_EXPIRED",
      { status: 401, cause: { reason: "consumed", error } },
    );
  }
  return {
    options: { ...options, ...definedIntent(sealed.intent) },
    returnHost: sealed.returnHost,
  };
}

/** The intent token's `typ`: never a session, flow or handoff token. */
const INTENT_TYP = "unauth-intent+jwt";

function carrierOf<TLink>(key: SessionConfigJWE["key"]): SealedCarrier<SealedIntent<TLink>> {
  return sealedCarrier<SealedIntent<TLink>>(key, { typ: INTENT_TYP, name: "unauth-intent" });
}

/** The members of `from`'s intent that have a value. */
function definedIntent<TLink>(from: StartIntent<TLink>): StartIntent<TLink> {
  const intent: Record<string, unknown> = {};
  for (const key of INTENT_KEYS) {
    if (from[key] !== undefined) intent[key] = from[key];
  }
  return intent;
}
