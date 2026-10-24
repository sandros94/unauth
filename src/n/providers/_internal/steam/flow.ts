import { UnauthError } from "../../../../error.ts";
import { providerError, stringField } from "../../../flow/_internal/http/shared.ts";
import type {
  CustomCompleteContext,
  CustomFlowResult,
  CustomStart,
  CustomStartContext,
} from "../../../flow/types.ts";
import { type SteamProfile, bareIdentity, playerSummary } from "./profile.ts";
import { checkAuthentication } from "./verify.ts";

/** Steam's OpenID provider endpoint: the only `openid.op_endpoint` a Steam assertion may name. */
export const STEAM_OP_ENDPOINT = "https://steamcommunity.com/openid/login";
const OPENID_NS = "http://specs.openid.net/auth/2.0";
const IDENTIFIER_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";
const LABEL = "Steam OpenID endpoint";
const CLAIMED_ID = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/;
/** What a positive assertion signs at least (OpenID 2.0 §10.1). */
const SIGNED_FIELDS = [
  "op_endpoint",
  "return_to",
  "response_nonce",
  "assoc_handle",
  "claimed_id",
  "identity",
];

/** What `start` seals for `complete`. */
export interface FlowData {
  /** The exact `openid.return_to` sent, which the assertion must name (OpenID 2.0 §11.1). */
  returnTo: string;
}

/**
 * The first leg (OpenID 2.0 §9.1): a `checkid_setup` request with `identifier_select` as both
 * identifiers, `openid.return_to` the callback URL with the flow's `state` in its query (§11.1
 * sends those query parameters back) and `openid.realm` the callback's origin. Steam takes no
 * `login`, `scopes` or extra parameters.
 */
export async function start(context: CustomStartContext): Promise<CustomStart> {
  const returnTo = new URL(context.redirectUri);
  returnTo.searchParams.set("state", context.record.state);
  const url = new URL(STEAM_OP_ENDPOINT);
  url.searchParams.set("openid.ns", OPENID_NS);
  url.searchParams.set("openid.mode", "checkid_setup");
  url.searchParams.set("openid.claimed_id", IDENTIFIER_SELECT);
  url.searchParams.set("openid.identity", IDENTIFIER_SELECT);
  url.searchParams.set("openid.return_to", returnTo.href);
  url.searchParams.set("openid.realm", returnTo.origin);
  const data: FlowData = { returnTo: returnTo.href };
  return { url, data: { ...data } };
}

/**
 * The second leg (OpenID 2.0 §11): the assertion's mode, `op_endpoint`, `return_to` (§11.1),
 * `claimed_id` and `identity` (§11.2) and signed fields (§10.1) checked, then verified directly at
 * Steam (§11.4.2); the SteamID64 the claimed identifier carries is the subject, with its player
 * summary when the provider has a Web API key. The response nonce (§11.3) needs no store of its
 * own: the engine's flow record is single-use, so an assertion completes at most one sign-in.
 */
export async function complete(
  context: CustomCompleteContext,
  provider: { apiKey?: string },
): Promise<CustomFlowResult<SteamProfile>> {
  const { params, record } = context;
  const returnTo = stringField(record.data, "returnTo");
  if (returnTo === undefined) throw mismatch(record.provider, "record");

  const mode = params["openid.mode"];
  if (mode === "cancel") {
    throw new UnauthError(
      "[unauth/n] The user did not sign in at Steam.",
      "ERR_AUTHN_PROVIDER_REFUSED",
      { status: 401, cause: { error: "cancel" } },
    );
  }
  if (mode !== "id_res") {
    throw providerError("Steam sent no positive assertion.", {
      reason: "malformed",
      cause: { mode },
    });
  }
  if (params["openid.op_endpoint"] !== STEAM_OP_ENDPOINT) {
    throw mismatch(record.provider, "op_endpoint");
  }
  if (params["openid.return_to"] !== returnTo) throw mismatch(record.provider, "return_to");
  const claimedId = params["openid.claimed_id"];
  const steamid = claimedId === undefined ? undefined : CLAIMED_ID.exec(claimedId)?.[1];
  if (steamid === undefined) throw mismatch(record.provider, "claimed_id");
  if (params["openid.identity"] !== claimedId) throw mismatch(record.provider, "identity");
  const unsigned = unsignedField(params);
  if (unsigned !== undefined) throw mismatch(record.provider, "signed", unsigned);

  const answer = await checkAuthentication(params, {
    endpoint: STEAM_OP_ENDPOINT,
    fetch: context.fetch,
    label: LABEL,
  });
  if (answer.is_valid !== "true") {
    throw new UnauthError(
      "[unauth/n] Steam did not confirm the assertion as its own.",
      "ERR_AUTHN_PROVIDER_REFUSED",
      { status: 401, cause: { error: "invalid_signature" } },
    );
  }

  const identity =
    provider.apiKey === undefined
      ? bareIdentity(steamid)
      : await playerSummary(steamid, { apiKey: provider.apiKey, fetch: context.fetch });
  return { identity };
}

/**
 * The first field a positive assertion must sign but does not, or lists as signed but does not
 * carry (OpenID 2.0 §10.1); `undefined` when the signature covers what it must.
 */
function unsignedField(params: Record<string, string>): string | undefined {
  const signed = new Set(params["openid.signed"]?.split(",") ?? []);
  const missing = SIGNED_FIELDS.find((field) => !signed.has(field));
  if (missing !== undefined) return missing;
  for (const field of signed) {
    if (params[`openid.${field}`] === undefined) return field;
  }
  return undefined;
}

/** `ERR_AUTHN_STATE_MISMATCH` (401): the assertion is not the one this sign-in asked Steam for. */
function mismatch(
  provider: string,
  reason: string,
  field?: string,
): UnauthError<"ERR_AUTHN_STATE_MISMATCH"> {
  return new UnauthError(
    "[unauth/n] The callback does not belong to this sign-in.",
    "ERR_AUTHN_STATE_MISMATCH",
    {
      status: 401,
      cause: field === undefined ? { provider, reason } : { provider, reason, field },
    },
  );
}
