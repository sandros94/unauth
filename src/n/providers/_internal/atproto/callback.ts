import { UnauthError } from "../../../../error.ts";
import { isRecord, profileError, stringField } from "../../../flow/_internal/http/shared.ts";
import { exchangeError, parseTokenResponse } from "../../../flow/_internal/token-response.ts";
import type {
  CustomCompleteContext,
  CustomFlowResult,
  ProfileResult,
} from "../../../flow/types.ts";
import { grantedScopes } from "../shared.ts";
import type { AtprotoClient } from "./client.ts";
import { type DpopKey, dpopPost } from "./dpop.ts";
import type { FlowData, Resolvers } from "./flow.ts";
import {
  type AtprotoResolveOptions,
  assertDid,
  pdsOf,
  resolveDid,
  verifiedHandle,
} from "./identity.ts";
import { authorizationServerOf } from "./server.ts";

/** The account an AT Protocol sign-in proves: its DID, verified handle, PDS and authorization server. */
export interface AtprotoProfile {
  did: string;
  /** The handle the account claims, present only when it resolves back to the DID. */
  handle?: string;
  /** The origin of the account's PDS. */
  pds: string;
  /** The origin of the authorization server that signed the account in. */
  authorizationServer: string;
}

/**
 * The second leg: the callback's `iss` and code, the DPoP-bound token request, and the account the
 * token names, verified.
 */
export async function complete(
  context: CustomCompleteContext,
  provider: { client: AtprotoClient; resolvers: Resolvers },
): Promise<CustomFlowResult<AtprotoProfile>> {
  const { params } = context;
  const data = flowData(context.record.data);
  if (params.iss !== data.issuer) {
    throw new UnauthError(
      "[unauth/n] The callback does not belong to this sign-in.",
      "ERR_AUTHN_STATE_MISMATCH",
      { status: 401, cause: { provider: context.record.provider, reason: "issuer" } },
    );
  }
  if (params.code === undefined) {
    throw new UnauthError(
      "[unauth/n] The authorization server returned no authorization code.",
      "ERR_AUTHN_PROVIDER_REFUSED",
      { status: 401, cause: { error: "invalid_request" } },
    );
  }

  const answer = await dpopPost(
    data.tokenEndpoint,
    {
      grant_type: "authorization_code",
      code: params.code,
      code_verifier: data.verifier,
      redirect_uri: provider.client.redirectUri,
      client_id: provider.client.id,
    },
    {
      key: data.key,
      nonce: data.nonce,
      fetch: context.fetch,
      now: context.now,
      label: "token endpoint",
    },
  );
  const tokens = parseTokenResponse(answer, { tokenType: "DPoP" });
  if (!grantedScopes(tokens.scope).includes("atproto")) {
    throw exchangeError("The token endpoint granted no atproto scope.", { scope: tokens.scope });
  }
  const sub = stringField(answer.body, "sub");
  if (sub === undefined) throw exchangeError("The token endpoint named no account.", {});
  try {
    assertDid(sub);
  } catch (error) {
    throw exchangeError("The token endpoint named an account that is not a DID.", {
      cause: error,
    });
  }

  const profile = await verifiedProfile(sub, data, { ...context, ...provider.resolvers });
  return { identity: profile };
}

/**
 * The account the token names, checked the way the atproto profile requires: against the DID
 * the sign-in started from, or, started from a server, against the PDS the DID's document names
 * and the authorization server that PDS delegates to.
 */
async function verifiedProfile(
  sub: string,
  data: FlowData,
  options: AtprotoResolveOptions,
): Promise<ProfileResult<AtprotoProfile>> {
  let profile: AtprotoProfile;
  if (data.account) {
    const { account } = data;
    if (sub !== account.did) {
      throw profileError("The authorization server signed in another account than asked.", {
        expected: account.did,
        sub,
      });
    }
    profile = { did: sub, pds: account.pds, authorizationServer: data.issuer };
    if (account.handle !== undefined) profile.handle = account.handle;
  } else {
    let document: Awaited<ReturnType<typeof resolveDid>>;
    try {
      document = await resolveDid(sub, options);
    } catch (error) {
      throw profileError("The signed-in account's DID document could not be read.", error);
    }
    const pds = pdsOf(document, options);
    const issuer = await authorizationServerOf(pds, options);
    if (issuer !== data.issuer) {
      throw profileError("The signed-in account belongs to another authorization server.", {
        expected: data.issuer,
        issuer,
      });
    }
    profile = {
      did: sub,
      pds,
      authorizationServer: data.issuer,
      ...(await verifiedHandle(document, options)),
    };
  }
  const result: ProfileResult<AtprotoProfile> = { subject: sub, profile };
  if (profile.handle !== undefined) result.name = profile.handle;
  return result;
}

/** The sealed data of this sign-in, as `start` left it; anything else is a flow that is not ours. */
function flowData(data: Record<string, unknown> | undefined): FlowData {
  const issuer = stringField(data, "issuer");
  const tokenEndpoint = stringField(data, "tokenEndpoint");
  const verifier = stringField(data, "verifier");
  const key = data?.key;
  if (!issuer || !tokenEndpoint || !verifier || !isDpopKey(key)) {
    throw new UnauthError(
      "[unauth/n] The callback does not belong to this sign-in.",
      "ERR_AUTHN_STATE_MISMATCH",
      { status: 401, cause: { reason: "record" } },
    );
  }
  const result: FlowData = { issuer, tokenEndpoint, verifier, key };
  const nonce = stringField(data, "nonce");
  if (nonce !== undefined) result.nonce = nonce;
  const account = data?.account;
  if (isRecord(account)) {
    const did = stringField(account, "did");
    const pds = stringField(account, "pds");
    if (did === undefined || pds === undefined) {
      throw new UnauthError(
        "[unauth/n] The callback does not belong to this sign-in.",
        "ERR_AUTHN_STATE_MISMATCH",
        { status: 401, cause: { reason: "record" } },
      );
    }
    result.account = { did, pds };
    const handle = stringField(account, "handle");
    if (handle !== undefined) result.account.handle = handle;
  }
  return result;
}

function isDpopKey(value: unknown): value is DpopKey {
  return (
    typeof value === "object" &&
    value !== null &&
    Reflect.get(value, "kty") === "EC" &&
    Reflect.get(value, "crv") === "P-256" &&
    typeof Reflect.get(value, "d") === "string"
  );
}
