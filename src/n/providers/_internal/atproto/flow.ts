import { UnauthError } from "../../../../error.ts";
import {
  assertSecureUrl,
  configError,
  providerError,
  stringField,
} from "../../../flow/_internal/http/shared.ts";
import { createPkce } from "../../../flow/random.ts";
import type { CustomStart, CustomStartContext } from "../../../flow/types.ts";
import { type AtprotoClient, relocation, sameCallback } from "./client.ts";
import { type DpopKey, createDpopKey, dpopPost } from "./dpop.ts";
import {
  type AtprotoIdentity,
  type AtprotoResolveOptions,
  parseLoginHint,
  resolveIdentity,
} from "./identity.ts";
import { type AtprotoServer, serverOfPds, serverOfUrl } from "./server.ts";

const DEFAULT_DNS_RESOLVER = "https://cloudflare-dns.com/dns-query";
const DEFAULT_PLC_DIRECTORY = "https://plc.directory";

/**
 * Where accounts are resolved: the DNS-over-HTTPS resolver and the `did:plc` directory; and
 * whether the URLs their documents name may use plain `http:`.
 */
export interface Resolvers {
  dnsResolver: string;
  plcDirectory: string;
  allowHttp: boolean;
}

/** The resolvers a provider config names, defaulted and checked to be `https:`. */
export function resolversOf(config: {
  dnsResolver?: string;
  plcDirectory?: string;
  allowHttp?: boolean;
}): Resolvers {
  const resolvers = {
    dnsResolver: config.dnsResolver ?? DEFAULT_DNS_RESOLVER,
    plcDirectory: config.plcDirectory ?? DEFAULT_PLC_DIRECTORY,
    allowHttp: config.allowHttp ?? false,
  };
  assertSecureUrl(resolvers.dnsResolver, { label: `The AT Protocol "dnsResolver"` });
  assertSecureUrl(resolvers.plcDirectory, { label: `The AT Protocol "plcDirectory"` });
  return resolvers;
}

/** What `start` seals for `complete`. */
export interface FlowData {
  issuer: string;
  tokenEndpoint: string;
  verifier: string;
  key: DpopKey;
  nonce?: string;
  /** The account the sign-in started from, which the token must then name. */
  account?: AtprotoIdentity;
}

/** PAR parameters the flow owns; `params` naming them are dropped. */
const RESERVED = new Set([
  "client_id",
  "response_type",
  "scope",
  "state",
  "redirect_uri",
  "code_challenge",
  "code_challenge_method",
  "login_hint",
]);

/**
 * The first leg: the account or server `loginHint` names is resolved, the request is pushed (PAR) with
 * PKCE and a DPoP proof, and the user is sent to the authorization endpoint; a start on one of
 * `devOrigins` is relocated first.
 */
export async function start(
  context: CustomStartContext,
  provider: {
    client: AtprotoClient;
    scopes: string[];
    resolvers: Resolvers;
    devOrigins: string[];
  },
): Promise<CustomStart> {
  const { client, resolvers } = provider;
  const relocate = relocation(context.request, { client, devOrigins: provider.devOrigins });
  if (relocate) return { relocate };
  if (!sameCallback(context.redirectUri, client.redirectUri, provider.devOrigins)) {
    throw configError(
      `The AT Protocol sign-in runs at ${context.redirectUri}, but the provider's "redirectUri" is ${client.redirectUri}; they must be the same URL.`,
    );
  }
  const loginHint = context.loginHint?.trim();
  if (!loginHint) {
    throw new UnauthError(
      "[unauth/n] Enter a handle, a DID or a server to sign in.",
      "ERR_AUTHN_LOGIN_HINT_REQUIRED",
      { status: 400 },
    );
  }
  const scopes = context.scopes ?? provider.scopes;
  if (!scopes.includes("atproto")) {
    throw configError(`An AT Protocol sign-in needs the "atproto" scope.`);
  }
  const options: AtprotoResolveOptions = { ...context, ...resolvers };
  const target = parseLoginHint(loginHint);
  let identity: AtprotoIdentity | undefined;
  let server: AtprotoServer;
  if (target.kind === "account") {
    identity = await resolveIdentity(target.input, options);
    server = await serverOfPds(identity.pds, options);
  } else {
    server = await serverOfUrl(target.url, options);
  }

  const pkce = await createPkce();
  const key = await createDpopKey();
  const form: Record<string, string> = {};
  for (const [name, value] of Object.entries(context.params ?? {})) {
    if (!RESERVED.has(name)) form[name] = value;
  }
  Object.assign(form, {
    client_id: client.id,
    response_type: "code",
    scope: scopes.join(" "),
    state: context.record.state,
    redirect_uri: client.redirectUri,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  });
  if (target.kind === "account") form.login_hint = target.input;

  const pushed = await dpopPost(server.parEndpoint, form, {
    key,
    fetch: context.fetch,
    now: context.now,
    label: "pushed authorization request endpoint",
  });
  const refusal = stringField(pushed.body, "error");
  if (refusal !== undefined) {
    throw new UnauthError(
      "[unauth/n] The authorization server did not accept the sign-in request.",
      "ERR_AUTHN_PROVIDER_REFUSED",
      {
        status: 401,
        cause: {
          error: refusal,
          error_description: stringField(pushed.body, "error_description"),
          error_uri: stringField(pushed.body, "error_uri"),
        },
      },
    );
  }
  if (!pushed.ok) {
    throw providerError(
      `${server.issuer} answered ${pushed.status} to the pushed authorization request.`,
      { reason: "status", status: pushed.status },
    );
  }
  const requestUri = stringField(pushed.body, "request_uri");
  if (requestUri === undefined) {
    throw providerError(`${server.issuer} pushed the request but sent no request_uri.`, {
      reason: "malformed",
      status: pushed.status,
    });
  }

  const url = new URL(server.authorizationEndpoint);
  url.searchParams.set("client_id", client.id);
  url.searchParams.set("request_uri", requestUri);
  const data: FlowData = {
    issuer: server.issuer,
    tokenEndpoint: server.tokenEndpoint,
    verifier: pkce.verifier,
    key,
  };
  if (pushed.nonce !== undefined) data.nonce = pushed.nonce;
  if (identity) data.account = identity;
  return { url, data: { ...data } };
}
