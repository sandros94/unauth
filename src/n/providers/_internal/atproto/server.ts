import { isUnauthError } from "../../../../error.ts";
import { assertSecureUrl, providerError } from "../../../flow/_internal/http/shared.ts";
import {
  type MetadataLoader,
  type MetadataOptions,
  assertDocument,
  assertIssuerDocument,
  defineMetadataLoader,
  requiredMember,
} from "../../../flow/_internal/cache/metadata.ts";
import { loginError } from "./identity.ts";

/** The atproto authorization server of an account, with the endpoints a sign-in uses. */
export interface AtprotoServer {
  /** The server's origin, which the callback's `iss` must equal. */
  issuer: string;
  authorizationEndpoint: string;
  parEndpoint: string;
  tokenEndpoint: string;
}

const PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER = "/.well-known/oauth-authorization-server";
const RESOURCE_LABEL = "PDS metadata";
const SERVER_LABEL = "authorization server metadata";

/** The values the atproto OAuth profile requires an authorization server's metadata to list. */
const REQUIRED_VALUES: [member: string, value: string][] = [
  ["response_types_supported", "code"],
  ["grant_types_supported", "authorization_code"],
  ["grant_types_supported", "refresh_token"],
  ["code_challenge_methods_supported", "S256"],
  ["token_endpoint_auth_methods_supported", "none"],
  ["token_endpoint_auth_methods_supported", "private_key_jwt"],
  ["token_endpoint_auth_signing_alg_values_supported", "ES256"],
  ["scopes_supported", "atproto"],
  ["dpop_signing_alg_values_supported", "ES256"],
];
/** The members the atproto OAuth profile requires to be `true`. */
const REQUIRED_TRUE = [
  "authorization_response_iss_parameter_supported",
  "require_pushed_authorization_requests",
  "client_id_metadata_document_supported",
];

/** The origin of the one authorization server a PDS's protected resource metadata names, kept ten minutes. */
export const authorizationServerOf: MetadataLoader<string> = /* @__PURE__ */ defineMetadataLoader({
  name: "atproto-resource",
  label: RESOURCE_LABEL,
  url: (pds) => `${pds}${PROTECTED_RESOURCE}`,
  parse: parseProtectedResource,
});

/** The metadata of an authorization server, checked against the atproto profile and kept ten minutes. */
export const serverMetadata: MetadataLoader<AtprotoServer> = /* @__PURE__ */ defineMetadataLoader({
  name: "atproto-server",
  label: SERVER_LABEL,
  url: (issuer) => `${issuer}${AUTHORIZATION_SERVER}`,
  parse: parseServerMetadata,
});

/** The authorization server of a PDS, with its metadata. */
export async function serverOfPds(pds: string, options: MetadataOptions): Promise<AtprotoServer> {
  return serverMetadata(await authorizationServerOf(pds, options), options);
}

/**
 * The authorization server behind a URL the user typed: a PDS (through its protected resource
 * metadata) or an authorization server itself. Neither is `ERR_AUTHN_LOGIN_INVALID`.
 */
export async function serverOfUrl(
  origin: string,
  options: MetadataOptions,
): Promise<AtprotoServer> {
  try {
    return await serverOfPds(origin, options);
  } catch (error) {
    if (!isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR") || error.cause.status !== 404) {
      throw loginError(`${origin} is not an atproto server.`, error);
    }
  }
  try {
    return await serverMetadata(origin, options);
  } catch (error) {
    throw loginError(`${origin} is not an atproto server.`, error);
  }
}

/** The one authorization server `document` names for `pds`, as an origin. */
function parseProtectedResource(document: unknown, pds: string): string {
  const url = `${pds}${PROTECTED_RESOURCE}`;
  const metadata = assertDocument(document, { url, label: RESOURCE_LABEL });
  const servers = Array.isArray(metadata.authorization_servers)
    ? metadata.authorization_servers
    : [];
  if (servers.length !== 1 || typeof servers[0] !== "string") {
    throw providerError(
      `The ${RESOURCE_LABEL} at ${url} must name exactly one authorization server.`,
      {
        reason: "malformed",
      },
    );
  }
  return originOf(servers[0], `The authorization server of ${pds}`);
}

/** `document` once it is `issuer`'s metadata and advertises what the atproto profile requires. */
function parseServerMetadata(document: unknown, issuer: string): AtprotoServer {
  const context = { issuer, url: `${issuer}${AUTHORIZATION_SERVER}`, label: SERVER_LABEL };
  const metadata = assertIssuerDocument(document, context);
  const endpoint = (name: string): string =>
    assertSecureUrl(requiredMember(metadata, name, context), { label: `${issuer} "${name}"` }).href;
  const includes = (name: string, value: string): boolean =>
    Array.isArray(metadata[name]) && metadata[name].includes(value);
  const notAtproto = (detail: string) =>
    providerError(`${issuer} is not an atproto authorization server: ${detail}.`, {
      reason: "malformed",
    });
  for (const [name, value] of REQUIRED_VALUES) {
    if (!includes(name, value)) throw notAtproto(`"${name}" lacks ${JSON.stringify(value)}`);
  }
  for (const name of REQUIRED_TRUE) {
    if (metadata[name] !== true) throw notAtproto(`"${name}" is not true`);
  }
  if (includes("token_endpoint_auth_signing_alg_values_supported", "none")) {
    throw notAtproto(`"token_endpoint_auth_signing_alg_values_supported" includes "none"`);
  }
  if (metadata.require_request_uri_registration === false) {
    throw notAtproto(`"require_request_uri_registration" is false`);
  }
  return {
    issuer,
    authorizationEndpoint: endpoint("authorization_endpoint"),
    parEndpoint: endpoint("pushed_authorization_request_endpoint"),
    tokenEndpoint: endpoint("token_endpoint"),
  };
}

/** `value` as an `https:` origin with no path; anything else is `ERR_AUTHN_PROVIDER_ERROR`. */
function originOf(value: string, label: string): string {
  let url: URL;
  try {
    url = assertSecureUrl(value, { label });
  } catch (error) {
    throw providerError(`${label} must be an https: URL, got ${JSON.stringify(value)}.`, {
      reason: "malformed",
      cause: error,
    });
  }
  if (url.href !== `${url.origin}/`) {
    throw providerError(`${label} must be an origin with no path, got ${JSON.stringify(value)}.`, {
      reason: "malformed",
    });
  }
  return url.origin;
}
