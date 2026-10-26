import { isUnauthError } from "../../../../error.ts";
import { assertRemoteUrl, providerError } from "../../../flow/_internal/http/shared.ts";
import {
  type MetadataLoader,
  type MetadataOptions,
  assertDocument,
  assertIssuerDocument,
  defineMetadataLoader,
  requiredMember,
} from "../../../flow/_internal/cache/metadata.ts";
import { loginHintError } from "./identity.ts";

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

/** What a server document's URLs are held to: `https:`, or any `http(s):` for a local setup. */
export interface UrlPolicy {
  allowHttp?: boolean;
}

const loadAuthorizationServer: MetadataLoader<string> = /* @__PURE__ */ defineMetadataLoader({
  name: "atproto-resource",
  label: RESOURCE_LABEL,
  url: (pds) => `${pds}${PROTECTED_RESOURCE}`,
  parse: parseProtectedResource,
});

const loadServerMetadata: MetadataLoader<AtprotoServer> = /* @__PURE__ */ defineMetadataLoader({
  name: "atproto-server",
  label: SERVER_LABEL,
  url: (issuer) => `${issuer}${AUTHORIZATION_SERVER}`,
  parse: parseServerMetadata,
});

/**
 * The origin of the one authorization server a PDS's protected resource metadata names, kept ten
 * minutes; one that is not `https:` (nor `http:` under `allowHttp`) is `ERR_AUTHN_PROVIDER_ERROR`.
 */
export async function authorizationServerOf(
  pds: string,
  options: MetadataOptions & UrlPolicy,
): Promise<string> {
  const issuer = await loadAuthorizationServer(pds, options);
  assertRemoteUrl(issuer, {
    label: `The authorization server of ${pds}`,
    allowHttp: options.allowHttp,
  });
  return issuer;
}

/**
 * The metadata of an authorization server, checked against the atproto profile and kept ten
 * minutes; an endpoint that is not `https:` (nor `http:` under `allowHttp`) is
 * `ERR_AUTHN_PROVIDER_ERROR`.
 */
export async function serverMetadata(
  issuer: string,
  options: MetadataOptions & UrlPolicy,
): Promise<AtprotoServer> {
  const server = await loadServerMetadata(issuer, options);
  for (const name of ["authorizationEndpoint", "parEndpoint", "tokenEndpoint"] as const) {
    assertRemoteUrl(server[name], { label: `${issuer} "${name}"`, allowHttp: options.allowHttp });
  }
  return server;
}

/** The authorization server of a PDS, with its metadata. */
export async function serverOfPds(
  pds: string,
  options: MetadataOptions & UrlPolicy,
): Promise<AtprotoServer> {
  return serverMetadata(await authorizationServerOf(pds, options), options);
}

/**
 * The authorization server behind a URL the user typed: a PDS (through its protected resource
 * metadata) or an authorization server itself. Neither is `ERR_AUTHN_LOGIN_HINT_INVALID`.
 */
export async function serverOfUrl(
  origin: string,
  options: MetadataOptions & UrlPolicy,
): Promise<AtprotoServer> {
  try {
    return await serverOfPds(origin, options);
  } catch (error) {
    if (!isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR") || error.cause.status !== 404) {
      throw loginHintError(`${origin} is not an atproto server.`, error);
    }
  }
  try {
    return await serverMetadata(origin, options);
  } catch (error) {
    throw loginHintError(`${origin} is not an atproto server.`, error);
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
  // Shape only: whether plain http: is acceptable is the caller's policy, checked at every use.
  const endpoint = (name: string): string =>
    assertRemoteUrl(requiredMember(metadata, name, context), {
      label: `${issuer} "${name}"`,
      allowHttp: true,
    }).href;
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

/** `value` as an `http(s):` origin with no path; anything else is `ERR_AUTHN_PROVIDER_ERROR`. */
function originOf(value: string, label: string): string {
  const url = assertRemoteUrl(value, { label, allowHttp: true });
  if (url.href !== `${url.origin}/`) {
    throw providerError(`${label} must be an origin with no path, got ${JSON.stringify(value)}.`, {
      reason: "malformed",
    });
  }
  return url.origin;
}
