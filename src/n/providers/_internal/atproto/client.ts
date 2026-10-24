import { assertSecureUrl, configError } from "../../../flow/_internal/http/shared.ts";
import { originOf } from "../../../flow/_internal/redirect.ts";

/** An AT Protocol provider's client. */
export interface AtprotoClient {
  id: string;
  /** The callback as registered: the configured one, or its `devOrigins` host mapped to `127.0.0.1`. */
  redirectUri: string;
  /** Whether `id` is the atproto development client (`http://localhost?…`), which publishes no metadata document. */
  development: boolean;
  /** The document to serve as JSON at `id`; absent for the development client, which has none. */
  metadata?: AtprotoClientMetadata;
}

/** The client metadata document (atproto OAuth profile) an app publishes at its `clientId`. */
export interface AtprotoClientMetadata {
  client_id: string;
  application_type: "web";
  grant_types: ["authorization_code"];
  response_types: ["code"];
  redirect_uris: [string];
  scope: string;
  dpop_bound_access_tokens: true;
  token_endpoint_auth_method: "none";
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  tos_uri?: string;
  policy_uri?: string;
}

/** What {@link resolveClient} reads from the provider's config. */
export interface AtprotoClientConfig {
  clientId?: string;
  redirectUri: string;
  scopes?: string[];
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
}

const LOOPBACK_IPS = new Set(["127.0.0.1", "[::1]"]);
const LOOPBACK_HOSTS = new Set([...LOOPBACK_IPS, "localhost"]);

/**
 * The provider's client. A published one needs an `https:` client id without a port and an
 * `https:` callback. An `http:` client id on a loopback host, or none with a loopback callback,
 * is the spec's development client, whose callback must be on a loopback IP: a callback on one of
 * `devOrigins` (`http://localhost:3000`) is mapped to `127.0.0.1` there.
 */
export function resolveClient(config: AtprotoClientConfig, devOrigins: string[]): AtprotoClient {
  const insecureHosts = devOrigins.map((origin) => new URL(origin).hostname);
  const redirect = assertSecureUrl(config.redirectUri, {
    label: `The AT Protocol "redirectUri"`,
    insecureHosts,
  });
  const id =
    config.clientId === undefined
      ? undefined
      : assertSecureUrl(config.clientId, {
          label: `The AT Protocol "clientId"`,
          insecureHosts,
        });
  const published = id !== undefined && id.protocol === "https:";

  if (published) {
    if (id.port !== "") {
      throw configError(
        `The AT Protocol "clientId" must be an https: URL without a port, got ${JSON.stringify(config.clientId)}.`,
      );
    }
    if (redirect.protocol !== "https:") {
      throw configError(
        `The AT Protocol "redirectUri" of a published client must be https:, got ${JSON.stringify(config.redirectUri)}; an http: loopback callback belongs to the development client.`,
      );
    }
    return {
      id: id.href,
      redirectUri: redirect.href,
      development: false,
      metadata: metadataOf(config, { id: id.href, redirectUri: redirect.href }),
    };
  }

  if (id !== undefined && !LOOPBACK_HOSTS.has(id.hostname) && !devOrigins.includes(id.origin)) {
    throw configError(
      `The AT Protocol "clientId" must be an https: URL, or an http: one on a loopback host for the development client, got ${JSON.stringify(config.clientId)}.`,
    );
  }
  if (redirect.protocol !== "http:") {
    throw configError(
      `The AT Protocol development client needs an http: "redirectUri" on 127.0.0.1 or [::1], got ${JSON.stringify(config.redirectUri)}; set "clientId" to the client metadata document's URL for a published client.`,
    );
  }
  if (!LOOPBACK_IPS.has(redirect.hostname)) {
    if (!devOrigins.includes(redirect.origin)) {
      throw configError(
        `The AT Protocol development client's "redirectUri" must be on 127.0.0.1 or [::1] (the atproto profile refuses "${redirect.hostname}", RFC 8252 §8.3); list its origin in "devOrigins" to have it mapped, got ${JSON.stringify(config.redirectUri)}.`,
      );
    }
    redirect.hostname = "127.0.0.1";
  }
  const query = new URLSearchParams({
    redirect_uri: redirect.href,
    scope: (config.scopes ?? ["atproto"]).join(" "),
  });
  return { id: `http://localhost?${query}`, redirectUri: redirect.href, development: true };
}

/**
 * Where a start on one of `devOrigins` is sent first: the same URL on the callback's host, port
 * and all, so the flow cookie is set where the callback returns.
 */
export function relocation(
  request: Request,
  options: { client: AtprotoClient; devOrigins: string[] },
): URL | undefined {
  if (!options.client.development) return undefined;
  const url = new URL(request.url);
  const callback = new URL(options.client.redirectUri);
  if (url.hostname === callback.hostname || !options.devOrigins.includes(url.origin)) {
    return undefined;
  }
  url.hostname = callback.hostname;
  return url;
}

/** Whether `given` is the registered callback, or the same URL on one of `devOrigins`. */
export function sameCallback(given: string, registered: string, devOrigins: string[]): boolean {
  if (given === registered) return true;
  try {
    const url = new URL(given);
    if (!devOrigins.includes(url.origin)) return false;
    url.hostname = new URL(registered).hostname;
    return url.href === registered;
  } catch {
    return false;
  }
}

/** The published client's document, from its config and the client it resolved to. */
function metadataOf(
  config: AtprotoClientConfig,
  client: { id: string; redirectUri: string },
): AtprotoClientMetadata {
  const document: AtprotoClientMetadata = {
    client_id: client.id,
    application_type: "web",
    grant_types: ["authorization_code"],
    response_types: ["code"],
    redirect_uris: [client.redirectUri],
    scope: (config.scopes ?? ["atproto"]).join(" "),
    dpop_bound_access_tokens: true,
    token_endpoint_auth_method: "none",
  };
  if (config.clientName) document.client_name = config.clientName;
  if (config.clientUri) document.client_uri = config.clientUri;
  if (config.logoUri) document.logo_uri = config.logoUri;
  if (config.tosUri) document.tos_uri = config.tosUri;
  if (config.policyUri) document.policy_uri = config.policyUri;
  return document;
}

/** The `devOrigins` entries as origins; `ERR_UNAUTH_CONFIG_INVALID` for one that is not an absolute URL. */
export function devOriginsOf(entries: string[] | undefined): string[] {
  return (entries ?? []).map((entry) => {
    const origin = originOf(entry);
    if (origin === undefined) {
      throw configError(
        `The AT Protocol "devOrigins" entries must be origins such as "http://localhost:3000", got ${JSON.stringify(entry)}.`,
      );
    }
    return origin;
  });
}
