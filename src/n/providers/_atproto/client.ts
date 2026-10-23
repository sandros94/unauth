import { assertSecureUrl, configError } from "../../flow/_http.ts";

/** An AT Protocol provider's client. */
export interface AtprotoClient {
  id: string;
  /** The callback as registered: the configured one, or its `devHosts` host mapped to `127.0.0.1`. */
  redirectUri: string;
  /** Whether `id` is the development client, which publishes no metadata document. */
  loopback: boolean;
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
/** Carries the `devHosts` host a relocated start came from, so the sign-in returns there. */
const FROM_PARAM = "unauth_from";

/**
 * The provider's client. A published one needs an `https:` client id without a port and an
 * `https:` callback. An `http:` client id on a loopback host, or none with a loopback callback,
 * is the spec's development client, whose callback must be on a loopback IP: a `devHosts` host
 * (`localhost`) is mapped to `127.0.0.1` there.
 */
export function resolveClient(config: AtprotoClientConfig, devHosts: string[]): AtprotoClient {
  const redirect = assertSecureUrl(config.redirectUri, {
    label: `The AT Protocol "redirectUri"`,
    insecureHosts: devHosts,
  });
  const id =
    config.clientId === undefined
      ? undefined
      : assertSecureUrl(config.clientId, {
          label: `The AT Protocol "clientId"`,
          insecureHosts: devHosts,
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
      loopback: false,
      metadata: metadataOf(config, { id: id.href, redirectUri: redirect.href }),
    };
  }

  if (id !== undefined && !LOOPBACK_HOSTS.has(id.hostname) && !devHosts.includes(id.hostname)) {
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
    if (!devHosts.includes(redirect.hostname)) {
      throw configError(
        `The AT Protocol development client's "redirectUri" must be on 127.0.0.1 or [::1] (the atproto profile refuses "${redirect.hostname}", RFC 8252 §8.3); list it in "devHosts" to have it mapped, got ${JSON.stringify(config.redirectUri)}.`,
      );
    }
    redirect.hostname = "127.0.0.1";
  }
  const query = new URLSearchParams({
    redirect_uri: redirect.href,
    scope: (config.scopes ?? ["atproto"]).join(" "),
  });
  return { id: `http://localhost?${query}`, redirectUri: redirect.href, loopback: true };
}

/**
 * Where a start on a `devHosts` host is sent first: the same URL on the callback's host, port and
 * all, so the flow cookie is set where the callback returns (what the official browser client does).
 */
export function relocation(
  request: Request,
  options: { client: AtprotoClient; devHosts: string[] },
): URL | undefined {
  if (!options.client.loopback) return undefined;
  const url = new URL(request.url);
  const callback = new URL(options.client.redirectUri);
  if (url.hostname === callback.hostname || !options.devHosts.includes(url.hostname)) {
    return undefined;
  }
  url.hostname = callback.hostname;
  url.searchParams.set(FROM_PARAM, new URL(request.url).hostname);
  return url;
}

/** The `devHosts` host a relocated start names as where it came from; anything else is ignored. */
export function returnHostOf(
  request: Request,
  options: { client: AtprotoClient; devHosts: string[] },
): string | undefined {
  if (!options.client.loopback) return undefined;
  const from = new URL(request.url).searchParams.get(FROM_PARAM);
  if (from === null || !options.devHosts.includes(from)) return undefined;
  return from === new URL(options.client.redirectUri).hostname ? undefined : from;
}

/** Whether `given` is the registered callback, or the same URL on a `devHosts` host. */
export function sameCallback(given: string, registered: string, devHosts: string[]): boolean {
  if (given === registered) return true;
  try {
    const url = new URL(given);
    if (!devHosts.includes(url.hostname)) return false;
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
