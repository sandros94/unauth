/** Options of {@link isPublicServer}. */
export interface PublicServerOptions {
  /** Relaxations of the default policy; nothing here can make it stricter (wrap the predicate for that). */
  allow?: {
    /** Plain `http:` as well as `https:`. */
    http?: boolean;
    /** An IPv4 or IPv6 address as the host. */
    ipLiterals?: boolean;
    /** A host without a dot, such as `intranet`. */
    singleLabel?: boolean;
    /** Names reached despite the special-use list, such as `[".local"]`; the rest of the list still applies. */
    suffixes?: string[];
  };
}

/** The special-use TLDs a public server is never under: the ones the atproto handle spec disallows. */
export const SPECIAL_USE_TLDS: readonly string[] = [
  "alt",
  "arpa",
  "example",
  "internal",
  "invalid",
  "local",
  "localhost",
  "onion",
];

const SPECIAL_USE = SPECIAL_USE_TLDS.map((tld) => `.${tld}`);

/**
 * Whether `url` names a server on the public internet, by its shape alone: `https:`, no
 * credentials, a host name with a dot that is no IP literal and ends in no special-use name
 * (`.local`, `.internal`, `localhost`…). It is the policy `defineAtprotoProvider` applies
 * by default to the servers a stranger's input or documents name. A public name can still resolve
 * to a private address: the wall against that is the deployment's `fetch`, the `fetch` option of
 * `startFlow` and `completeFlow`.
 *
 * @example
 * isPublicServer(url, { allow: { suffixes: [".local"] } });
 * @example
 * const isServerAllowed = (url: URL) => isPublicServer(url) && url.hostname.endsWith(".bsky.network");
 */
export function isPublicServer(url: string | URL, options: PublicServerOptions = {}): boolean {
  const parsed = parseUrl(url);
  if (parsed === undefined || parsed.username !== "" || parsed.password !== "") return false;
  const allow = options.allow ?? {};
  if (parsed.protocol !== "https:" && !(allow.http && parsed.protocol === "http:")) return false;
  const host = parsed.hostname.replace(/\.$/, "").toLowerCase();
  if (host.startsWith("[") || /^\d+(\.\d+){3}$/.test(host)) return allow.ipLiterals === true;
  const name = `.${host}`;
  if (SPECIAL_USE.some((suffix) => name.endsWith(suffix)) && !allowedSuffix(name, allow.suffixes)) {
    return false;
  }
  return host.includes(".") || allow.singleLabel === true;
}

function allowedSuffix(name: string, suffixes: string[] = []): boolean {
  return suffixes.some((suffix) => {
    const lower = suffix.toLowerCase();
    return name.endsWith(lower.startsWith(".") ? lower : `.${lower}`);
  });
}

function parseUrl(url: string | URL): URL | undefined {
  if (url instanceof URL) return url;
  try {
    return new URL(url);
  } catch {
    return undefined;
  }
}
