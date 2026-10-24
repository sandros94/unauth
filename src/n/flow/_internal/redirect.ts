import { configError } from "./http/shared.ts";

/**
 * The `redirect_uri` of a flow: the configured one, else the request's own URL (without its query)
 * when the request's origin is one of `trustedOrigins`. Anything else is a configuration error:
 * a redirect URI is never guessed from an untrusted Host.
 */
export function resolveRedirectUri(
  request: Request,
  options: { redirectUri?: string; trustedOrigins?: string[] },
): string {
  if (options.redirectUri !== undefined) return options.redirectUri;
  const url = new URL(request.url);
  const trusted = (options.trustedOrigins ?? []).some((origin) => originOf(origin) === url.origin);
  if (!trusted) {
    throw configError(
      options.trustedOrigins
        ? `The request origin ${url.origin} is not in "trustedOrigins"; set "redirectUri" or trust it.`
        : `Set "redirectUri", or "trustedOrigins" to derive it from the request.`,
    );
  }
  return `${url.origin}${url.pathname}`;
}

/** `redirect` when it is a same-origin path (`/…`, not `//…` or `/\…`), else `undefined`. */
export function safeRedirect(redirect: string | undefined): string | undefined {
  if (typeof redirect !== "string" || !redirect.startsWith("/")) return undefined;
  // `//host`, `/\host` and `/<tab>/host` parse as another origin, so the origin check refuses them.
  const base = "https://unauth.invalid";
  const url = new URL(redirect, base);
  if (url.origin !== base) return undefined;
  // Dot segments are removed after parsing (`/.//host` becomes `//host`): check the result too.
  if (url.pathname.startsWith("//")) return undefined;
  const result = `${url.pathname}${url.search}${url.hash}`;
  return new URL(result, base).origin === base ? result : undefined;
}

/** The origin of `origin` when it is an absolute URL, else `undefined`. */
export function originOf(origin: string): string | undefined {
  try {
    return new URL(origin).origin;
  } catch {
    return undefined;
  }
}
