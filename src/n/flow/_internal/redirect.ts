import { UnauthError } from "../../../error.ts";
import { configError } from "./http/shared.ts";

/**
 * The `redirect_uri` of a flow: the configured one, else the request's own URL (without its query)
 * when the request's origin is one of `trustedOrigins`. Without either it is a configuration error;
 * a request from any other origin is refused with `ERR_AUTHN_ORIGIN_UNTRUSTED` (421): a redirect
 * URI is never guessed from an untrusted Host.
 */
export function resolveRedirectUri(
  request: Request,
  options: { redirectUri?: string; trustedOrigins?: string[] },
): string {
  if (options.redirectUri !== undefined) return options.redirectUri;
  if (!options.trustedOrigins?.length) {
    throw configError(`Set "redirectUri", or "trustedOrigins" to derive it from the request.`);
  }
  const url = new URL(request.url);
  if (!options.trustedOrigins.some((origin) => originOf(origin) === url.origin)) {
    throw untrustedOrigin(url.origin);
  }
  return `${url.origin}${url.pathname}`;
}

/** `ERR_AUTHN_ORIGIN_UNTRUSTED` (421): the request reached the sign-in on `origin`, which is not one of `trustedOrigins`. */
export function untrustedOrigin(origin: string): UnauthError<"ERR_AUTHN_ORIGIN_UNTRUSTED"> {
  return new UnauthError(
    "[unauth/n] This sign-in is not served on this address.",
    "ERR_AUTHN_ORIGIN_UNTRUSTED",
    { status: 421, cause: { origin } },
  );
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
