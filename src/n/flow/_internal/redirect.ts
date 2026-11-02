import { UnauthError } from "../../../error.ts";
import { configError } from "./http/shared.ts";

/**
 * The `redirect_uri` of a flow: the configured one, else the request's own URL (without its query)
 * when the request's origin is one of `trustedOrigins`. Without either it is a configuration error;
 * a request from any other origin is refused with `ERR_AUTHN_ORIGIN_UNTRUSTED` (421): a redirect
 * URI is never guessed from an untrusted Host. Once `trustedOrigins` are listed, a configured one
 * is used only on those origins and the callback's (its own, or the provider's `registered` one,
 * where a relocated start runs), 421 otherwise; without them it is used whatever the request's
 * origin, which a proxy may hide.
 */
export function resolveRedirectUri(
  request: Request,
  options: { redirectUri?: string; trustedOrigins?: string[]; registered?: string },
): string {
  const { redirectUri, trustedOrigins = [], registered } = options;
  if (redirectUri === undefined && trustedOrigins.length === 0) {
    throw configError(`Set "redirectUri", or "trustedOrigins" to derive it from the request.`);
  }
  if (redirectUri !== undefined && trustedOrigins.length === 0) return redirectUri;
  const url = new URL(request.url);
  const accepted = [...trustedOrigins, redirectUri, registered].filter((o) => o !== undefined);
  if (!accepted.some((origin) => originOf(origin) === url.origin)) {
    throw untrustedOrigin(url.origin);
  }
  return redirectUri ?? `${url.origin}${url.pathname}`;
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
