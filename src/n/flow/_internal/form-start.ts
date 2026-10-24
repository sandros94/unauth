import { UnauthError, type UnauthErrorCauseMap } from "../../../error.ts";
import { originOf } from "./redirect.ts";

type Refusal = UnauthErrorCauseMap["ERR_AUTHN_CROSS_SITE_START"]["reason"];

/**
 * Throws `ERR_AUTHN_CROSS_SITE_START` (403) unless `request` is a form submission from the
 * application's own pages: a `POST` whose `Origin` is the request's origin or one of
 * `trustedOrigins`, and whose `Sec-Fetch-Site`, when the browser sends one for the request's own
 * origin, is `same-origin`. A `GET` never passes: a browser sends `Sec-Fetch-Site: none` for a
 * pasted URL or a link opened from a mail client, and that navigation still carries `SameSite=Lax`
 * cookies, so it proves nothing about who chose the request's parameters.
 */
export function assertFormStart(request: Request, trustedOrigins: string[] | undefined): void {
  const reason = refusal(request, trustedOrigins ?? []);
  if (reason === undefined) return;
  throw new UnauthError(
    "[unauth/n] Start the sign-in from this site.",
    "ERR_AUTHN_CROSS_SITE_START",
    { status: 403, cause: { reason } },
  );
}

function refusal(request: Request, trustedOrigins: string[]): Refusal | undefined {
  if (request.method !== "POST") return "method";
  const origin = request.headers.get("origin");
  const self = new URL(request.url).origin;
  const trusted =
    origin !== null &&
    (origin === self || trustedOrigins.some((candidate) => originOf(candidate) === origin));
  if (!trusted) return "origin";
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && origin === self) return "cross-site";
  return undefined;
}
