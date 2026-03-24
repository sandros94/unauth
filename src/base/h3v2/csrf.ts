import type { H3Event } from "h3v2";
import { hmac } from "unsecure";
import { secureCompare } from "unsecure";
import type { CookieSerializeOptions } from "cookie-esv2";

/** Framework-agnostic CSRF configuration. */
export interface CsrfConfig {
  /** Cookie name for the CSRF token. @default "csrf" */
  name?: string;
  /** Header name to validate against. @default "x-csrf-token" */
  headerName?: string;
  /** HTTP methods that require CSRF validation. @default ["POST", "PUT", "DELETE", "PATCH"] */
  protectedMethods?: string[];
}

/** h3v2-specific CSRF options. */
export interface H3CsrfOptions extends CsrfConfig {
  /** Secret for HMAC-based token generation. */
  secret: string;
  /** Cookie serialization options. `httpOnly` is always forced to `false`. */
  cookie?: CookieSerializeOptions & { chunkMaxLength?: number };
}

const DEFAULT_PROTECTED_METHODS = ["POST", "PUT", "DELETE", "PATCH"];

/**
 * Creates a CSRF protection middleware using the double-submit cookie pattern.
 *
 * - **Safe methods** (GET, HEAD, OPTIONS): sets a CSRF cookie if absent.
 *   The token is `HMAC(secret, randomUUID())`.
 * - **Protected methods** (POST, PUT, DELETE, PATCH): validates the request
 *   header matches the cookie using constant-time comparison.
 *
 * The cookie is non-httpOnly so client JavaScript can read and echo it
 * in request headers.
 *
 * @example
 * ```ts
 * const csrf = defineCsrf({ secret: process.env.CSRF_SECRET! });
 *
 * app.get("/form", handler, { middleware: [csrf] });
 * app.post("/form", handler, { middleware: [csrf] });
 * ```
 */
export function defineCsrf(options: H3CsrfOptions): (event: H3Event) => Promise<void> {
  const cookieName = options.name ?? "csrf";
  const headerName = options.headerName ?? "x-csrf-token";
  const protectedMethods = options.protectedMethods ?? DEFAULT_PROTECTED_METHODS;
  const cookieOptions = {
    secure: true,
    sameSite: "lax",
    path: "/",
    ...options.cookie,
    httpOnly: false,
  } as const;

  return async (event: H3Event): Promise<void> => {
    const { getCookie, setCookie, HTTPError } = await import("h3v2");

    const method = event.req.method.toUpperCase();

    if (protectedMethods.includes(method)) {
      const cookieToken = getCookie(event, cookieName);
      const headerToken = event.req.headers.get(headerName);

      if (!cookieToken || !headerToken) {
        throw new HTTPError("CSRF token missing", { status: 403 });
      }

      if (!secureCompare(cookieToken, headerToken)) {
        throw new HTTPError("CSRF token mismatch", { status: 403 });
      }
    } else {
      const existing = getCookie(event, cookieName);
      if (!existing) {
        const nonce = crypto.randomUUID();
        const token = await hmac(options.secret, nonce);
        setCookie(event, cookieName, token, cookieOptions);
      }
    }
  };
}
