import { type H3Event, getCookie, setCookie, getHeader, createError } from "h3v1";
import { secureCompare } from "unsecure";
import type { CookieSerializeOptions } from "cookie-esv1";
import {
  DEFAULT_CSRF_NAME,
  DEFAULT_CSRF_HEADER,
  DEFAULT_PROTECTED_METHODS,
  DEFAULT_CSRF_COOKIE,
} from "../_internal/defaults.ts";
import { type CsrfConfig, createCsrfToken } from "../_internal/csrf.ts";

export type { CsrfConfig };

/** h3v1-specific CSRF options. */
export interface H3CsrfOptions extends CsrfConfig {
  /** Secret for HMAC-based token generation. */
  secret: string;
  /** Cookie serialization options. `httpOnly` is always forced to `false`. */
  cookie?: CookieSerializeOptions & { chunkMaxLength?: number };
}

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
 * app.use("/form", defineEventHandler({ onRequest: csrf, handler }));
 * ```
 */
export function defineCsrf(options: H3CsrfOptions): (event: H3Event) => Promise<void> {
  const cookieName = options.name ?? DEFAULT_CSRF_NAME;
  const headerName = options.headerName ?? DEFAULT_CSRF_HEADER;
  const protectedMethods = options.protectedMethods ?? DEFAULT_PROTECTED_METHODS;
  const cookieOptions = {
    ...DEFAULT_CSRF_COOKIE,
    ...options.cookie,
    httpOnly: false,
  } as const;

  return async (event: H3Event): Promise<void> => {
    const method = event.method.toUpperCase();

    if (protectedMethods.includes(method)) {
      const cookieToken = getCookie(event, cookieName);
      const headerToken = getHeader(event, headerName);

      if (!cookieToken || !headerToken) {
        throw createError({ statusCode: 403, statusMessage: "CSRF token missing" });
      }

      if (!secureCompare(cookieToken, headerToken)) {
        throw createError({ statusCode: 403, statusMessage: "CSRF token mismatch" });
      }
    } else {
      const existing = getCookie(event, cookieName);
      if (!existing) {
        const token = await createCsrfToken(options.secret);
        setCookie(event, cookieName, token, cookieOptions);
      }
    }
  };
}
