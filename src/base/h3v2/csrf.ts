import type { H3Event } from "h3v2";
import { hmac } from "unsecure";
import { secureCompare } from "unsecure";
import type { CookieSerializeOptions } from "cookie-esv2";

export interface CsrfConfig {
  name?: string;
  headerName?: string;
  protectedMethods?: string[];
}

export interface H3CsrfOptions extends CsrfConfig {
  secret: string;
  cookie?: CookieSerializeOptions & { chunkMaxLength?: number };
}

const DEFAULT_PROTECTED_METHODS = ["POST", "PUT", "DELETE", "PATCH"];

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
