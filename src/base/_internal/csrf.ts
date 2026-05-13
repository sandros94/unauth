import { hmac } from "unsecure";

/** Framework-agnostic CSRF configuration. */
export interface CsrfConfig {
  /** Cookie name for the CSRF token. @default "csrf" */
  name?: string;
  /** Header name to validate against. @default "x-csrf-token" */
  headerName?: string;
  /** HTTP methods that require CSRF validation. @default ["POST", "PUT", "DELETE", "PATCH"] */
  protectedMethods?: string[];
}

/** Mints a fresh CSRF token: `HMAC(secret, randomUUID())`. */
export function createCsrfToken(secret: string): Promise<string> {
  return hmac(secret, crypto.getRandomValues(new Uint8Array(16)).toString());
}
