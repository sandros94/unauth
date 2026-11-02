import { isJWTError } from "unjwt/error";
import { configError } from "./shared.ts";

/**
 * The key lookup's own failure when a token read ended with `error` there: what the application's
 * `onKeyLookup` threw, as it is, or unjwt's `ERR_JWK_INVALID` for a key it returned that cannot be
 * used. `undefined` for any other end of a read: the token is refused.
 */
export function keyLookupFailure(error: unknown): { error: unknown } | undefined {
  return isJWTError(error, "ERR_SESSION_READ_FAILED") ? { error: error.cause } : undefined;
}

/**
 * The session `define` returns; a config unjwt refuses throws `ERR_UNAUTH_CONFIG_INVALID` with
 * `prefix`, unjwt's error as `cause`.
 */
export function definedSession<T>(define: () => T, options: { prefix: string }): T {
  try {
    return define();
  } catch (error) {
    if (!isJWTError(error)) throw error;
    throw configError(error.message.replace(UNJWT_PREFIX, ""), {
      prefix: options.prefix,
      cause: error,
    });
  }
}

const UNJWT_PREFIX = /^\[unjwt[^\]]*\]\s*/;
