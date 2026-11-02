import { isJWTError } from "unjwt/error";
import { UnauthError, type UnauthErrorCauseMap } from "../../error.ts";

/** `ERR_SESSION_TOKEN_INVALID` (401) for the request's token, `cause` saying why. */
export function tokenError(
  prefix: string,
  cause: UnauthErrorCauseMap["ERR_SESSION_TOKEN_INVALID"],
): UnauthError<"ERR_SESSION_TOKEN_INVALID"> {
  return new UnauthError(`${prefix} The session token is not valid.`, "ERR_SESSION_TOKEN_INVALID", {
    status: 401,
    cause,
  });
}

/**
 * What `run` returns; a JWTError of unjwt's session helpers, already prefixed, becomes the
 * `UnauthError` of the same meaning: `ERR_SESSION_READONLY_EVENT` as it is, a config refusal as
 * `ERR_UNAUTH_CONFIG_INVALID`, unjwt's error as `cause`.
 */
export function unjwtRethrown<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (isJWTError(error, "ERR_SESSION_READONLY_EVENT")) {
      throw new UnauthError(error.message, "ERR_SESSION_READONLY_EVENT", {
        status: 500,
        cause: error,
      });
    }
    if (
      isJWTError(error, "ERR_SESSION_CONFIG_INVALID") ||
      isJWTError(error, "ERR_INVALID_OPTION")
    ) {
      throw new UnauthError(error.message, "ERR_UNAUTH_CONFIG_INVALID", {
        status: 500,
        cause: error,
      });
    }
    throw error;
  }
}
