import { UnauthError, type UnauthErrorCauseMap } from "../../_internal/error.ts";
import { stringField } from "./_http.ts";
import type { FormAnswer } from "./_http-json.ts";
import type { OAuthTokens } from "./types.ts";

/** Options of {@link parseTokenResponse}. */
export interface TokenResponseOptions {
  /**
   * The `token_type` the endpoint must issue, compared case-insensitively (RFC 6749 §5.1).
   *
   * @default "Bearer"
   */
  tokenType?: string;
}

/**
 * The tokens a token endpoint answered with (RFC 6749 §5.1). A refusal, whether sent as 400, 401
 * or a 200 carrying `error` (§5.2), any other failed status, and a body without `access_token`
 * and `token_type` or with another token type than `tokenType` throw `ERR_AUTHN_TOKEN_EXCHANGE`
 * (401) with the detail in `cause`.
 */
export function parseTokenResponse(
  answer: Pick<FormAnswer, "ok" | "status" | "body">,
  options: TokenResponseOptions = {},
): OAuthTokens {
  const raw = answer.body;
  const error = stringField(raw, "error");
  if (error !== undefined) {
    throw exchangeError("The token endpoint refused the grant.", {
      status: answer.status,
      error,
      error_description: stringField(raw, "error_description"),
      error_uri: stringField(raw, "error_uri"),
    });
  }
  if (!answer.ok || !raw) {
    throw exchangeError(`The token endpoint answered ${answer.status}.`, {
      status: answer.status,
    });
  }
  const access_token = stringField(raw, "access_token");
  const token_type = stringField(raw, "token_type");
  if (access_token === undefined || token_type === undefined) {
    throw exchangeError("The token endpoint answered without an access_token and token_type.", {});
  }
  const expected = options.tokenType ?? "Bearer";
  if (token_type.toLowerCase() !== expected.toLowerCase()) {
    throw exchangeError(`The token endpoint issued a token type other than ${expected}.`, {
      token_type,
    });
  }
  const tokens: OAuthTokens = { access_token, token_type, raw };
  const expiresIn = numericField(raw.expires_in);
  if (expiresIn !== undefined) tokens.expires_in = expiresIn;
  const refreshToken = stringField(raw, "refresh_token");
  if (refreshToken !== undefined) tokens.refresh_token = refreshToken;
  const scope = stringField(raw, "scope");
  if (scope !== undefined) tokens.scope = scope;
  const idToken = stringField(raw, "id_token");
  if (idToken !== undefined) tokens.id_token = idToken;
  return tokens;
}

/** `ERR_AUTHN_TOKEN_EXCHANGE` (401) with the `[unauth/n]` prefix. */
export function exchangeError(
  message: string,
  cause: UnauthErrorCauseMap["ERR_AUTHN_TOKEN_EXCHANGE"],
): UnauthError<"ERR_AUTHN_TOKEN_EXCHANGE"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_AUTHN_TOKEN_EXCHANGE", {
    status: 401,
    cause,
  });
}

/** A finite number, or a string of digits; anything else is `undefined`. */
function numericField(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  return typeof value === "string" && /^\d+$/.test(value) ? Number(value) : undefined;
}
