import { type ExpiresIn, type SessionConfigJWS, defineJWSSession } from "unjwt/session";
import { secureRandomBytes } from "unsecure/random";
import { base64Stringify } from "unsecure/utils";
import { hash } from "unsecure/hash";
import { UnauthError } from "../_internal/error.ts";
import { configError, durationSeconds } from "./flow/_http.ts";

/** What `consume` is asked to burn. */
export interface OneTimeTokenUse {
  /** The token's unique id. */
  jti: string;
  /** When the token expires, in ms: the record may be dropped after. */
  expiresAt: number;
  purpose: string;
}

/** Options of {@link defineOneTimeToken}. */
export interface OneTimeTokenConfig {
  /** Signing key (a JWS session key). */
  key: SessionConfigJWS["key"];
  maxAge: ExpiresIn;
  /** Names what the token is for; a token of another purpose never opens. */
  purpose: string;
  /** Records the use and answers whether this was the first one (`true`) or a replay (`false`). */
  consume: (use: OneTimeTokenUse) => boolean | Promise<boolean>;
}

/** A kind of one-time token: invitations, password resets, magic links, handoff tickets. */
export interface OneTimeToken<TData extends object> {
  /** A signed token carrying `data` and the purpose; nothing is stored. */
  issue: (data: TData) => Promise<string>;
  /**
   * The token's data, once: a forged, expired or malformed token throws `ERR_AUTHN_TOKEN_INVALID`,
   * another purpose `ERR_AUTHN_TOKEN_PURPOSE` (without consuming it), a replay `ERR_AUTHN_TOKEN_USED`.
   */
  open: (token: string) => Promise<TData>;
}

/** Defines a kind of signed, single-use, expiring token over the `consume` driver. */
export function defineOneTimeToken<TData extends object>(
  config: OneTimeTokenConfig,
): OneTimeToken<TData> {
  const { purpose, consume } = config;
  durationSeconds(config.maxAge, { label: "A one-time token" });
  const tokens = defineJWSSession<{ purpose: string; data: TData }, ExpiresIn>({
    key: config.key,
    maxAge: config.maxAge,
    cookie: false,
    sessionHeader: false,
    // Its own `typ`, so a session token signed with the same key never opens here.
    jws: { signOptions: { protectedHeader: { typ: ONE_TIME_TOKEN_TYP } } },
  });

  return {
    issue: (data) => tokens.issue({ purpose, data }),
    open: async (token) => {
      let opened: Awaited<ReturnType<typeof tokens.open>>;
      try {
        opened = await tokens.open(token);
      } catch (error) {
        throw tokenError("The link is invalid or has expired.", "ERR_AUTHN_TOKEN_INVALID", error);
      }
      if (opened.data.purpose !== purpose) {
        throw tokenError("The link is not valid here.", "ERR_AUTHN_TOKEN_PURPOSE", {
          purpose: opened.data.purpose,
        });
      }
      if (!(await consume({ jti: opened.id, expiresAt: opened.expiresAt, purpose }))) {
        throw tokenError("The link was already used.", "ERR_AUTHN_TOKEN_USED");
      }
      return opened.data.data;
    },
  };
}

/** An opaque random token for apps that store tokens: hand out `token`, keep only `hash`. */
export async function createOpaqueToken(options?: {
  /** Random bytes, at least 16. @default 32 */
  bytes?: number;
}): Promise<{ token: string; hash: string }> {
  const bytes = options?.bytes ?? 32;
  if (!Number.isInteger(bytes) || bytes < 16) {
    throw configError(
      `An opaque token needs a whole number of at least 16 random bytes, got ${bytes}.`,
    );
  }
  const token = base64Stringify(secureRandomBytes(bytes), { alphabet: "base64url" });
  return { token, hash: await hashOpaqueToken(token) };
}

/** The SHA-256 (base64url) under which an opaque token is stored and looked up. */
export function hashOpaqueToken(token: string): Promise<string> {
  return hash(token, { algorithm: "SHA-256", returnAs: "base64url" });
}

/** The JWS `typ` of one-time tokens. */
const ONE_TIME_TOKEN_TYP = "unauth-ott+jwt";

function tokenError<
  TCode extends "ERR_AUTHN_TOKEN_INVALID" | "ERR_AUTHN_TOKEN_PURPOSE" | "ERR_AUTHN_TOKEN_USED",
>(message: string, code: TCode, cause?: unknown): UnauthError<TCode> {
  return new UnauthError(`[unauth/n] ${message}`, code, { status: 401, cause });
}
