import {
  type ExpiresIn,
  type JWSAlgorithm,
  type JWSSessionKeyLookup,
  type SessionConfigJWS,
  defineJWSSession,
} from "unjwt/session";
import { secureRandomBytes } from "unsecure/random";
import { base64Stringify } from "unsecure/utils";
import { hash } from "unsecure/hash";
import { UnauthError } from "../error.ts";
import { configError, durationSeconds, isRecord } from "./flow/_internal/http/shared.ts";
import { definedSession, keyLookupFailure } from "./_internal/session-error.ts";

/** What `consume` is asked to burn. */
export interface OneTimeTokenUse {
  /** The token's unique id. */
  jti: string;
  /** When the token expires, in ms: the record may be dropped after. */
  expiresAt: number;
  purpose: string;
}

/**
 * Picks the key that verifies an incoming one-time token from its protected header (its `kid`,
 * `alg`): an HMAC or public JWK, a `CryptoKey` or a JWK Set, for keys kept elsewhere (a KMS, a
 * remote set). It replaces `key` for verifying; `key` still signs. A key it returns naming no `alg`
 * verifies tokens signed under `jws.alg`. It gets the token's `header` alone: no request event, and
 * never unjwt's session `config`. What it throws propagates as it is, an `UnauthError` included,
 * and a key it returns that cannot verify the token rejects with unjwt's `ERR_JWK_INVALID`; to
 * refuse the token instead, return `undefined`: `ERR_AUTHN_TOKEN_INVALID`.
 */
export type OneTimeTokenKeyLookup = (
  args: Pick<Parameters<JWSSessionKeyLookup>[0], "header">,
) => ReturnType<JWSSessionKeyLookup>;

/** Options of {@link defineOneTimeToken}. */
export interface OneTimeTokenConfig {
  /**
   * The key that signs and verifies, as unjwt's JWS session takes it: an HMAC `oct` JWK (the
   * suggested key, `generateJWK("HS256")`), a secret `CryptoKey`, a JWK Set of HMAC `oct` JWKs, or
   * a pair whose `privateKey` signs and `publicKey` verifies. A set's first key signs and every key
   * verifies: to rotate, put the new key first and keep the old ones while their tokens may still
   * arrive. A key naming no `alg` needs `jws`.
   */
  key: SessionConfigJWS["key"];
  /**
   * The JWS `alg` the key signs with: required when a key names none (a `CryptoKey`, an `oct` JWK
   * without `alg`, a JWK Set entry without one, a pair half that is a `CryptoKey` or a JWK without
   * one). Such a key, and one `onKeyLookup` returns, verifies tokens signed under this `alg`.
   */
  jws?: { alg: JWSAlgorithm };
  /** Picks the key that verifies a token from its header; `key` still signs. See {@link OneTimeTokenKeyLookup}. */
  onKeyLookup?: OneTimeTokenKeyLookup;
  /** How long a token stays valid: seconds, or a duration such as `"15m"`. */
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
   * another purpose `ERR_AUTHN_TOKEN_PURPOSE` (without consuming it), a replay `ERR_AUTHN_TOKEN_USED`;
   * what `onKeyLookup` throws propagates as it is, and a key it returns that cannot verify the
   * token rejects with unjwt's `ERR_JWK_INVALID`.
   */
  open: (token: string) => Promise<TData>;
}

/**
 * A kind of signed, single-use, expiring token; `consume` records each use.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for a `maxAge` that is not a positive duration, a key (or
 * set entry, or pair half) naming no algorithm given without `jws`, or a key unjwt refuses (such
 * as a JWK Set whose entries without `kid` are more than a token may be tried against), unjwt's
 * error as `cause`.
 */
export function defineOneTimeToken<TData extends object>(
  config: OneTimeTokenConfig,
): OneTimeToken<TData> {
  const { key, jws, onKeyLookup, purpose, consume } = config;
  durationSeconds(config.maxAge, { label: "A one-time token" });
  if (!jws?.alg && !keysOf(key).every(namesAlgorithm)) {
    throw configError('A one-time token key naming no algorithm needs "jws": its "alg".');
  }
  // Own `typ`: a session token signed with the same key never opens here.
  const protectedHeader = { typ: ONE_TIME_TOKEN_TYP };
  const tokens = definedSession(() =>
    defineJWSSession<{ purpose: string; data: TData }, ExpiresIn>({
      key,
      maxAge: config.maxAge,
      cookie: false,
      sessionHeader: false,
      jws: jws
        ? {
            signOptions: { protectedHeader, alg: jws.alg },
            verifyOptions: { algorithms: [jws.alg] },
          }
        : { signOptions: { protectedHeader } },
      ...(onKeyLookup && { hooks: { onKeyLookup: ({ header }) => onKeyLookup({ header }) } }),
    }),
  );

  return {
    issue: (data) => tokens.issue({ purpose, data }),
    open: async (token) => {
      let opened: Awaited<ReturnType<typeof tokens.open>>;
      try {
        opened = await tokens.open(token);
      } catch (error) {
        const failure = keyLookupFailure(error);
        if (failure) throw failure.error;
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

/**
 * A random base64url token and its {@link hashOpaqueToken} hash: hand out `token`, store only
 * `hash`.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for `bytes` below 16 or not an integer.
 */
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

/**
 * The keys of `key` that must name their algorithm: each entry of a set, a pair's halves (a public
 * list or set aside), or the key itself; none for what is no key at all, which unjwt refuses.
 */
function keysOf(key: unknown): unknown[] {
  if (!isRecord(key)) return [];
  if (Array.isArray(key.keys)) return key.keys;
  if (!("privateKey" in key)) return [key];
  const { privateKey, publicKey } = key;
  const single = isRecord(publicKey) && !Array.isArray(publicKey.keys);
  return single ? [privateKey, publicKey] : [privateKey];
}

function namesAlgorithm(key: unknown): boolean {
  return isRecord(key) && typeof key.alg === "string";
}

function tokenError<
  TCode extends "ERR_AUTHN_TOKEN_INVALID" | "ERR_AUTHN_TOKEN_PURPOSE" | "ERR_AUTHN_TOKEN_USED",
>(message: string, code: TCode, cause?: unknown): UnauthError<TCode> {
  return new UnauthError(`[unauth/n] ${message}`, code, { status: 401, cause });
}
