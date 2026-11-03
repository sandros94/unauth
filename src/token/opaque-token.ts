import { secureRandomBytes } from "unsecure/random";
import { base64Stringify } from "unsecure/utils";
import { type DigestAlgorithm, hash } from "unsecure/hash";
import { configError } from "../_internal/shared.ts";

/**
 * A random base64url token and its {@link hashOpaqueToken} hash: hand out `token`, store only
 * `hash`.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for `bytes` outside 16 to {@link MAX_TOKEN_BYTES} or not an integer.
 */
export async function createOpaqueToken(options?: {
  /** Random bytes, 16 to {@link MAX_TOKEN_BYTES}. @default 32 */
  bytes?: number;
}): Promise<{ token: string; hash: string }> {
  const bytes = options?.bytes ?? 32;
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > MAX_TOKEN_BYTES) {
    throw configError(
      `An opaque token needs a whole number of 16 to ${MAX_TOKEN_BYTES} random bytes, got ${bytes}.`,
      { prefix: "[unauth/token]" },
    );
  }
  const token = base64Stringify(secureRandomBytes(bytes), { alphabet: "base64url" });
  return { token, hash: await hashOpaqueToken(token) };
}

/** The most random bytes a token may carry: 512 base64url characters. */
export const MAX_TOKEN_BYTES: number = 384;

/** The SHA-256 (base64url) under which an opaque token is stored and looked up. */
export function hashOpaqueToken(
  token: string,
  options?: { algorithm?: DigestAlgorithm },
): Promise<string> {
  return hash(token, { algorithm: options?.algorithm ?? "SHA-256", returnAs: "base64url" });
}
