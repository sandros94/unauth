import { thumbprint } from "unjwt/jwk";
import type { JWK_oct } from "unjwt/session";
import { hkdf } from "unsecure/hkdf";
import { configError } from "./flow/_internal/http/shared.ts";

/**
 * An `A256GCM` JWK for a JWE session (a sign-in's `key`), derived from `secret` with HKDF-SHA-256
 * under `options.info` and the fixed salt `"unauth"`. The same secret and info give the same key on
 * every instance and restart; another info gives an unrelated key. Changing the secret or the info
 * invalidates every flow in flight.
 *
 * Its `kid` is the key's RFC 7638 thumbprint, so the same on every instance too. It names the key
 * in every token the key seals: a JWK Set rotating derived keys opens each token with the key
 * that sealed it alone, and never meets unjwt's cap on the keys a token without `kid` is tried
 * against.
 *
 * `secret` is a random string the deployment holds (`openssl rand -base64 32`, an `AUTH_SECRET`),
 * never something a person chose or typed, whatever a framework calls it: HKDF only spreads the
 * randomness it is given, and the length check is a floor, not a measure of entropy. A key from a
 * password is `unauth/session`'s `deriveJWKFromPassword`, which stretches it.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for a secret shorter than 32 characters or an empty `info`.
 */
export async function deriveJWK(
  secret: string,
  options: { info: string },
): Promise<JWK_oct<"A256GCM">> {
  const { info } = options;
  if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) {
    const got = typeof secret === "string" ? String(secret.length) : "none";
    throw configError(
      `deriveJWK needs a \`secret\` of at least ${MIN_SECRET_LENGTH} characters, got ${got}: use a longer random secret, such as \`openssl rand -base64 32\`.`,
    );
  }
  if (typeof info !== "string" || info === "") {
    throw configError(
      'deriveJWK needs a non-empty `info` naming the key\'s purpose, such as "unauth:flow".',
    );
  }
  const k = await hkdf(new TextEncoder().encode(secret), {
    algorithm: "SHA-256",
    salt: SALT,
    info,
    length: 32,
    returnAs: "base64url",
  });
  return { kty: "oct", k, alg: "A256GCM", kid: await thumbprint({ kty: "oct", k }) };
}

const MIN_SECRET_LENGTH = 32;
const SALT = "unauth";
