import { secureRandomBytes } from "unsecure/random";
import { base64Stringify } from "unsecure/utils";
import { hash } from "unsecure/hash";

/** A PKCE pair (RFC 7636): keep `verifier` server-side, send `challenge` and `method`. */
export interface Pkce {
  verifier: string;
  challenge: string;
  method: "S256";
}

/** A fresh PKCE pair: a 256-bit verifier and its SHA-256 challenge (RFC 7636 §4.1, §4.2). */
export async function createPkce(): Promise<Pkce> {
  const verifier = randomToken();
  const challenge = await hash(verifier, { algorithm: "SHA-256", returnAs: "base64url" });
  return { verifier, challenge, method: "S256" };
}

/** A fresh 256-bit `state` (RFC 6749 §10.12). */
export function createState(): string {
  return randomToken();
}

/** A fresh 256-bit OpenID Connect `nonce`. */
export function createNonce(): string {
  return randomToken();
}

/** A fresh 256-bit JWT ID (RFC 7519 §4.1.7), for a client assertion or a DPoP proof. */
export function createJti(): string {
  return randomToken();
}

function randomToken(): string {
  return base64Stringify(secureRandomBytes(32), { alphabet: "base64url" });
}
