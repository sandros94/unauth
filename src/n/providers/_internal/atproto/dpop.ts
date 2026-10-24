import { type JWK_EC_Private, generateJWK, toPublicJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import { digestUrl } from "unjwt/utils";
import { type Fetch, providerError, stringField } from "../../../flow/_internal/http/shared.ts";
import { type FormAnswer, postForm } from "../../../flow/_internal/http/form.ts";
import { createJti } from "../../../flow/random.ts";

/**
 * The ES256 key a sign-in's DPoP proofs are signed with (RFC 9449); it binds the flow's tokens.
 * For exploration: not a stable part of the API, and may change or go without notice.
 */
export type DpopKey = JWK_EC_Private<"ES256">;

/** A fresh ES256 key for one sign-in, unnamed: its public half travels in every proof instead. */
export async function createDpopKey(): Promise<DpopKey> {
  const { privateKey } = await generateJWK("ES256", { kid: false });
  return privateKey;
}

/**
 * Options of {@link createDpopProof}. For exploration: not a stable part of the API, and may change
 * or go without notice.
 */
export interface DpopProofOptions {
  /** The request's method. */
  htm: string;
  /** The request's URL; its query and fragment are dropped, as RFC 9449 §4.2 requires. */
  htu: string;
  /** The nonce the server last sent, when it did. */
  nonce?: string;
  /** Binds the proof to this access token (`ath`), for a request to a resource server. */
  accessToken?: string;
  now?: () => number;
}

/**
 * An RFC 9449 proof JWT for one request, signed with `key` and carrying its public half (§4.2).
 * For exploration: not a stable part of the API, and may change or go without notice.
 */
export async function createDpopProof(key: DpopKey, options: DpopProofOptions): Promise<string> {
  const url = new URL(options.htu);
  const claims: Record<string, unknown> = {
    jti: createJti(),
    htm: options.htm.toUpperCase(),
    htu: url.origin + url.pathname,
  };
  if (options.nonce !== undefined) claims.nonce = options.nonce;
  if (options.accessToken !== undefined) claims.ath = await digestUrl(options.accessToken);
  return sign(claims, key, {
    alg: "ES256",
    protectedHeader: { typ: "dpop+jwt", jwk: toPublicJWK(key) },
    issuedAt: new Date((options.now ?? Date.now)()),
  });
}

/** What a DPoP form POST answered. */
export interface DpopAnswer extends FormAnswer {
  /** The JSON body, empty when there was none. */
  body: Record<string, unknown>;
  /** The nonce the server sent for the next request, when it sent one. */
  nonce?: string;
}

/**
 * A form POST to an authorization server with a DPoP proof, retried once when the server asks
 * for a nonce (RFC 9449 §8). A successful answer without a `DPoP-Nonce` is refused, as the atproto
 * profile requires; a failed one is returned for the caller to read.
 */
export async function dpopPost(
  url: string,
  form: Record<string, string>,
  options: { key: DpopKey; nonce?: string; fetch: Fetch; now: () => number; label: string },
): Promise<DpopAnswer> {
  const { key, fetch, now, label } = options;
  const body = new URLSearchParams(form);
  let nonce = options.nonce;
  for (let attempt = 0; ; attempt++) {
    const proof = await createDpopProof(key, { htm: "POST", htu: url, nonce, now });
    const answer = await postForm(url, body, { fetch, headers: { dpop: proof }, label });
    const next = answer.headers.get("dpop-nonce") ?? undefined;
    const object = answer.body ?? {};
    if (attempt === 0 && next !== undefined && wantsNonce(answer, object)) {
      nonce = next;
      continue;
    }
    if (answer.ok && next === undefined) {
      throw providerError(`The ${label} at ${url} sent no DPoP nonce.`, {
        reason: "malformed",
        status: answer.status,
      });
    }
    const result: DpopAnswer = { ...answer, body: object };
    if (next !== undefined) result.nonce = next;
    return result;
  }
}

/** Whether a 4xx asks for a (new) DPoP nonce, in its body or its `WWW-Authenticate` challenge. */
function wantsNonce(answer: FormAnswer, body: Record<string, unknown>): boolean {
  if (answer.status !== 400 && answer.status !== 401) return false;
  if (stringField(body, "error") === "use_dpop_nonce") return true;
  return answer.headers.get("www-authenticate")?.includes("use_dpop_nonce") ?? false;
}
