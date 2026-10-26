import { UnauthError, isUnauthError } from "../../../../error.ts";
import {
  MAX_URL_LENGTH,
  assertRemoteUrl,
  assertSecureUrl,
  isRecord,
  providerError,
  stringField,
} from "../../../flow/_internal/http/shared.ts";
import {
  PROVIDER_FETCH_TIMEOUT,
  discardBody,
  isAbort,
  readText,
  raced,
} from "../../../flow/_internal/http/body.ts";
import { getObject } from "../../../flow/_internal/http/json.ts";
import {
  type MetadataOptions,
  defineMetadataLoader,
} from "../../../flow/_internal/cache/metadata.ts";

/** Where the resolvers an identity needs are, and how to reach them. */
export interface AtprotoResolveOptions extends MetadataOptions {
  /** A DNS-over-HTTPS resolver answering `application/dns-json`. */
  dnsResolver: string;
  /** The `did:plc` directory. */
  plcDirectory: string;
  /** Lets the URLs read from documents use plain `http:` (a PDS run locally). */
  allowHttp?: boolean;
}

/** An account: its DID, the handle it verifiably claims, and the origin of its PDS. */
export interface AtprotoIdentity {
  did: string;
  /** Present only when the handle and the DID document point at each other. */
  handle?: string;
  pds: string;
}

/** What `loginHint` names: an account, or a server to start from. */
export type AtprotoLoginHint = { kind: "account"; input: string } | { kind: "server"; url: string };

/** Handle syntax (atproto Handle spec) and the TLDs it never resolves. */
const HANDLE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
const DISALLOWED_TLDS = new Set([
  "alt",
  "arpa",
  "example",
  "internal",
  "invalid",
  "local",
  "localhost",
  "onion",
]);
const DID_PLC = /^did:plc:[a-z2-7]{24}$/;
const DID_WEB = /^did:web:([a-z0-9.-]+)$/;
/** The longest handle document (`/.well-known/atproto-did`) read. */
const HANDLE_DOCUMENT_MAX_BYTES = 1024;

const loadDid = /* @__PURE__ */ defineMetadataLoader<DidDocument, AtprotoResolveOptions>({
  name: "atproto-did",
  label: "DID document",
  url: (did, options) =>
    did.startsWith("did:plc:")
      ? `${plcOrigin(options)}/${did}`
      : `https://${did.slice("did:web:".length)}/.well-known/did.json`,
  partition: (options) => plcOrigin(options),
  parse: parseDidDocument,
  revive: reviveDidDocument,
});

/** The `did:plc` directory as a URL without its trailing slash, the half of a `did:plc` document's location the configuration chooses. */
function plcOrigin(options: AtprotoResolveOptions): string {
  return options.plcDirectory.replace(/\/$/, "");
}

/** `ERR_AUTHN_LOGIN_HINT_INVALID` (400): `loginHint` names no usable account. */
export function loginHintError(
  message: string,
  cause?: unknown,
): UnauthError<"ERR_AUTHN_LOGIN_HINT_INVALID"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_AUTHN_LOGIN_HINT_INVALID", {
    status: 400,
    cause,
  });
}

/** A `loginHint`: an `https://` URL is a server to start from, anything else an account (handle or DID). */
export function parseLoginHint(loginHint: string): AtprotoLoginHint {
  const input = loginHint.trim().replace(/^@/, "");
  if (/^https:\/\//i.test(input)) {
    const url = assertServerUrl(input);
    return { kind: "server", url: url.origin };
  }
  if (input.startsWith("did:")) {
    assertDid(input);
    return { kind: "account", input };
  }
  return { kind: "account", input: normalizeHandle(input) };
}

/**
 * Handle or DID → DID document → PDS, the handle verified in both directions: starting from a
 * handle, a document not claiming it is refused; starting from a DID, an unverified handle is
 * left out. `did:plc` and host-only `did:web` are the methods atproto supports.
 */
export async function resolveIdentity(
  input: string,
  options: AtprotoResolveOptions,
): Promise<AtprotoIdentity> {
  if (input.startsWith("did:")) {
    const document = await resolveDid(input, options);
    return {
      did: input,
      ...(await verifiedHandle(document, options)),
      pds: pdsOf(document, options),
    };
  }
  const did = await resolveHandle(input, options);
  const document = await resolveDid(did, options);
  if (claimedHandle(document) !== input) {
    throw loginHintError(`${did} does not claim the handle ${input}.`);
  }
  return { did, handle: input, pds: pdsOf(document, options) };
}

/** The handle `document` claims, when the handle resolves back to the document's DID. */
export async function verifiedHandle(
  document: DidDocument,
  options: AtprotoResolveOptions,
): Promise<{ handle?: string }> {
  const claimed = claimedHandle(document);
  if (claimed === undefined) return {};
  const did = await resolveHandle(claimed, options).catch(() => undefined);
  return did === document.id ? { handle: claimed } : {};
}

/** A DID document, kept ten minutes; an unknown DID is `ERR_AUTHN_LOGIN_HINT_INVALID`. */
export function resolveDid(did: string, options: AtprotoResolveOptions): Promise<DidDocument> {
  assertDid(did);
  return loadDid(did, options).catch((error: unknown) => {
    if (isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR") && error.cause.status === 404) {
      throw loginHintError(`${did} is unknown.`, error);
    }
    throw error;
  });
}

/** The origin of the PDS a DID document names; `ERR_AUTHN_LOGIN_HINT_INVALID` without one. */
export function pdsOf(document: DidDocument, options: { allowHttp?: boolean }): string {
  if (document.pds === undefined) throw loginHintError(`${document.id} names no PDS.`);
  try {
    return assertRemoteUrl(document.pds, {
      label: `The PDS of ${document.id}`,
      allowHttp: options.allowHttp,
    }).origin;
  } catch (error) {
    throw loginHintError(`${document.id} names an unusable PDS.`, error);
  }
}

export function normalizeHandle(value: string): string {
  const handle = value.toLowerCase();
  const tld = handle.slice(handle.lastIndexOf(".") + 1);
  if (handle.length > 253 || !HANDLE.test(handle) || DISALLOWED_TLDS.has(tld)) {
    throw loginHintError(`${JSON.stringify(value)} is not an atproto handle or DID.`);
  }
  return handle;
}

export function assertDid(did: string): void {
  if (DID_PLC.test(did)) return;
  const host = DID_WEB.exec(did)?.[1];
  if (host !== undefined && HANDLE.test(host) && !/^[\d.]+$/.test(host)) return;
  throw loginHintError(`${JSON.stringify(did)} is not a did:plc or a host-only did:web.`);
}

/** The `https://` origin of a server given as `loginHint`. */
function assertServerUrl(input: string): URL {
  try {
    return assertSecureUrl(input, { label: "The server" });
  } catch (error) {
    throw loginHintError(`${JSON.stringify(input)} is not an https:// server URL.`, error);
  }
}

/**
 * DNS TXT `_atproto.<handle>` over DNS-over-HTTPS, then the HTTPS well-known document when DNS has
 * no record or cannot be asked. A DNS answer naming two DIDs refuses the handle instead.
 */
async function resolveHandle(handle: string, options: AtprotoResolveOptions): Promise<string> {
  const fromDns = await resolveHandleDns(handle, options).catch((error: unknown) => {
    if (isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID")) throw error;
    return undefined;
  });
  const did = fromDns ?? (await resolveHandleHttps(handle, options));
  try {
    assertDid(did);
  } catch (error) {
    throw loginHintError(`The handle ${handle} resolves to something that is not a DID.`, error);
  }
  return did;
}

async function resolveHandleDns(
  handle: string,
  options: AtprotoResolveOptions,
): Promise<string | undefined> {
  const url = new URL(options.dnsResolver);
  url.searchParams.set("name", `_atproto.${handle}`);
  url.searchParams.set("type", "TXT");
  const answer = await getObject(url.href, {
    fetch: options.fetch,
    headers: { accept: "application/dns-json" },
    label: "DNS resolver",
  });
  const records = Array.isArray(answer.Answer) ? answer.Answer : [];
  const dids = new Set<string>();
  for (const record of records) {
    if (!isRecord(record) || record.type !== 16) continue;
    const data = stringField(record, "data");
    if (data === undefined) continue;
    // A TXT record arrives as one or more quoted character-strings.
    const text = data.replaceAll(/"\s*"/g, "").replace(/^"|"$/g, "");
    if (text.startsWith("did=")) dids.add(text.slice(4));
  }
  if (dids.size > 1) throw loginHintError(`The handle ${handle} has conflicting DNS records.`);
  return dids.values().next().value;
}

async function resolveHandleHttps(handle: string, options: AtprotoResolveOptions): Promise<string> {
  const url = `https://${handle}/.well-known/atproto-did`;
  const signal = AbortSignal.timeout(PROVIDER_FETCH_TIMEOUT);
  let response: Response;
  try {
    response = await raced(options.fetch(url, { signal, redirect: "error" }), signal);
  } catch (error) {
    throw loginHintError(
      isAbort(error)
        ? `The handle ${handle} did not answer within ${PROVIDER_FETCH_TIMEOUT} ms.`
        : `The handle ${handle} does not resolve.`,
      error,
    );
  }
  if (!response.ok) {
    discardBody(response);
    throw loginHintError(`The handle ${handle} does not resolve.`);
  }
  const text = await readText(response, { maxBytes: HANDLE_DOCUMENT_MAX_BYTES, signal }).catch(
    () => undefined,
  );
  const did = text?.split("\n", 1)[0]?.trim();
  if (!did) throw loginHintError(`The handle ${handle} does not resolve.`);
  return did;
}

/**
 * What a sign-in reads from a DID document, and all the cache keeps of it: the handle the account
 * claims (its first `at://` alias) and the `#atproto_pds` service endpoint. A document is as large
 * as whoever published it likes; keeping only these two bounded strings keeps the cache's footprint
 * independent of that size.
 */
export interface DidDocument {
  id: string;
  /** The first `at://` alias, lower-cased, without the scheme. */
  handle?: string;
  /** The `#atproto_pds` service endpoint, as the document spells it. */
  pds?: string;
}

/** The longest handle an `at://` alias may carry, after the scheme. */
const HANDLE_MAX_LENGTH = 253;

/** The members a sign-in uses of the DID document of `did`; another DID's document is refused. */
function parseDidDocument(document: unknown, did: string): DidDocument {
  if (!isRecord(document))
    throw providerError(`The DID document of ${did} is not a JSON object.`, {
      reason: "malformed",
    });
  if (document.id !== did) {
    throw providerError(`The DID document fetched for ${did} belongs to another DID.`, {
      reason: "malformed",
    });
  }
  const result: DidDocument = { id: did };
  const aliases = Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs : [];
  const alias = aliases.find(
    (entry): entry is string =>
      typeof entry === "string" &&
      entry.startsWith("at://") &&
      entry.length <= "at://".length + HANDLE_MAX_LENGTH,
  );
  if (alias !== undefined) result.handle = alias.slice("at://".length).toLowerCase();
  const services = Array.isArray(document.service) ? document.service : [];
  for (const entry of services) {
    if (!isRecord(entry)) continue;
    const endpoint = stringField(entry, "serviceEndpoint");
    if (
      (entry.id === "#atproto_pds" || entry.id === `${did}#atproto_pds`) &&
      entry.type === "AtprotoPersonalDataServer" &&
      endpoint !== undefined &&
      endpoint.length <= MAX_URL_LENGTH
    ) {
      result.pds = endpoint;
      break;
    }
  }
  return result;
}

/** A {@link DidDocument} a cache driver handed back, within the bounds `parseDidDocument` keeps; anything else is refused as malformed. */
function reviveDidDocument(value: unknown, did: string): DidDocument {
  const malformed = () =>
    providerError(`The cached DID document of ${did} is not one this version keeps.`, {
      reason: "malformed",
    });
  if (!isRecord(value) || value.id !== did) throw malformed();
  const result: DidDocument = { id: did };
  const handle = stringField(value, "handle");
  const pds = stringField(value, "pds");
  if (handle !== undefined) {
    if (handle.length > HANDLE_MAX_LENGTH) throw malformed();
    result.handle = handle;
  }
  if (pds !== undefined) {
    if (pds.length > MAX_URL_LENGTH) throw malformed();
    result.pds = pds;
  }
  return result;
}

/** The handle the account claims: its first `at://` alias. */
function claimedHandle(document: DidDocument): string | undefined {
  return document.handle;
}
