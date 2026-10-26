/**
 * An in-process AT Protocol world reached through an injected `fetch`: a DNS-over-HTTPS resolver,
 * handle well-known documents, a `did:plc` directory, a `did:web` host, a PDS with its protected
 * resource metadata, and an authorization server that validates DPoP proofs (with the nonce
 * dance), pushed authorization requests, PKCE and the client id, and records every request.
 */
import { thumbprint, verify } from "unjwt";
import type { JWK_EC_Public } from "unjwt";
import { s256 } from "../flow/_fake-provider.ts";

export const DNS = "https://dns.test/dns-query";
export const PLC = "https://plc.test";
export const PDS = "https://pds.test";
export const ISSUER = "https://auth.test";
export const CLIENT_ID = "https://app.test/oauth-client-metadata.json";
export const REDIRECT_URI = "https://app.test/auth/atproto";

export const ALICE = { handle: "alice.test", did: "did:plc:ewvi7nxzyoun6zhxrhs64oiz" };
export const BOB = { handle: "bob.test", did: "did:web:bob.test" };
export const CAROL = { handle: "carol.test", did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" };

interface PushedRequest {
  clientId: string;
  redirectUri: string;
  challenge: string;
  state: string;
  scope: string;
  loginHint: string | null;
  thumbprint: string;
}

export interface FakeAtproto {
  fetch: typeof fetch;
  requests: { url: URL; method: string; headers: Headers; body: string }[];
  /** Simulates consent at the authorization URL: where the server redirects the browser. */
  approve: (authorizationUrl: string | URL) => URL;
  /** DNS TXT answers per handle; absent handles answer NXDOMAIN. */
  dns: Map<string, string[]>;
  /** `/.well-known/atproto-did` per handle. */
  wellKnown: Map<string, string>;
  /** DID documents, served by the plc directory or the did:web host. */
  documents: Map<string, Record<string, unknown>>;
  /** Overrides of the authorization server metadata. */
  metadata: Record<string, unknown>;
  /** The nonce the server currently requires. */
  nonce: string;
  /** Overrides of the token response. */
  token: Record<string, unknown>;
  /** Answers the next token request with this instead. */
  nextTokenResponse: (response: Response) => void;
  /** Answers the next pushed authorization request with this instead. */
  nextParResponse: (response: Response) => void;
  /** The pushed requests, by `request_uri`. */
  pushed: Map<string, PushedRequest>;
  /** The DPoP key thumbprints the token endpoint saw, in order. */
  tokenThumbprints: string[];
}

export function didDocument(
  did: string,
  handle: string,
  pds: string = PDS,
): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": did,
    "alsoKnownAs": [`at://${handle}`],
    "service": [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: pds }],
  };
}

export function createFakeAtproto(options: { issuer?: string } = {}): FakeAtproto {
  const issuer = options.issuer ?? ISSUER;
  const requests: FakeAtproto["requests"] = [];
  const codes = new Map<string, PushedRequest>();
  let override: Response | undefined;
  let parOverride: Response | undefined;
  let nonceIndex = 0;

  const fake: FakeAtproto = {
    requests,
    dns: new Map([[ALICE.handle, [ALICE.did]]]),
    wellKnown: new Map([[BOB.handle, BOB.did]]),
    documents: new Map([
      [ALICE.did, didDocument(ALICE.did, ALICE.handle)],
      [BOB.did, didDocument(BOB.did, BOB.handle)],
      [CAROL.did, didDocument(CAROL.did, CAROL.handle)],
    ]),
    metadata: {},
    nonce: "n0",
    token: {},
    pushed: new Map(),
    tokenThumbprints: [],
    nextTokenResponse: (response) => {
      override = response;
    },
    nextParResponse: (response) => {
      parOverride = response;
    },
    approve: (authorizationUrl) => {
      const url = new URL(authorizationUrl);
      const request = fake.pushed.get(url.searchParams.get("request_uri") ?? "");
      if (!request || request.clientId !== url.searchParams.get("client_id")) {
        throw new Error("approve: unknown request_uri or client_id");
      }
      const code = `code-${crypto.randomUUID()}`;
      codes.set(code, request);
      const back = new URL(request.redirectUri);
      back.searchParams.set("code", code);
      back.searchParams.set("state", request.state);
      back.searchParams.set("iss", issuer);
      return back;
    },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      const body = request.method === "POST" ? await request.text() : "";
      requests.push({ url, method: request.method, headers: request.headers, body });
      return route(url, request, body);
    },
  };

  async function route(url: URL, request: Request, body: string): Promise<Response> {
    if (url.href.startsWith(DNS)) {
      const name = url.searchParams.get("name") ?? "";
      const dids = fake.dns.get(name.replace(/^_atproto\./, ""));
      if (!dids) return Response.json({ Status: 3 });
      return Response.json({
        Status: 0,
        Answer: dids.map((did) => ({ name, type: 16, TTL: 60, data: `"did=${did}"` })),
      });
    }
    if (url.pathname === "/.well-known/atproto-did") {
      const did = fake.wellKnown.get(url.hostname);
      return did ? new Response(`${did}\n`) : new Response("no", { status: 404 });
    }
    if (url.pathname === "/.well-known/did.json") {
      const document = fake.documents.get(`did:web:${url.hostname}`);
      return document ? Response.json(document) : new Response("no", { status: 404 });
    }
    if (url.origin === PLC) {
      const document = fake.documents.get(url.pathname.slice(1));
      return document ? Response.json(document) : new Response("no", { status: 404 });
    }
    if (url.pathname === "/.well-known/oauth-protected-resource" && url.origin !== issuer) {
      // Any other PDS delegates to another authorization server.
      const server = url.origin === PDS ? issuer : `https://auth-of-${url.hostname}`;
      return Response.json({ resource: url.origin, authorization_servers: [server] });
    }
    if (url.origin !== issuer) return new Response("not found", { status: 404 });

    switch (url.pathname) {
      case "/.well-known/oauth-authorization-server":
        return Response.json({
          issuer,
          authorization_endpoint: `${issuer}/oauth/authorize`,
          token_endpoint: `${issuer}/oauth/token`,
          pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
          require_pushed_authorization_requests: true,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
          token_endpoint_auth_signing_alg_values_supported: ["ES256"],
          scopes_supported: ["atproto", "transition:generic"],
          require_request_uri_registration: true,
          authorization_response_iss_parameter_supported: true,
          dpop_signing_alg_values_supported: ["ES256"],
          client_id_metadata_document_supported: true,
          ...fake.metadata,
        });
      case "/oauth/par": {
        if (parOverride) {
          const response = parOverride;
          parOverride = undefined;
          return response;
        }
        return dpop(request, url, (proof) => par(new URLSearchParams(body), proof));
      }
      case "/oauth/token": {
        if (override) {
          const response = override;
          override = undefined;
          return response;
        }
        return dpop(request, url, (proof) => token(new URLSearchParams(body), proof));
      }
    }
    return new Response("not found", { status: 404 });
  }

  /** Checks the DPoP proof and the nonce, then runs `handler`; every answer carries the nonce. */
  async function dpop(
    request: Request,
    url: URL,
    handler: (proof: { thumbprint: string; claims: Record<string, unknown> }) => Promise<Response>,
  ): Promise<Response> {
    const withNonce = (response: Response) => {
      response.headers.set("dpop-nonce", fake.nonce);
      return response;
    };
    const proof = request.headers.get("dpop");
    if (!proof) return withNonce(Response.json({ error: "invalid_dpop_proof" }, { status: 400 }));
    const header = JSON.parse(atob(proof.split(".")[0]!.replaceAll("-", "+").replaceAll("_", "/")));
    if (header.typ !== "dpop+jwt") {
      return withNonce(Response.json({ error: "invalid_dpop_proof" }, { status: 400 }));
    }
    const jwk: JWK_EC_Public<"ES256"> = header.jwk;
    let claims: Record<string, unknown>;
    try {
      const result = await verify(proof, jwk, { algorithms: ["ES256"], validateClaims: false });
      claims = result.payload;
    } catch {
      return withNonce(Response.json({ error: "invalid_dpop_proof" }, { status: 400 }));
    }
    if (claims.htm !== "POST" || claims.htu !== url.origin + url.pathname) {
      return withNonce(Response.json({ error: "invalid_dpop_proof" }, { status: 400 }));
    }
    if (claims.nonce !== fake.nonce) {
      // Rotate so a stale nonce is never accepted twice.
      fake.nonce = `n${++nonceIndex}`;
      return withNonce(Response.json({ error: "use_dpop_nonce" }, { status: 400 }));
    }
    return withNonce(await handler({ thumbprint: await thumbprint(jwk), claims }));
  }

  async function par(form: URLSearchParams, proof: { thumbprint: string }): Promise<Response> {
    const fail = (error: string) => Response.json({ error }, { status: 400 });
    if (form.get("response_type") !== "code") return fail("invalid_request");
    if (form.get("code_challenge_method") !== "S256") return fail("invalid_request");
    const scope = form.get("scope") ?? "";
    if (!scope.split(" ").includes("atproto")) return fail("invalid_scope");
    const id = `urn:ietf:params:oauth:request_uri:${crypto.randomUUID()}`;
    fake.pushed.set(id, {
      clientId: form.get("client_id") ?? "",
      redirectUri: form.get("redirect_uri") ?? "",
      challenge: form.get("code_challenge") ?? "",
      state: form.get("state") ?? "",
      scope,
      loginHint: form.get("login_hint"),
      thumbprint: proof.thumbprint,
    });
    return Response.json({ request_uri: id, expires_in: 300 }, { status: 201 });
  }

  async function token(form: URLSearchParams, proof: { thumbprint: string }): Promise<Response> {
    const fail = (error: string) => Response.json({ error }, { status: 400 });
    fake.tokenThumbprints.push(proof.thumbprint);
    if (form.get("grant_type") !== "authorization_code") return fail("unsupported_grant_type");
    const code = form.get("code") ?? "";
    const grant = codes.get(code);
    codes.delete(code);
    if (!grant) return fail("invalid_grant");
    if (grant.thumbprint !== proof.thumbprint) return fail("invalid_dpop_proof");
    if (form.get("client_id") !== grant.clientId) return fail("invalid_client");
    if (form.get("redirect_uri") !== grant.redirectUri) return fail("invalid_grant");
    if ((await s256(form.get("code_verifier") ?? "")) !== grant.challenge)
      return fail("invalid_grant");
    const sub = grant.loginHint ? subjectOf(grant.loginHint) : ALICE.did;
    return Response.json({
      access_token: `at-${crypto.randomUUID()}`,
      token_type: "DPoP",
      refresh_token: "rt-1",
      expires_in: 300,
      scope: grant.scope,
      sub,
      ...fake.token,
    });
  }

  function subjectOf(loginHint: string): string {
    if (loginHint.startsWith("did:")) return loginHint;
    for (const [did, document] of fake.documents) {
      const aliases = document.alsoKnownAs as string[];
      if (aliases.includes(`at://${loginHint}`)) return did;
    }
    return loginHint;
  }

  return fake;
}
