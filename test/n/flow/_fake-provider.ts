/**
 * An in-process OAuth 2.0 / OpenID Connect provider reached through an injected `fetch`. It issues
 * codes for an authorization URL, checks PKCE, `redirect_uri` and client authentication at its
 * token endpoint, signs id_tokens with a rotating key, and records every request it served. It
 * advertises and sends the RFC 9207 `iss` authorization response parameter.
 */
import { generateJWK, sign } from "unjwt";
import type { JWK } from "unjwt";

export const ISSUER = "https://idp.test";
export const CLIENT_ID = "client-1";
export const CLIENT_SECRET = "secret-1";

interface Grant {
  clientId: string;
  redirectUri: string;
  challenge: string | null;
  method: string | null;
  nonce: string | null;
  scope: string | null;
}

export interface FakeProvider {
  fetch: typeof fetch;
  /** Requests served, in order. */
  requests: { url: URL; method: string; headers: Headers; body: string }[];
  /** Number of JWKS fetches served. */
  jwksFetches: () => number;
  /** Simulates the user consenting at `authorizationUrl`: the URL the provider redirects back to. */
  approve: (authorizationUrl: string | URL) => URL;
  /** Replaces the signing key; the JWKS serves the new one only. */
  rotateKey: () => Promise<void>;
  /** Overrides the next token-endpoint response. */
  nextTokenResponse: (response: Response) => void;
  /** Claims merged into the next id_token. */
  idTokenClaims: Record<string, unknown>;
  /** The userinfo payload. */
  userinfo: Record<string, unknown>;
  /** Discovery document overrides. */
  discovery: Record<string, unknown>;
  /** Issue an id_token even when the `openid` scope was not asked for. */
  alwaysIdToken: boolean;
  /** Signs arbitrary claims with the current key. */
  signIdToken: (claims: Record<string, unknown>) => Promise<string>;
  publicJwk: () => JWK;
}

export async function createFakeProvider(
  options: { issuer?: string; tokenAuth?: "basic" | "body" | "none" } = {},
): Promise<FakeProvider> {
  const issuer = options.issuer ?? ISSUER;
  const tokenAuth = options.tokenAuth ?? "basic";
  let keyIndex = 0;
  let keys = await generateJWK("RS256", { kid: `k${keyIndex}` });
  const grants = new Map<string, Grant>();
  const requests: FakeProvider["requests"] = [];
  let jwksFetches = 0;
  let override: Response | undefined;

  const fake: FakeProvider = {
    requests,
    jwksFetches: () => jwksFetches,
    idTokenClaims: {},
    userinfo: { sub: "user-1", name: "Ada", email: "ada@idp.test", email_verified: true },
    discovery: {},
    alwaysIdToken: false,
    publicJwk: () => {
      const {
        key_ops: _ops,
        ext: _ext,
        ...jwk
      } = keys.publicKey as JWK & {
        key_ops?: unknown;
        ext?: unknown;
      };
      return jwk;
    },
    signIdToken: (claims) => sign(claims, keys.privateKey),
    rotateKey: async () => {
      keyIndex++;
      keys = await generateJWK("RS256", { kid: `k${keyIndex}` });
    },
    nextTokenResponse: (response) => {
      override = response;
    },
    approve: (authorizationUrl) => {
      const url = new URL(authorizationUrl);
      const q = url.searchParams;
      const code = crypto.randomUUID();
      grants.set(code, {
        clientId: q.get("client_id")!,
        redirectUri: q.get("redirect_uri")!,
        challenge: q.get("code_challenge"),
        method: q.get("code_challenge_method"),
        nonce: q.get("nonce"),
        scope: q.get("scope"),
      });
      const back = new URL(q.get("redirect_uri")!);
      back.searchParams.set("code", code);
      back.searchParams.set("state", q.get("state")!);
      back.searchParams.set("iss", issuer);
      return back;
    },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      const body = request.method === "POST" ? await request.text() : "";
      requests.push({ url, method: request.method, headers: request.headers, body });
      if (url.origin !== issuer) return new Response("not found", { status: 404 });

      switch (url.pathname) {
        case "/.well-known/openid-configuration": {
          return Response.json({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            userinfo_endpoint: `${issuer}/userinfo`,
            jwks_uri: `${issuer}/jwks`,
            authorization_response_iss_parameter_supported: true,
            ...fake.discovery,
          });
        }
        case "/jwks": {
          jwksFetches++;
          return Response.json({ keys: [fake.publicJwk()] });
        }
        case "/userinfo": {
          if (!(request.headers.get("authorization") ?? "").startsWith("Bearer at-")) {
            return new Response(null, { status: 401 });
          }
          return Response.json(fake.userinfo);
        }
        case "/token": {
          if (override) {
            const response = override;
            override = undefined;
            return response;
          }
          return tokenEndpoint(new URLSearchParams(body), request.headers);
        }
      }
      return new Response("not found", { status: 404 });
    },
  };

  async function tokenEndpoint(form: URLSearchParams, headers: Headers): Promise<Response> {
    const fail = (error: string, status = 400) => Response.json({ error }, { status });
    const clientId = authenticate(form, headers);
    if (!clientId) return fail("invalid_client", 401);

    if (form.get("grant_type") === "refresh_token") {
      if (form.get("refresh_token") !== "rt-1") return fail("invalid_grant");
      return Response.json({ access_token: "at-2", token_type: "bearer", expires_in: 3600 });
    }
    if (form.get("grant_type") !== "authorization_code") return fail("unsupported_grant_type");

    const code = form.get("code") ?? "";
    const grant = grants.get(code);
    grants.delete(code);
    if (!grant || grant.clientId !== clientId) return fail("invalid_grant");
    if (form.get("redirect_uri") !== grant.redirectUri) return fail("invalid_grant");
    if (grant.challenge !== null) {
      const verifier = form.get("code_verifier") ?? "";
      const expected = grant.method === "S256" ? await s256(verifier) : verifier;
      if (expected !== grant.challenge) return fail("invalid_grant");
    } else if (form.has("code_verifier")) {
      return fail("invalid_request");
    }

    const accessToken = `at-${crypto.randomUUID()}`;
    const now = Math.floor(Date.now() / 1000);
    const idToken =
      fake.alwaysIdToken || grant.scope?.split(" ").includes("openid")
        ? await fake.signIdToken({
            iss: issuer,
            sub: "user-1",
            aud: clientId,
            iat: now,
            exp: now + 300,
            ...(grant.nonce === null ? {} : { nonce: grant.nonce }),
            at_hash: await atHash(accessToken),
            email: "ada@idp.test",
            email_verified: true,
            ...fake.idTokenClaims,
          })
        : undefined;
    return Response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: "3600",
      refresh_token: "rt-1",
      scope: grant.scope,
      ...(idToken ? { id_token: idToken } : {}),
    });
  }

  function authenticate(form: URLSearchParams, headers: Headers): string | undefined {
    if (tokenAuth === "none") return form.get("client_id") ?? undefined;
    if (tokenAuth === "body") {
      return form.get("client_id") === CLIENT_ID && form.get("client_secret") === CLIENT_SECRET
        ? CLIENT_ID
        : undefined;
    }
    const auth = headers.get("authorization") ?? "";
    const expected = `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`;
    return auth === expected && !form.has("client_secret") ? CLIENT_ID : undefined;
  }

  return fake;
}

/** base64url(SHA-256(text)), computed independently of the library. */
export async function s256(text: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
  );
  return b64url(digest);
}

/** OIDC `at_hash` for an RS256 token: base64url of the left half of SHA-256. */
export async function atHash(accessToken: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken)),
  );
  return b64url(digest.slice(0, digest.length / 2));
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}
