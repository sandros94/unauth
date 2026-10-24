import { beforeAll, beforeEach, describe, expect, expectTypeOf, it } from "vitest";
import { type JWK_oct, generateJWK, verify } from "unjwt";
import { defineJWESession } from "unjwt/session";

import {
  type CacheDriver,
  type WebRequestEvent,
  type UnauthError,
  completeFlow,
  defineSignInHandler,
  isUnauthError,
  startFlow,
} from "../../../src/n/index.ts";
import {
  type AtprotoProvider,
  createDpopProof,
  defineAtprotoHandler,
  defineAtprotoProvider,
} from "../../../src/n/providers/atproto.ts";
import { type CookieJar, cookieJar } from "../_cookies.ts";
import { cookieHeader, formStart, isExpired } from "../_session.ts";
import { s256 } from "../flow/_fake-provider.ts";
import {
  ALICE,
  BOB,
  CAROL,
  CLIENT_ID,
  DNS,
  type FakeAtproto,
  ISSUER,
  PDS,
  PLC,
  REDIRECT_URI,
  createFakeAtproto,
  didDocument,
} from "./_fake-atproto.ts";

let key: JWK_oct<"A256GCM">;
let fake: FakeAtproto;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
});

beforeEach(() => {
  fake = createFakeAtproto();
});

function provider(overrides: Partial<Parameters<typeof defineAtprotoProvider>[0]> = {}) {
  return defineAtprotoProvider({
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    dnsResolver: DNS,
    plcDirectory: PLC,
    ...overrides,
  });
}

/** The application's own reading of the account from the request: the `?login=` query member. */
const loginFromQuery = (event: WebRequestEvent) => ({
  loginHint: new URL(event.req.url).searchParams.get("login") ?? undefined,
});

/** A request to `url` with `cookie`; `form` makes it the `POST` a start naming the account must be. */
function requestFor(url: string | URL, cookie?: string, form = false): Request {
  const headers: Record<string, string> = cookie ? { cookie } : {};
  return form ? formStart(url, { headers }) : new Request(url, cookie ? { headers } : undefined);
}

/** The first leg for `loginHint`: the redirect and the request that carries the flow cookie back. */
async function begin(atproto: AtprotoProvider, loginHint: string | undefined) {
  const response = await startFlow(atproto, formStart(REDIRECT_URI), {
    key,
    redirectUri: REDIRECT_URI,
    fetch: fake.fetch,
    loginHint,
  });
  return { response, location: new URL(response.headers.get("location")!) };
}

/** Both legs for `loginHint`. */
async function signIn(atproto: AtprotoProvider, loginHint: string | undefined) {
  const { response, location } = await begin(atproto, loginHint);
  const back = fake.approve(location);
  const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });
  const headers = new Headers();
  const result = await completeFlow(atproto, request, { key, fetch: fake.fetch, headers });
  return { response, location, back, request, headers, result };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

function served(pathname: string): number {
  return fake.requests.filter((r) => r.url.pathname === pathname).length;
}

describe("sign-in from a handle", () => {
  it("pushes the request with PKCE and DPoP, redirects, then proves the account", async () => {
    const { location, result, headers } = await signIn(provider(), ALICE.handle);

    expect(location.origin + location.pathname).toBe(`${ISSUER}/oauth/authorize`);
    expect(location.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(location.searchParams.get("request_uri")).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    expect([...location.searchParams.keys()].toSorted()).toEqual(["client_id", "request_uri"]);

    const pushed = [...fake.pushed.values()][0]!;
    expect(pushed).toMatchObject({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      scope: "atproto",
      loginHint: ALICE.handle,
    });
    expect(pushed.challenge).toMatch(/^[\w-]{43}$/);
    // The same key signed the PAR and the token request.
    expect(fake.tokenThumbprints).toEqual([pushed.thumbprint]);

    expect(result.identity).toEqual({
      provider: "atproto",
      subject: ALICE.did,
      name: ALICE.handle,
      profile: { did: ALICE.did, handle: ALICE.handle, pds: PDS, authorizationServer: ISSUER },
    });
    expect(result.tokens).toBeUndefined();
    expect(Object.hasOwn(result.identity, "tokens")).toBe(false);
    const line = headers.getSetCookie().find((l) => l.startsWith("__Host-unauth-flow="))!;
    expect(isExpired(line)).toBe(true);
  });

  it("retries once with the nonce the server asks for, on each endpoint", async () => {
    await signIn(provider(), ALICE.handle);

    const par = fake.requests.filter((r) => r.url.pathname === "/oauth/par");
    expect(par).toHaveLength(2);
    const token = fake.requests.filter((r) => r.url.pathname === "/oauth/token");
    // The nonce the PAR answer carried is reused, so the token request needs no retry.
    expect(token).toHaveLength(1);
  });

  it("falls back to the well-known document when DNS has no record", async () => {
    const { result } = await signIn(provider(), BOB.handle);

    expect(result.identity.subject).toBe(BOB.did);
    expect(result.identity.profile.handle).toBe(BOB.handle);
    expect(served("/.well-known/atproto-did")).toBe(1);
    expect(served("/.well-known/did.json")).toBe(1);
  });

  it("accepts an @-prefixed, upper-cased handle", async () => {
    const { result } = await signIn(provider(), "@Alice.Test");
    expect(result.identity.subject).toBe(ALICE.did);
  });

  it("refuses a handle whose DNS names two DIDs, without asking the well-known document", async () => {
    fake.dns.set("two.test", [ALICE.did, BOB.did]);

    const error = await rejection(begin(provider(), "two.test"));

    expect(isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID")).toBe(true);
    expect(served("/.well-known/atproto-did")).toBe(0);
    expect(served("/oauth/par")).toBe(0);
  });

  it("refuses a handle the DID document does not claim", async () => {
    fake.dns.set("mallory.test", [ALICE.did]);

    const error = await rejection(begin(provider(), "mallory.test"));

    expect(isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(400);
    expect(served("/oauth/par")).toBe(0);
  });

  it("refuses a handle that resolves nowhere, a malformed one, and a missing login", async () => {
    for (const login of ["nobody.test", "not a handle", "did:key:abc", "alice.local"]) {
      const error = await rejection(begin(provider(), login));
      expect({ login, invalid: isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID") }).toEqual({
        login,
        invalid: true,
      });
    }
    const missing = await rejection(begin(provider(), undefined));
    expect(isUnauthError(missing, "ERR_AUTHN_LOGIN_HINT_REQUIRED")).toBe(true);
    expect(isUnauthError(missing) && missing.status).toBe(400);
  });

  it("refuses a DID document without a PDS", async () => {
    fake.documents.set(ALICE.did, { ...didDocument(ALICE.did, ALICE.handle), service: [] });

    const error = await rejection(begin(provider(), ALICE.handle));

    expect(isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID")).toBe(true);
  });
});

describe("a remote document naming a plain-http loopback URL", () => {
  const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
  const reachedLoopback = () => fake.requests.some((r) => LOOPBACK.has(r.url.hostname));

  it("refuses a DID document whose PDS is on loopback, without asking it anything", async () => {
    fake.documents.set(ALICE.did, didDocument(ALICE.did, ALICE.handle, "http://127.0.0.1:2375"));

    const error = await rejection(begin(provider(), ALICE.handle));

    expect(isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID")).toBe(true);
    expect(reachedLoopback()).toBe(false);
  });

  it("refuses PDS metadata delegating to a loopback authorization server", async () => {
    const fetch: typeof fake.fetch = async (input, init) => {
      const url = new URL(new Request(input, init).url);
      if (url.origin === PDS && url.pathname === "/.well-known/oauth-protected-resource") {
        return Response.json({ resource: PDS, authorization_servers: ["http://localhost:9000"] });
      }
      return fake.fetch(input, init);
    };
    const error = await rejection(
      startFlow(provider(), formStart(REDIRECT_URI), {
        key,
        redirectUri: REDIRECT_URI,
        fetch,
        loginHint: ALICE.handle,
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(error).toMatchObject({ cause: { reason: "malformed" } });
    expect(reachedLoopback()).toBe(false);
  });

  it("refuses authorization-server metadata naming a loopback endpoint, as a provider error", async () => {
    for (const member of ["pushed_authorization_request_endpoint", "token_endpoint"]) {
      fake.metadata = { [member]: "http://[::1]:6379/internal/admin?cmd=FLUSHALL" };

      const error = await rejection(begin(provider(), ALICE.handle));

      expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
      expect(isUnauthError(error) && error.status).toBe(502);
      expect(reachedLoopback()).toBe(false);
      expect(served("/oauth/par")).toBe(0);
    }
  });

  it("follows them when the provider opts in with allowHttp, for a PDS run locally", async () => {
    fake.documents.set(ALICE.did, didDocument(ALICE.did, ALICE.handle, "http://127.0.0.1:2583"));
    await rejection(begin(provider({ allowHttp: true }), ALICE.handle));
    expect(fake.requests.map((r) => r.url.href)).toContain(
      "http://127.0.0.1:2583/.well-known/oauth-protected-resource",
    );

    fake = createFakeAtproto();
    fake.metadata = { pushed_authorization_request_endpoint: "http://localhost:2583/oauth/par" };
    await rejection(begin(provider({ allowHttp: true }), ALICE.handle));
    expect(fake.requests.map((r) => r.url.href)).toContain("http://localhost:2583/oauth/par");
  });
});

describe("the DID document cache", () => {
  it("keeps only the handle and the PDS of a document, however large it comes", async () => {
    const padding = Array.from({ length: 20_000 }, () => ({}));
    fake.documents.set(ALICE.did, { ...didDocument(ALICE.did, ALICE.handle), padding });
    const stored = new Map<string, unknown>();
    const cache: CacheDriver = {
      get: <T>(name: string) => (stored.get(name) as T | undefined) ?? null,
      set: (name, value) => void stored.set(name, value),
    };

    const { result } = await signInWith({ cache });
    expect(result.identity.profile).toMatchObject({
      did: ALICE.did,
      handle: ALICE.handle,
      pds: PDS,
    });

    const [entry] = [...stored.entries()].filter(([name]) =>
      name.startsWith("unauth:atproto-did:"),
    );
    expect(entry).toBeDefined();
    expect(JSON.stringify(entry![1]).length).toBeLessThan(512);
    expect(entry![1]).toMatchObject({
      value: { id: ALICE.did, handle: ALICE.handle, pds: PDS },
    });
  });

  async function signInWith(extra: Partial<Parameters<typeof startFlow>[2]>) {
    const atproto = provider();
    const response = await startFlow(atproto, formStart(REDIRECT_URI), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      loginHint: ALICE.handle,
      ...extra,
    });
    const back = fake.approve(new URL(response.headers.get("location")!));
    const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });
    const result = await completeFlow(atproto, request, {
      key,
      fetch: fake.fetch,
      headers: new Headers(),
      ...extra,
    });
    return { result };
  }
});

describe("sign-in from a DID", () => {
  it("keeps the handle only when it resolves back to the DID", async () => {
    const verified = await signIn(provider(), ALICE.did);
    expect(verified.result.identity.profile.handle).toBe(ALICE.handle);

    // Carol's document claims a handle nothing resolves.
    const unverified = await signIn(provider(), CAROL.did);
    expect(unverified.result.identity.subject).toBe(CAROL.did);
    expect(unverified.result.identity.profile.handle).toBeUndefined();
    expect(unverified.result.identity.name).toBeUndefined();
  });

  it("sends the DID as typed as login_hint and refuses a token naming another account", async () => {
    fake.token = { sub: BOB.did };

    const error = await rejection(signIn(provider(), ALICE.did));

    expect([...fake.pushed.values()][0]!.loginHint).toBe(ALICE.did);
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });
});

describe("sign-in from a server", () => {
  it("starts at a PDS without a login_hint and verifies the account's PDS afterwards", async () => {
    const { result } = await signIn(provider(), PDS);

    expect([...fake.pushed.values()][0]!.loginHint).toBeNull();
    expect(result.identity.subject).toBe(ALICE.did);
    expect(result.identity.profile).toEqual({
      did: ALICE.did,
      handle: ALICE.handle,
      pds: PDS,
      authorizationServer: ISSUER,
    });
  });

  it("starts at an authorization server with no protected resource metadata", async () => {
    const { result } = await signIn(provider(), `${ISSUER}/`);
    expect(result.identity.subject).toBe(ALICE.did);
  });

  it("refuses an account whose PDS delegates to another authorization server", async () => {
    fake.documents.set(ALICE.did, didDocument(ALICE.did, ALICE.handle, "https://other-pds.test"));

    const error = await rejection(signIn(provider(), `${ISSUER}/`));

    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("refuses a URL that is no atproto server", async () => {
    const error = await rejection(begin(provider(), "https://nowhere.test"));
    expect(isUnauthError(error, "ERR_AUTHN_LOGIN_HINT_INVALID")).toBe(true);
  });
});

describe("the pushed authorization request", () => {
  it("reports a refusal as ERR_AUTHN_PROVIDER_REFUSED with the OAuth error", async () => {
    fake.nextParResponse(
      Response.json({ error: "invalid_client_metadata", error_description: "no" }, { status: 400 }),
    );

    const error = await rejection(begin(provider(), ALICE.handle));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_REFUSED")).toBe(true);
    expect(isUnauthError(error) && error.cause).toEqual({
      error: "invalid_client_metadata",
      error_description: "no",
      error_uri: undefined,
    });
  });

  it("reports an outage and an answer without request_uri as the provider's failure", async () => {
    fake.nextParResponse(new Response("down", { status: 503 }));
    const down = await rejection(begin(provider(), ALICE.handle));
    expect(isUnauthError(down, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(down) && down.cause).toEqual({ reason: "status", status: 503 });

    fake.nextParResponse(
      Response.json({ expires_in: 60 }, { status: 201, headers: { "dpop-nonce": "n1" } }),
    );
    const empty = await rejection(begin(provider(), ALICE.handle));
    expect(isUnauthError(empty, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(empty) && empty.cause).toEqual({ reason: "malformed", status: 201 });
    expect((empty as Error).message).toMatch(/no request_uri/);

    fake.nextParResponse(Response.json({ request_uri: "urn:x" }, { status: 201 }));
    const noNonce = await rejection(begin(provider(), ALICE.handle));
    expect(isUnauthError(noNonce, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(noNonce) && noNonce.cause).toEqual({ reason: "malformed", status: 201 });
    expect((noNonce as Error).message).toMatch(/no DPoP nonce/);
  });
});

describe("the callback", () => {
  it("refuses an iss naming another server", async () => {
    const { response, location } = await begin(provider(), ALICE.handle);
    const back = fake.approve(location);
    back.searchParams.set("iss", "https://evil.test");
    const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });

    const error = await rejection(
      completeFlow(provider(), request, { key, fetch: fake.fetch, headers: new Headers() }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(served("/oauth/token")).toBe(0);
  });

  it("refuses a token that is not DPoP-bound, lacks the atproto scope, or is refused", async () => {
    fake.token = { token_type: "Bearer" };
    expect(
      isUnauthError(await rejection(signIn(provider(), ALICE.handle)), "ERR_AUTHN_TOKEN_EXCHANGE"),
    ).toBe(true);

    fake.token = { scope: "transition:generic" };
    expect(
      isUnauthError(await rejection(signIn(provider(), ALICE.handle)), "ERR_AUTHN_TOKEN_EXCHANGE"),
    ).toBe(true);

    fake.token = {};
    fake.nextTokenResponse(Response.json({ error: "invalid_grant" }, { status: 400 }));
    const refused = await rejection(signIn(provider(), ALICE.handle));
    expect(isUnauthError(refused, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
    expect(isUnauthError(refused) && refused.cause).toMatchObject({ error: "invalid_grant" });
  });

  it("reports a refusal sent back to the redirect URI", async () => {
    const { response, location } = await begin(provider(), ALICE.handle);
    const back = fake.approve(location);
    back.searchParams.delete("code");
    back.searchParams.set("error", "access_denied");
    const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });

    const error = await rejection(
      completeFlow(provider(), request, { key, fetch: fake.fetch, headers: new Headers() }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_REFUSED")).toBe(true);
  });
});

describe("discovery", () => {
  it.each([
    ["response_types_supported", ["token"]],
    ["grant_types_supported", ["authorization_code"]],
    ["code_challenge_methods_supported", ["plain"]],
    ["token_endpoint_auth_methods_supported", ["private_key_jwt"]],
    ["token_endpoint_auth_signing_alg_values_supported", ["RS256"]],
    ["token_endpoint_auth_signing_alg_values_supported", ["ES256", "none"]],
    ["scopes_supported", ["transition:generic"]],
    ["dpop_signing_alg_values_supported", ["RS256"]],
    ["authorization_response_iss_parameter_supported", false],
    ["require_pushed_authorization_requests", undefined],
    ["client_id_metadata_document_supported", "true"],
    ["require_request_uri_registration", false],
  ])(
    "refuses an authorization server whose metadata breaks the atproto profile on %s = %j",
    async (member, value) => {
      fake.metadata = { [member]: value };

      const error = await rejection(begin(provider(), ALICE.handle));

      expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
      expect((error as Error).message).toContain(`"${member}"`);
      expect(served("/oauth/par")).toBe(0);
    },
  );

  it("keeps DID documents and server metadata between the legs and across sign-ins", async () => {
    const atproto = provider();
    await signIn(atproto, ALICE.handle);
    await signIn(atproto, ALICE.handle);

    expect(served("/.well-known/oauth-protected-resource")).toBe(1);
    expect(served("/.well-known/oauth-authorization-server")).toBe(1);
    expect(served(`/${ALICE.did}`)).toBe(1);
    // The handle itself is looked up on every sign-in.
    expect(served("/dns-query")).toBe(2);
  });
});

describe("the client", () => {
  it("carries the metadata document of a https client id", () => {
    const document = provider({ clientName: "Playground" }).client.metadata;

    expect(document).toEqual({
      client_id: CLIENT_ID,
      application_type: "web",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: [REDIRECT_URI],
      scope: "atproto",
      dpop_bound_access_tokens: true,
      token_endpoint_auth_method: "none",
      client_name: "Playground",
    });
  });

  it("derives the development client from a loopback redirect URI and publishes nothing", () => {
    const atproto = defineAtprotoProvider({ redirectUri: "http://127.0.0.1:3000/auth/atproto" });

    expect(atproto.client.development).toBe(true);
    expect(atproto.client.id).toBe(
      "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fauth%2Fatproto&scope=atproto",
    );
    expect(atproto.client.metadata).toBeUndefined();
  });

  it("derives the development client from an http: loopback client id, mapping a devOrigins callback to 127.0.0.1", () => {
    const atproto = defineAtprotoProvider({
      clientId: "http://localhost:3000/oauth-client-metadata.json",
      redirectUri: "http://localhost:3000/auth/atproto",
      devOrigins: ["http://localhost:3000"],
    });

    expect(atproto.client.development).toBe(true);
    expect(atproto.client.redirectUri).toBe("http://127.0.0.1:3000/auth/atproto");
    expect(atproto.redirectUri).toBe("http://127.0.0.1:3000/auth/atproto");
    expect(atproto.client.id).toBe(
      "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fauth%2Fatproto&scope=atproto",
    );
  });

  it("refuses the configurations that cannot work", () => {
    expect(() => defineAtprotoProvider({ redirectUri: REDIRECT_URI })).toThrow(
      /development client/,
    );
    expect(() =>
      defineAtprotoProvider({
        clientId: "https://app.test:8443/m.json",
        redirectUri: REDIRECT_URI,
      }),
    ).toThrow(/without a port/);
    expect(() =>
      defineAtprotoProvider({
        clientId: CLIENT_ID,
        redirectUri: "http://127.0.0.1:3000/auth/atproto",
      }),
    ).toThrow(/must be https:/);
    expect(() =>
      defineAtprotoProvider({ redirectUri: "http://localhost:3000/auth/atproto" }),
    ).toThrow(/"devOrigins"/);
    expect(() =>
      defineAtprotoProvider({
        redirectUri: "http://localhost:3000/auth/atproto",
        devOrigins: ["http://localhost:4000"],
      }),
    ).toThrow(/"devOrigins"/);
    expect(() =>
      defineAtprotoProvider({
        redirectUri: "http://localhost:3000/auth/atproto",
        devOrigins: ["localhost"],
      }),
    ).toThrow(/must be origins/);
    expect(() =>
      defineAtprotoProvider({
        clientId: "http://dev.test/m.json",
        redirectUri: "http://127.0.0.1:3000/auth/atproto",
      }),
    ).toThrow(/https:/);
    expect(() => provider({ scopes: ["transition:generic"] })).toThrow(/"atproto" scope/);
  });

  it("moves a start on a devOrigins origin to the callback's host before setting any cookie", async () => {
    const atproto = defineAtprotoProvider({
      redirectUri: "http://localhost:3000/auth/atproto",
      devOrigins: ["http://localhost:3000"],
      dnsResolver: DNS,
      plcDirectory: PLC,
    });

    // No redirectUri on the start options: the provider's registered one is used.
    const moved = await startFlow(
      atproto,
      formStart("http://localhost:3000/auth/atproto?login=x"),
      { key, fetch: fake.fetch, loginHint: "x" },
    );
    expect(moved.status).toBe(302);
    const movedTo = new URL(moved.headers.get("location")!);
    const intent = movedTo.searchParams.get("unauth_intent")!;
    expect(intent).toMatch(/^eyJ/);
    expect(movedTo.href).toBe(
      `http://127.0.0.1:3000/auth/atproto?login=x&unauth_intent=${encodeURIComponent(intent)}`,
    );
    expect(moved.headers.getSetCookie()).toEqual([]);
    expect(fake.requests).toHaveLength(0);

    // The same hostname on another port is another origin: the start runs where it is.
    const otherPort = await startFlow(
      atproto,
      formStart("http://localhost:3987/auth/atproto?login=x"),
      { key, fetch: fake.fetch, loginHint: ALICE.handle },
    );
    expect(new URL(otherPort.headers.get("location")!).origin).toBe(ISSUER);
    expect(otherPort.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);

    // Not listed: the start runs where it is, and the flow cookie is set on that host. A handler
    // naming the devOrigins form of the callback is accepted as the same callback.
    const stayed = await startFlow(atproto, formStart("http://dev.test:3000/auth/atproto"), {
      key,
      redirectUri: "http://localhost:3000/auth/atproto",
      fetch: fake.fetch,
      loginHint: ALICE.handle,
    });
    expect(stayed.status).toBe(302);
    expect(new URL(stayed.headers.get("location")!).origin).toBe(ISSUER);
    expect(stayed.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
  });

  it("refuses to run at another callback URL than the one it published", async () => {
    const error = await rejection(
      startFlow(provider(), formStart("https://app.test/other"), {
        key,
        redirectUri: "https://app.test/other",
        fetch: fake.fetch,
        loginHint: ALICE.handle,
      }),
    );
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });
});

describe("createDpopProof", () => {
  it("signs an ES256 proof carrying its public key, the method, the bare URL and the token hash", async () => {
    const { result } = await signIn(provider(), ALICE.handle);
    expect(result.identity.subject).toBe(ALICE.did);
    const { privateKey, publicKey } = await generateJWK("ES256");
    const proof = await createDpopProof(
      { ...privateKey, alg: "ES256" },
      {
        htm: "get",
        htu: `${PDS}/xrpc/com.atproto.server.getSession?x=1#f`,
        nonce: "n9",
        accessToken: "at-1",
        now: () => 1_700_000_000_000,
      },
    );

    const { payload, protectedHeader } = await verify(proof, publicKey, {
      algorithms: ["ES256"],
      validateClaims: false,
    });
    expect(protectedHeader.typ).toBe("dpop+jwt");
    expect(protectedHeader.jwk).toMatchObject({ kty: "EC", crv: "P-256", x: publicKey.x });
    expect(payload).toMatchObject({
      htm: "GET",
      htu: `${PDS}/xrpc/com.atproto.server.getSession`,
      nonce: "n9",
      iat: 1_700_000_000,
      ath: await s256("at-1"),
    });
    expect(payload.jti).toMatch(/^[\w-]{43}$/);
  });
});

describe("a devOrigins round trip through defineSignInHandler", () => {
  it("relocates the start, completes on the loopback IP and hands the result back to localhost", async () => {
    const atproto = defineAtprotoProvider({
      clientId: "http://localhost:3000/oauth-client-metadata.json",
      redirectUri: "http://localhost:3000/auth/atproto",
      devOrigins: ["http://localhost:3000"],
      dnsResolver: DNS,
      plcDirectory: PLC,
    });
    const seen: { host: string; did: string }[] = [];
    const handler = defineSignInHandler(atproto, {
      key,
      fetch: fake.fetch,
      onStart: loginFromQuery,
      onSuccess: (event, result) => {
        seen.push({ host: new URL(event.req.url).hostname, did: result.identity.subject });
        return { did: result.identity.subject };
      },
    });
    const call = async (url: string | URL, cookie?: string, form = false) => {
      const res = { headers: new Headers() };
      const answer = await handler({ req: requestFor(url, cookie, form), res });
      return { answer, res };
    };

    // 1. Start on localhost: moved to 127.0.0.1, nothing set.
    const moved = await call(
      `http://localhost:3000/auth/atproto?login=${ALICE.handle}`,
      undefined,
      true,
    );
    const movedTo = new URL((moved.answer as Response).headers.get("location")!);
    const intent = movedTo.searchParams.get("unauth_intent")!;
    expect(movedTo.href).toBe(
      `http://127.0.0.1:3000/auth/atproto?login=${ALICE.handle}&unauth_intent=${encodeURIComponent(intent)}`,
    );
    expect(moved.res.headers.getSetCookie()).toEqual([]);

    // 2. Start on 127.0.0.1: the real first leg, flow cookie set there.
    const started = await call(movedTo);
    const startResponse = started.answer as Response;
    expect(new URL(startResponse.headers.get("location")!).origin).toBe(ISSUER);
    const cookie = cookieHeader(startResponse.headers);
    expect(cookie).toMatch(/unauth-flow=/);

    // 3. Callback on 127.0.0.1: completed, then handed back to localhost in a sealed token.
    const back = fake.approve(startResponse.headers.get("location")!);
    const completed = await call(back, cookie);
    const handoff = new URL((completed.answer as Response).headers.get("location")!);
    expect(handoff.origin).toBe("http://localhost:3000");
    expect(handoff.pathname).toBe("/auth/atproto");
    expect(handoff.searchParams.get("unauth_handoff")).toMatch(/^eyJ/);
    expect(seen).toEqual([]);
    const cleared = completed.res.headers.getSetCookie().find((l) => l.includes("unauth-flow="));
    expect(cleared && isExpired(cleared)).toBe(true);

    // 4. The handoff on localhost: onSuccess runs there, once.
    const home = await call(handoff);
    expect(home.answer).toEqual({ did: ALICE.did });
    expect(seen).toEqual([{ host: "localhost", did: ALICE.did }]);

    const replay = await call(handoff);
    expect((replay.answer as Response).status).toBe(401);
    const forged = await call(`http://localhost:3000/auth/atproto?unauth_handoff=eyJ.forged.token`);
    expect((forged.answer as Response).status).toBe(401);
    expect(seen).toHaveLength(1);
  });

  describe("keeps the intent made on localhost", () => {
    const LOCAL = "http://localhost:3987";
    interface Session {
      userId: string;
      provider: string;
      subject: string;
      name?: string;
      signedInAt: number;
    }
    const userSession = () =>
      defineJWESession<Session, "1h">({
        key,
        name: "app",
        maxAge: "1h",
        cookie: { secure: false },
      });

    /** A browser on the dev server: one cookie jar per host, as cookies are kept. */
    function browser(handler: (event: WebRequestEvent) => Promise<unknown>) {
      const jars = new Map<string, CookieJar>();
      const jarOf = (url: URL): CookieJar => {
        const jar = jars.get(url.hostname) ?? cookieJar();
        jars.set(url.hostname, jar);
        return jar;
      };
      return {
        jarOf,
        visit: async (to: string | URL, form = false) => {
          const url = new URL(to);
          const jar = jarOf(url);
          const cookie = jar.toString();
          const res = { headers: new Headers() };
          const answer = await handler({ req: requestFor(url, cookie, form), res });
          jar.update(res.headers);
          if (answer instanceof Response) jar.update(answer.headers);
          return { answer, res };
        },
      };
    }

    /** From the start on localhost to the handoff back there: the answer and the response headers of each step. */
    async function devRoundTrip(visit: ReturnType<typeof browser>["visit"]) {
      const moved = await visit(`${LOCAL}/auth/atproto?login=${ALICE.handle}`, true);
      const movedTo = new URL((moved.answer as Response).headers.get("location")!);
      const intent = movedTo.searchParams.get("unauth_intent")!;
      expect(intent).toMatch(/^eyJ/);
      expect(movedTo.href).toBe(
        `http://127.0.0.1:3987/auth/atproto?login=${ALICE.handle}&unauth_intent=${encodeURIComponent(intent)}`,
      );
      const started = await visit(movedTo);
      const back = fake.approve((started.answer as Response).headers.get("location")!);
      const completed = await visit(back);
      const handoff = new URL((completed.answer as Response).headers.get("location")!);
      expect(handoff.origin).toBe(LOCAL);
      return visit(handoff);
    }

    const devConfig = {
      clientId: `${LOCAL}/oauth-client-metadata.json`,
      redirectUri: `${LOCAL}/auth/atproto`,
      devOrigins: [LOCAL],
      dnsResolver: DNS,
      plcDirectory: PLC,
    };

    it("links the account to the user signed in on localhost, leaving the session as it is", async () => {
      const session = userSession();
      const links: unknown[] = [];
      const handler = defineAtprotoHandler({
        ...devConfig,
        key,
        fetch: fake.fetch,
        onStart: async (event) => {
          const current = await session.use(event);
          return {
            ...loginFromQuery(event),
            ...(current.id ? { memo: { userId: current.data.userId } } : {}),
          };
        },
        onSuccess: async (event, { identity, memo }) => {
          const current = await session.use(event);
          if (memo) {
            links.push(memo);
            return "linked";
          }
          await current.clear();
          await current.update({
            userId: "new",
            provider: identity.provider,
            subject: identity.subject,
            signedInAt: 2,
          });
          return "signed in";
        },
      });
      const { jarOf, visit } = browser(handler);

      const seed = { headers: new Headers() };
      const seeded = await session.use({ req: new Request(LOCAL), res: seed });
      const data: Session = { userId: "u1", provider: "password", subject: "u1", signedInAt: 1 };
      await seeded.update(data);
      jarOf(new URL(LOCAL)).update(seed.headers);
      const before = jarOf(new URL(LOCAL)).toString();

      const home = await devRoundTrip(visit);
      expect(home.answer).toBe("linked");
      expect(links).toEqual([{ userId: "u1" }]);
      expect(home.res.headers.getSetCookie().filter((l) => l.startsWith("app="))).toEqual([]);
      expect(jarOf(new URL(LOCAL)).toString()).toBe(before);
      const after = await session.use({
        req: new Request(LOCAL, { headers: { cookie: before } }),
        res: { headers: new Headers() },
      });
      expect(after.id).toBe(seeded.id);
      expect(after.data).toMatchObject(data);
    });

    it("keeps the redirect onStart asked for", async () => {
      const session = userSession();
      const handler = defineAtprotoHandler({
        ...devConfig,
        key,
        fetch: fake.fetch,
        onStart: (event) => ({
          ...loginFromQuery(event),
          ...(new URL(event.req.url).hostname === "localhost" ? { redirect: "/after" } : {}),
        }),
        onSuccess: async (event, { identity }) => {
          const current = await session.use(event);
          await current.clear();
          await current.update({
            userId: "u2",
            provider: identity.provider,
            subject: identity.subject,
            signedInAt: 2,
          });
        },
      });
      const { jarOf, visit } = browser(handler);

      const home = await devRoundTrip(visit);
      expect((home.answer as Response).headers.get("location")).toBe("/after");
      const signedIn = await session.use({
        req: new Request(LOCAL, { headers: { cookie: jarOf(new URL(LOCAL)).toString() } }),
        res: { headers: new Headers() },
      });
      expect(signedIn.data).toMatchObject({ subject: ALICE.did, userId: "u2" });
    });
  });
});

describe("through defineSignInHandler", () => {
  it("takes the login from onStart and signs the account in", async () => {
    const atproto = provider();
    const handler = defineSignInHandler(atproto, {
      key,
      fetch: fake.fetch,
      onStart: loginFromQuery,
      onSuccess: (_event, result) => ({ did: result.identity.subject }),
    });
    const start = await handler({
      req: formStart(`${REDIRECT_URI}?login=${ALICE.handle}`),
      res: { headers: new Headers() },
    });
    expect(start).toBeInstanceOf(Response);
    const response = start as Response;
    expect(response.status).toBe(302);

    const back = fake.approve(response.headers.get("location")!);
    const done = await handler({
      req: new Request(back, { headers: { cookie: cookieHeader(response.headers) } }),
      res: { headers: new Headers() },
    });
    expect(done).toEqual({ did: ALICE.did });

    const missing = await handler({
      req: new Request(REDIRECT_URI),
      res: { headers: new Headers() },
    });
    expect((missing as Response).status).toBe(400);
  });
});

describe("defineAtprotoHandler", () => {
  interface SignedIn {
    provider: string;
    subject: string;
    name?: string;
  }
  const auth = () => defineJWESession<SignedIn, "1h">({ key, name: "unauth", maxAge: "1h" });
  const replaceSession =
    (session: ReturnType<typeof auth>) =>
    async (
      event: WebRequestEvent,
      { identity }: { identity: { provider: string; subject: string; name?: string } },
    ): Promise<void> => {
      const current = await session.use(event);
      await current.clear();
      await current.update({
        provider: identity.provider,
        subject: identity.subject,
        ...(identity.name ? { name: identity.name } : {}),
      });
    };

  /** Runs `handler` on `url`, the way a runtime would: the answer and the response's headers. */
  async function run(
    handler: (event: WebRequestEvent) => Promise<unknown>,
    url: string | URL,
    cookie?: string,
    form = false,
  ) {
    const res = { headers: new Headers() };
    const answer = await handler({ req: requestFor(url, cookie, form), res });
    return { answer, res };
  }

  /** Both legs from `url`, then the session the browser ends up with. */
  async function roundTrip(
    handler: (event: WebRequestEvent) => Promise<unknown>,
    session: ReturnType<typeof auth>,
    url: string,
  ) {
    const started = await run(handler, url, undefined, true);
    const start = started.answer as Response;
    expect(start.status).toBe(302);
    const back = fake.approve(start.headers.get("location")!);
    const done = await run(handler, back, cookieHeader(start.headers));
    expect((done.answer as Response).status).toBe(302);
    const current = await session.use({
      req: new Request(REDIRECT_URI, { headers: { cookie: cookieHeader(done.res.headers) } }),
      res: { headers: new Headers() },
    });
    return current.data;
  }

  it("signs the account onStart names in and writes the session, from an inline config", async () => {
    const session = auth();
    const handler = defineAtprotoHandler({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      dnsResolver: DNS,
      plcDirectory: PLC,
      key,
      fetch: fake.fetch,
      onStart: loginFromQuery,
      onSuccess: replaceSession(session),
    });

    const data = await roundTrip(handler, session, `${REDIRECT_URI}?login=${ALICE.handle}`);
    expect(data).toMatchObject({ provider: "atproto", subject: ALICE.did, name: ALICE.handle });
    expect([...fake.pushed.values()][0]?.loginHint).toBe(ALICE.handle);
  });

  it("signs in through a provider defined elsewhere", async () => {
    const session = auth();
    const handler = defineAtprotoHandler({
      provider: provider(),
      key,
      fetch: fake.fetch,
      onStart: loginFromQuery,
      onSuccess: replaceSession(session),
    });

    const data = await roundTrip(handler, session, `${REDIRECT_URI}?login=${ALICE.handle}`);
    expect(data).toMatchObject({ provider: "atproto", subject: ALICE.did, name: ALICE.handle });
  });

  it("lets an explicit onStart login win over the query, and keeps the rest of its intent", async () => {
    const handler = defineAtprotoHandler({
      provider: provider(),
      key,
      fetch: fake.fetch,
      onStart: () => ({ loginHint: ALICE.handle, redirect: "/account" }),
      onSuccess: (_event, result) => ({ did: result.identity.subject, redirect: result.redirect }),
    });

    const started = await run(handler, `${REDIRECT_URI}?login=nobody.test`, undefined, true);
    const start = started.answer as Response;
    expect([...fake.pushed.values()][0]?.loginHint).toBe(ALICE.handle);
    const back = fake.approve(start.headers.get("location")!);
    const done = await run(handler, back, cookieHeader(start.headers));
    expect(done.answer).toEqual({ did: ALICE.did, redirect: "/account" });
  });

  it("reads nothing from the request itself: a query login without onStart is no account", async () => {
    const errors: UnauthError[] = [];
    const handler = defineAtprotoHandler({
      provider: provider(),
      key,
      fetch: fake.fetch,
      onStart: () => ({ redirect: "/account" }),
      onSuccess: () => "ok",
      onError: (_event, error) => {
        errors.push(error);
        return new Response(null, { status: error.status });
      },
    });

    const started = await run(handler, `${REDIRECT_URI}?login=${ALICE.handle}`, undefined, true);
    expect((started.answer as Response).status).toBe(400);
    expect(errors.map((error) => error.code)).toEqual(["ERR_AUTHN_LOGIN_HINT_REQUIRED"]);
    expect(served("/oauth/par")).toBe(0);
  });

  it("refuses a sign-in with no login anywhere", async () => {
    const errors: UnauthError[] = [];
    const handler = defineAtprotoHandler({
      provider: provider(),
      key,
      fetch: fake.fetch,
      onSuccess: () => "ok",
      onError: (_event, error) => {
        errors.push(error);
        return new Response(null, { status: error.status });
      },
    });

    const { answer } = await run(handler, REDIRECT_URI);
    expect((answer as Response).status).toBe(400);
    expect(errors.map((error) => error.code)).toEqual(["ERR_AUTHN_LOGIN_HINT_REQUIRED"]);
    expect(served("/oauth/par")).toBe(0);
  });

  it("runs a devOrigins round trip with the callback given once", async () => {
    const seen: string[] = [];
    const handler = defineAtprotoHandler({
      clientId: "http://localhost:3000/oauth-client-metadata.json",
      redirectUri: "http://localhost:3000/auth/atproto",
      devOrigins: ["http://localhost:3000"],
      dnsResolver: DNS,
      plcDirectory: PLC,
      key,
      fetch: fake.fetch,
      onStart: loginFromQuery,
      onSuccess: (event, result) => {
        seen.push(`${new URL(event.req.url).hostname} ${result.identity.subject}`);
        return "ok";
      },
    });

    const moved = await run(
      handler,
      `http://localhost:3000/auth/atproto?login=${ALICE.handle}`,
      undefined,
      true,
    );
    const movedTo = new URL((moved.answer as Response).headers.get("location")!);
    expect(movedTo.origin).toBe("http://127.0.0.1:3000");
    const started = await run(handler, movedTo);
    const start = started.answer as Response;
    expect([...fake.pushed.values()][0]?.redirectUri).toBe("http://127.0.0.1:3000/auth/atproto");
    const back = fake.approve(start.headers.get("location")!);
    const completed = await run(handler, back, cookieHeader(start.headers));
    const handoff = new URL((completed.answer as Response).headers.get("location")!);
    expect(handoff.origin).toBe("http://localhost:3000");
    expect((await run(handler, handoff)).answer).toBe("ok");
    expect(seen).toEqual([`localhost ${ALICE.did}`]);
  });

  it("types the provider part: an inline config or a provider, not both", () => {
    const both = () =>
      // @ts-expect-error the provider's options belong to the provider
      defineAtprotoHandler({
        provider: provider(),
        clientId: CLIENT_ID,
        key,
        onSuccess: () => "ok",
      });
    // @ts-expect-error an inline config needs its redirectUri
    const partial = () => defineAtprotoHandler({ clientId: CLIENT_ID, key, onSuccess: () => "ok" });
    expectTypeOf(both).toBeFunction();
    expectTypeOf(partial).toBeFunction();
  });

  it("refuses a provider given with the provider's options, naming them", () => {
    const both = { provider: provider(), devOrigins: ["http://localhost:3000"], clientName: "App" };
    let refusal: unknown;
    try {
      // @ts-expect-error the provider's options belong to the provider
      defineAtprotoHandler({ ...both, key, onSuccess: () => "ok" });
    } catch (error) {
      refusal = error;
    }
    expect(isUnauthError(refusal, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((refusal as Error).message).toContain(`"devOrigins", "clientName"`);
    expect(() =>
      defineAtprotoHandler({
        provider: provider(),
        redirectUri: REDIRECT_URI,
        key,
        onSuccess: () => "ok",
      }),
    ).not.toThrow();
  });
});
