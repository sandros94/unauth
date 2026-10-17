import { describe, expect, it } from "vitest";
import { generateJWK, verify } from "unjwt";

import {
  type Provider,
  type ProviderDescriptor,
  buildAuthorizationUrl,
  createNonce,
  createPkce,
  createState,
  defineProvider,
  exchangeCode,
  fetchProfile,
  isUnauthError,
  refreshTokens,
} from "../../../src/n/index.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider, s256 } from "./_fake-provider.ts";

const BASE64URL = /^[\w-]+$/;

function github(overrides: Partial<ProviderDescriptor> = {}): Provider {
  return defineProvider({
    id: "fake",
    kind: "oauth2",
    client: { id: CLIENT_ID, secret: CLIENT_SECRET },
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
    scopes: ["read:user", "user:email"],
    tokenAuth: "basic",
    profile: async ({ userinfo }) => ({ subject: String(userinfo?.sub), profile: userinfo ?? {} }),
    ...overrides,
  });
}

/** Runs the authorization leg against the fake; returns the code and its PKCE verifier. */
async function codeFor(fake: Awaited<ReturnType<typeof createFakeProvider>>, provider: Provider) {
  const pkce = await createPkce();
  const url = buildAuthorizationUrl(provider, {
    redirectUri: "https://app.test/auth/fake",
    state: createState(),
    pkce,
  });
  return { code: fake.approve(url).searchParams.get("code")!, codeVerifier: pkce.verifier };
}

describe("random values", () => {
  it("createPkce returns an S256 pair whose challenge is the verifier's SHA-256", async () => {
    const pkce = await createPkce();

    expect(pkce.method).toBe("S256");
    expect(pkce.verifier).toMatch(BASE64URL);
    expect(pkce.verifier.length).toBeGreaterThanOrEqual(43);
    expect(pkce.verifier.length).toBeLessThanOrEqual(128);
    expect(pkce.challenge).toBe(await s256(pkce.verifier));
    expect((await createPkce()).verifier).not.toBe(pkce.verifier);
  });

  it("createState and createNonce are distinct 256-bit base64url strings", () => {
    const values = [createState(), createState(), createNonce(), createNonce()];

    for (const value of values) expect(value).toMatch(/^[\w-]{43}$/);
    expect(new Set(values).size).toBe(4);
  });
});

describe("defineProvider", () => {
  it("fills secure defaults", () => {
    const provider = github({ tokenAuth: undefined });

    expect(provider.pkce).toBe("S256");
    expect(provider.nonce).toBe(false);
    expect(provider.scopeSeparator).toBe(" ");
    expect(provider.responseMode).toBe("query");
    expect(provider.tokenAuth).toBe("basic");
    expect(
      github({ kind: "oidc", issuer: ISSUER, jwks: `${ISSUER}/jwks`, scopes: ["openid"] }).nonce,
    ).toBe(true);
  });

  it.each([
    ["no token endpoint", { token: undefined }],
    ["an http endpoint", { token: "http://idp.test/token" }],
    ["basic auth without a secret", { client: { id: CLIENT_ID } }],
    ["oidc without an issuer", { kind: "oidc" as const }],
    ["an empty id", { id: "" }],
  ])("refuses %s with ERR_UNAUTH_CONFIG_INVALID", (_label, overrides) => {
    let error: unknown;
    try {
      github(overrides);
    } catch (error_) {
      error = error_;
    }
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(500);
  });

  it("requires the openid scope on an OpenID Connect provider", () => {
    let error: unknown;
    try {
      github({ kind: "oidc", issuer: ISSUER, jwks: `${ISSUER}/jwks`, scopes: ["profile"] });
    } catch (error_) {
      error = error_;
    }
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("accepts plain http on a loopback host", () => {
    expect(() => github({ token: "http://127.0.0.1:8080/token" })).not.toThrow();
  });

  it.each([
    ["a LAN IP", "http://192.168.1.20:8080/token", "192.168.1.20"],
    ["a local domain", "http://idp.lan/token", "IDP.lan"],
  ])("accepts plain http on %s only when insecureHosts lists it", (_label, token, host) => {
    expect(
      isUnauthError(
        thrown(() => github({ token })),
        "ERR_UNAUTH_CONFIG_INVALID",
      ),
    ).toBe(true);
    expect(
      isUnauthError(
        thrown(() => github({ token, insecureHosts: ["other.lan"] })),
        "ERR_UNAUTH_CONFIG_INVALID",
      ),
    ).toBe(true);
    expect(github({ token, insecureHosts: [host] }).insecureHosts).toEqual([host]);
  });

  it("matches insecureHosts exactly, never as a suffix", () => {
    const error = thrown(() =>
      github({ token: "http://evil.idp.lan/token", insecureHosts: ["idp.lan"] }),
    );
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("never needs insecureHosts for https", () => {
    expect(() => github({ token: "https://idp.lan/token" })).not.toThrow();
    expect(() =>
      github({ token: "https://idp.lan/token", insecureHosts: ["other.lan"] }),
    ).not.toThrow();
  });

  it("lets a provider leave out the openid scope with openidScope: false", () => {
    const oidcProvider = (overrides: Partial<ProviderDescriptor>) =>
      github({
        kind: "oidc",
        issuer: ISSUER,
        jwks: `${ISSUER}/jwks`,
        scopes: ["email"],
        ...overrides,
      });

    expect(
      isUnauthError(
        thrown(() => oidcProvider({})),
        "ERR_UNAUTH_CONFIG_INVALID",
      ),
    ).toBe(true);
    const provider = oidcProvider({ openidScope: false });
    expect(provider.openidScope).toBe(false);
    expect(provider.nonce).toBe(true);
    expect(provider.scopes).toEqual(["email"]);
  });

  it("needs an issuer to check the iss parameter", () => {
    const error = thrown(() => github({ issuerParameter: true }));
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(github({ issuerParameter: true, issuer: ISSUER }).issuerParameter).toBe(true);
  });
});

function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe("buildAuthorizationUrl", () => {
  it("carries the code-flow parameters", async () => {
    const pkce = await createPkce();
    const url = buildAuthorizationUrl(github({ authorizationParams: { prompt: "consent" } }), {
      redirectUri: "https://app.test/cb",
      state: "s1",
      nonce: "n1",
      pkce,
    });

    expect(url.origin + url.pathname).toBe(`${ISSUER}/authorize`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: "https://app.test/cb",
      scope: "read:user user:email",
      state: "s1",
      nonce: "n1",
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      prompt: "consent",
    });
  });

  it("joins scopes with the provider's separator and adds response_mode=form_post", () => {
    const url = buildAuthorizationUrl(
      github({ scopeSeparator: ",", responseMode: "form_post", pkce: false }),
      {
        redirectUri: "https://app.test/cb",
        state: "s1",
        scopes: ["a", "b"],
      },
    );

    expect(url.searchParams.get("scope")).toBe("a,b");
    expect(url.searchParams.get("response_mode")).toBe("form_post");
  });

  it("refuses to build a request without PKCE for a PKCE provider", () => {
    let error: unknown;
    try {
      buildAuthorizationUrl(github(), { redirectUri: "https://app.test/cb", state: "s1" });
    } catch (error_) {
      error = error_;
    }
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("never lets extra parameters override the security ones", () => {
    const url = buildAuthorizationUrl(
      github({
        authorizationParams: { state: "evil", redirect_uri: "https://evil.test" },
        pkce: false,
      }),
      {
        redirectUri: "https://app.test/cb",
        state: "s1",
        params: { client_id: "evil", response_type: "token", code_challenge: "x" },
      },
    );

    expect(url.searchParams.getAll("state")).toEqual(["s1"]);
    expect(url.searchParams.getAll("redirect_uri")).toEqual(["https://app.test/cb"]);
    expect(url.searchParams.getAll("client_id")).toEqual([CLIENT_ID]);
    expect(url.searchParams.getAll("response_type")).toEqual(["code"]);
    expect(url.searchParams.has("code_challenge")).toBe(false);
  });
});

describe("exchangeCode", () => {
  it("redeems a code with PKCE and basic client auth", async () => {
    const fake = await createFakeProvider();
    const provider = github();
    const grant = await codeFor(fake, provider);

    const tokens = await exchangeCode(provider, {
      ...grant,
      redirectUri: "https://app.test/auth/fake",
      fetch: fake.fetch,
    });

    expect(tokens.access_token).toMatch(/^at-/);
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.expires_in).toBe(3600);
    expect(tokens.refresh_token).toBe("rt-1");
    expect(tokens.raw.expires_in).toBe("3600");
    const sent = fake.requests.at(-1)!;
    expect(sent.method).toBe("POST");
    expect(sent.headers.get("accept")).toBe("application/json");
    expect(sent.headers.get("content-type")).toMatch(/^application\/x-www-form-urlencoded/);
  });

  it("sends the secret in the body with tokenAuth: body", async () => {
    const fake = await createFakeProvider({ tokenAuth: "body" });
    const provider = github({ tokenAuth: "body" });
    const grant = await codeFor(fake, provider);

    await exchangeCode(provider, {
      ...grant,
      redirectUri: "https://app.test/auth/fake",
      fetch: fake.fetch,
    });

    const form = new URLSearchParams(fake.requests.at(-1)!.body);
    expect(form.get("client_secret")).toBe(CLIENT_SECRET);
    expect(fake.requests.at(-1)!.headers.has("authorization")).toBe(false);
  });

  it("sends only client_id with tokenAuth: none", async () => {
    const fake = await createFakeProvider({ tokenAuth: "none" });
    const provider = github({ tokenAuth: "none", client: { id: CLIENT_ID } });
    const grant = await codeFor(fake, provider);

    await exchangeCode(provider, {
      ...grant,
      redirectUri: "https://app.test/auth/fake",
      fetch: fake.fetch,
    });

    const form = new URLSearchParams(fake.requests.at(-1)!.body);
    expect(form.get("client_id")).toBe(CLIENT_ID);
    expect(form.has("client_secret")).toBe(false);
  });

  it("signs a client assertion with tokenAuth: private_key_jwt (RFC 7523)", async () => {
    const keys = await generateJWK("ES256", { kid: "client-key" });
    const seen: URLSearchParams[] = [];
    const provider = github({
      tokenAuth: "private_key_jwt",
      client: { id: CLIENT_ID, privateKey: keys.privateKey },
    });

    await exchangeCode(provider, {
      code: "c1",
      redirectUri: "https://app.test/cb",
      now: () => Date.UTC(2026, 9, 1),
      fetch: async (_input, init) => {
        seen.push(init?.body as URLSearchParams);
        return Response.json({ access_token: "at-1", token_type: "Bearer" });
      },
    });

    const form = seen[0]!;
    expect(form.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    const { payload } = await verify(form.get("client_assertion")!, keys.publicKey, {
      audience: `${ISSUER}/token`,
      issuer: CLIENT_ID,
      subject: CLIENT_ID,
      currentDate: new Date(Date.UTC(2026, 9, 1, 0, 0, 30)),
      requiredClaims: ["jti", "exp", "iat"],
    });
    expect(payload.exp! - payload.iat!).toBeLessThanOrEqual(300);
    expect(form.has("client_secret")).toBe(false);
  });

  it.each([
    [
      "400 invalid_grant",
      () => Response.json({ error: "invalid_grant", error_description: "used" }, { status: 400 }),
      "invalid_grant",
    ],
    [
      "401 invalid_client",
      () => Response.json({ error: "invalid_client" }, { status: 401 }),
      "invalid_client",
    ],
    [
      "200 with error",
      () => Response.json({ error: "bad_verification_code" }),
      "bad_verification_code",
    ],
    [
      "urlencoded error",
      () =>
        new Response("error=invalid_grant", {
          status: 400,
          headers: { "content-type": "application/x-www-form-urlencoded" },
        }),
      "invalid_grant",
    ],
  ])(
    "throws ERR_AUTHN_TOKEN_EXCHANGE on %s with the RFC 6749 error in cause",
    async (_label, respond, rfcError) => {
      const error = await exchangeCode(github(), {
        code: "c1",
        redirectUri: "https://app.test/cb",
        fetch: async () => respond(),
      }).catch((error_: unknown) => error_);

      expect(isUnauthError(error, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
      expect(isUnauthError(error) && error.status).toBe(401);
      expect(isUnauthError(error) && error.cause).toMatchObject({ error: rfcError });
      expect(isUnauthError(error) && error.message).not.toContain(rfcError);
    },
  );

  it.each([
    ["a 500 page", async () => new Response("<html>oops</html>", { status: 500 })],
    ["a response without access_token", async () => Response.json({ token_type: "Bearer" })],
    [
      "a network failure",
      async (): Promise<Response> => {
        throw new TypeError("fetch failed");
      },
    ],
  ])("throws ERR_AUTHN_TOKEN_EXCHANGE on %s", async (_label, respond) => {
    const error = await exchangeCode(github(), {
      code: "c1",
      redirectUri: "https://app.test/cb",
      fetch: respond,
    }).catch((error_: unknown) => error_);

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
  });

  it("throws ERR_AUTHN_TOKEN_EXCHANGE for a token type other than bearer", async () => {
    const error = await exchangeCode(github(), {
      code: "c1",
      redirectUri: "https://app.test/cb",
      fetch: async () => Response.json({ access_token: "at-1", token_type: "DPoP" }),
    }).catch((error_: unknown) => error_);

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
    expect(isUnauthError(error) && error.cause).toMatchObject({ token_type: "DPoP" });
  });

  it.each([
    [3600, 3600],
    ["3600", 3600],
    ["", undefined],
    ["1e3", undefined],
    [null, undefined],
    [true, undefined],
    ["abc", undefined],
  ])("parses expires_in %j as %j", async (expiresIn, expected) => {
    const tokens = await exchangeCode(github(), {
      code: "c1",
      redirectUri: "https://app.test/cb",
      fetch: async () =>
        Response.json({ access_token: "at-1", token_type: "BEARER", expires_in: expiresIn }),
    });

    expect(tokens.expires_in).toBe(expected);
    expect("expires_in" in tokens).toBe(expected !== undefined);
  });

  it("parses an urlencoded success body", async () => {
    const tokens = await exchangeCode(github(), {
      code: "c1",
      redirectUri: "https://app.test/cb",
      fetch: async () =>
        new Response("access_token=at-9&token_type=bearer&scope=a%2Cb", {
          headers: { "content-type": "application/x-www-form-urlencoded" },
        }),
    });

    expect(tokens).toMatchObject({ access_token: "at-9", token_type: "bearer", scope: "a,b" });
  });
});

describe("client secret", () => {
  it("calls a client secret function on every request", async () => {
    let calls = 0;
    const provider = github({
      tokenAuth: "body",
      client: { id: CLIENT_ID, secret: async () => `minted-${++calls}` },
    });
    const bodies: URLSearchParams[] = [];
    const fetch = async (_input: unknown, init?: RequestInit) => {
      bodies.push(init?.body as URLSearchParams);
      return Response.json({ access_token: "at-1", token_type: "Bearer" });
    };

    await exchangeCode(provider, { code: "c1", redirectUri: "https://app.test/cb", fetch });
    await exchangeCode(provider, { code: "c2", redirectUri: "https://app.test/cb", fetch });

    expect(bodies.map((body) => body.get("client_secret"))).toEqual(["minted-1", "minted-2"]);
  });
});

describe("refreshTokens", () => {
  it("keeps the old refresh token when the provider does not rotate it", async () => {
    const fake = await createFakeProvider();

    const tokens = await refreshTokens(github(), { refreshToken: "rt-1", fetch: fake.fetch });

    expect(tokens.access_token).toBe("at-2");
    expect(tokens.refresh_token).toBe("rt-1");
    expect(new URLSearchParams(fake.requests.at(-1)!.body).get("grant_type")).toBe("refresh_token");
  });

  it("throws ERR_AUTHN_TOKEN_EXCHANGE on a refused refresh token", async () => {
    const fake = await createFakeProvider();

    const error = await refreshTokens(github(), { refreshToken: "nope", fetch: fake.fetch }).catch(
      (error_: unknown) => error_,
    );

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
  });
});

describe("fetchProfile", () => {
  const tokens = { access_token: "at-1", token_type: "bearer", raw: {} };

  it("reads userinfo with the bearer token and the provider's headers", async () => {
    const fake = await createFakeProvider();
    const provider = github({ userinfoHeaders: { "user-agent": "unauth" } });

    const userinfo = await fetchProfile(provider, { tokens, fetch: fake.fetch });

    expect(userinfo).toEqual(fake.userinfo);
    const sent = fake.requests.at(-1)!;
    expect(sent.headers.get("authorization")).toBe("Bearer at-1");
    expect(sent.headers.get("user-agent")).toBe("unauth");
    expect(sent.headers.get("accept")).toBe("application/json");
  });

  it("throws ERR_AUTHN_PROVIDER_ERROR when userinfo refuses", async () => {
    const fake = await createFakeProvider();

    const error = await fetchProfile(github(), {
      tokens: { ...tokens, access_token: "wrong" },
      fetch: fake.fetch,
    }).catch((error_: unknown) => error_);

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
  });

  it("strips prototype-polluting keys", async () => {
    const userinfo = await fetchProfile(github(), {
      tokens,
      fetch: async () =>
        new Response('{"sub":"u","__proto__":{"polluted":true}}', {
          headers: { "content-type": "application/json" },
        }),
    });

    expect(Object.hasOwn(userinfo, "__proto__")).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
