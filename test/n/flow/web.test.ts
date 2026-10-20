import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type CacheDriver,
  type FlowRecord,
  type Provider,
  type FlowStore,
  startFlow,
  completeFlow,
  defineProvider,
  isUnauthError,
  defineOAuth2Provider,
  defineOidcProvider,
} from "../../../src/n/index.ts";
import { cookieHeader, isExpired } from "../_session.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./_fake-provider.ts";

const APP = "https://app.test";
const REDIRECT_URI = `${APP}/auth/fake`;
const FLOW_COOKIE = "__Host-unauth-flow";

let key: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
});

afterEach(() => {
  vi.useRealTimers();
});

function fakeOAuth2(): Provider {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
    scopes: ["profile"],
  });
}

/**
 * An OIDC fake on an issuer of its own: the JWKS cache is per URL and process-wide, so a shared
 * issuer would serve one test's keys to the next under the same `kid`.
 */
async function oidcSetup() {
  const issuer = `https://${crypto.randomUUID()}.idp.test`;
  const fake = await createFakeProvider({ issuer });
  const provider = defineOidcProvider({ issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
  return { fake, provider };
}

/** Runs `startFlow`, the provider's consent and returns what `completeFlow` needs. */
async function beginSignIn(
  provider: Provider,
  fake: Awaited<ReturnType<typeof createFakeProvider>>,
  options: Partial<Parameters<typeof startFlow>[2]> = {},
) {
  const response = await startFlow(provider, new Request(`${APP}/auth/fake`), {
    key,
    redirectUri: REDIRECT_URI,
    fetch: fake.fetch,
    ...options,
  });
  const location = new URL(response.headers.get("location")!);
  const back = fake.approve(location);
  const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });
  return { response, location, back, request };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

function flowCookieCleared(headers: Headers): boolean {
  const line = headers.getSetCookie().find((l) => l.startsWith(`${FLOW_COOKIE}=`));
  return line !== undefined && isExpired(line);
}

describe("startFlow", () => {
  it("redirects to the provider with state, PKCE S256 and a sealed flow cookie", async () => {
    const fake = await createFakeProvider();
    const { response, location } = await beginSignIn(fakeOAuth2(), fake);

    expect(response.status).toBe(302);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(location.origin + location.pathname).toBe(`${ISSUER}/authorize`);
    expect(location.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(location.searchParams.get("state")).toMatch(/^[\w-]{43}$/);
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.has("nonce")).toBe(false);
    const line = response.headers.getSetCookie().find((l) => l.startsWith(`${FLOW_COOKIE}=`))!;
    expect(line).toMatch(/; HttpOnly/i);
    expect(line).toMatch(/; Secure/i);
    expect(line).toMatch(/; SameSite=Lax/i);
    expect(line).not.toContain(location.searchParams.get("state")!);
  });

  it("adds a nonce for OIDC and resolves endpoints through discovery", async () => {
    const { fake, provider } = await oidcSetup();
    const { location } = await beginSignIn(provider, fake);

    expect(location.searchParams.get("nonce")).toMatch(/^[\w-]{43}$/);
    expect(location.searchParams.get("scope")).toBe("openid profile email");
  });

  it("refuses to guess a redirect URI", async () => {
    const error = await rejection(
      startFlow(fakeOAuth2(), new Request(`${APP}/auth/fake`), { key }),
    );

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("derives the redirect URI from a trusted request origin only", async () => {
    const fake = await createFakeProvider();
    const trusted = await startFlow(fakeOAuth2(), new Request(`${APP}/auth/fake?x=1`), {
      key,
      trustedOrigins: [APP],
      fetch: fake.fetch,
    });
    const location = new URL(trusted.headers.get("location")!);
    expect(location.searchParams.get("redirect_uri")).toBe(`${APP}/auth/fake`);

    const error = await rejection(
      startFlow(fakeOAuth2(), new Request("https://evil.test/auth/fake"), {
        key,
        trustedOrigins: [APP],
      }),
    );
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("drops a SameSite=Lax cookie for form_post providers in favour of SameSite=None", async () => {
    const fake = await createFakeProvider();
    const provider = defineOAuth2Provider({
      id: "fake",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      userinfo: `${ISSUER}/userinfo`,
      responseMode: "form_post",
    });
    const { response } = await beginSignIn(provider, fake);

    expect(response.headers.getSetCookie().join("\n")).toMatch(/SameSite=None/i);
  });
});

describe("completeFlow", () => {
  it("completes an OAuth 2.0 flow and clears the flow cookie", async () => {
    const fake = await createFakeProvider();
    const { request } = await beginSignIn(fakeOAuth2(), fake, {
      redirect: "/dashboard?tab=1",
      link: { userId: "u-42" },
    });
    const headers = new Headers();

    const result = await completeFlow(fakeOAuth2(), request, { key, headers, fetch: fake.fetch });

    expect(result.identity).toMatchObject({
      provider: "fake",
      subject: "user-1",
      name: "Ada",
      email: "ada@idp.test",
      emailVerified: true,
      profile: fake.userinfo,
    });
    expect(result.identity.tokens).toBe(result.tokens);
    expect(result.tokens.access_token).toMatch(/^at-/);
    expect(result.redirect).toBe("/dashboard?tab=1");
    expect(result.link).toEqual({ userId: "u-42" });
    expect(flowCookieCleared(headers)).toBe(true);
  });

  it("fetches the discovery document once across both legs", async () => {
    const { fake, provider } = await oidcSetup();
    const { request } = await beginSignIn(provider, fake);

    await completeFlow(provider, request, { key, headers: new Headers(), fetch: fake.fetch });

    const discoveries = fake.requests.filter((r) =>
      r.url.pathname.endsWith("openid-configuration"),
    );
    expect(discoveries).toHaveLength(1);
  });

  it("hands the callback parameters to profile() as untrusted input", async () => {
    const fake = await createFakeProvider();
    const seen: Record<string, string>[] = [];
    const provider = defineOAuth2Provider({
      id: "fake",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      profile: ({ params }) => {
        seen.push(params);
        return { subject: "s", profile: {} };
      },
    });
    const { back, request } = await beginSignIn(provider, fake);

    await completeFlow(provider, request, { key, headers: new Headers(), fetch: fake.fetch });

    expect(seen[0]).toMatchObject({ code: back.searchParams.get("code") });
  });

  it("completes an OIDC flow, verifying the id_token", async () => {
    const { fake, provider } = await oidcSetup();
    const { request } = await beginSignIn(provider, fake);

    const result = await completeFlow(provider, request, {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity).toMatchObject({
      provider: "oidc",
      subject: "user-1",
      email: "ada@idp.test",
      emailVerified: true,
      name: "Ada",
    });
    expect(result.tokens.id_token).toBeTypeOf("string");
  });

  it("verifies the id_token over an http JWKS on a host the provider lists in insecureHosts", async () => {
    const issuer = "http://callback-insecure.lan";
    const fake = await createFakeProvider({ issuer });
    const provider = defineOidcProvider({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      insecureHosts: ["callback-insecure.lan"],
    });
    const { request } = await beginSignIn(provider, fake);

    const result = await completeFlow(provider, request, {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
    expect(fake.jwksFetches()).toBe(1);
  });

  it.each([
    ["javascript:alert(1)"],
    ["//evil.test/x"],
    ["/\\evil.test"],
    ["/\t/evil.test"],
    ["/.//evil.com"],
    ["/a/..//evil.com"],
    ["/%2e//evil.com"],
    ["/..//evil.com"],
    ["/./\\evil.com"],
    ["https://evil.test/"],
    ["dashboard"],
  ])("drops the unsafe redirect %s", async (redirect) => {
    const fake = await createFakeProvider();
    const { request } = await beginSignIn(fakeOAuth2(), fake, { redirect });

    const result = await completeFlow(fakeOAuth2(), request, {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.redirect).toBeUndefined();
  });

  it("throws ERR_AUTHN_STATE_MISMATCH on another state, and still clears the cookie", async () => {
    const fake = await createFakeProvider();
    const { back, request } = await beginSignIn(fakeOAuth2(), fake);
    back.searchParams.set("state", "forged");
    const headers = new Headers();

    const error = await rejection(
      completeFlow(fakeOAuth2(), new Request(back, { headers: request.headers }), {
        key,
        headers,
        fetch: fake.fetch,
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(401);
    expect(flowCookieCleared(headers)).toBe(true);
  });

  it("throws ERR_AUTHN_STATE_MISMATCH when the flow was started for another provider", async () => {
    const fake = await createFakeProvider();
    const { request } = await beginSignIn(fakeOAuth2(), fake);
    const other = defineOAuth2Provider({
      ...fakeOAuth2(),
      id: "other",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      userinfo: `${ISSUER}/userinfo`,
    });

    const error = await rejection(
      completeFlow(other, request, { key, headers: new Headers(), fetch: fake.fetch }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
  });

  it("throws ERR_AUTHN_FLOW_EXPIRED without a flow cookie or after ten minutes", async () => {
    const fake = await createFakeProvider();
    const { back, request } = await beginSignIn(fakeOAuth2(), fake);

    const missing = await rejection(
      completeFlow(fakeOAuth2(), new Request(back), {
        key,
        headers: new Headers(),
        fetch: fake.fetch,
      }),
    );
    expect(isUnauthError(missing, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);

    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 10 * 60_000 + 1000 });
    const expired = await rejection(
      completeFlow(fakeOAuth2(), request, { key, headers: new Headers(), fetch: fake.fetch }),
    );
    expect(isUnauthError(expired, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
  });

  it("throws ERR_AUTHN_PROVIDER_REFUSED on ?error=, with the provider's error in cause", async () => {
    const fake = await createFakeProvider();
    const { back, request } = await beginSignIn(fakeOAuth2(), fake);
    const refused = new URL(REDIRECT_URI);
    refused.searchParams.set("error", "access_denied");
    refused.searchParams.set("error_description", "The user said no");
    refused.searchParams.set("state", back.searchParams.get("state")!);
    const headers = new Headers();

    const error = await rejection(
      completeFlow(fakeOAuth2(), new Request(refused, { headers: request.headers }), {
        key,
        headers,
        fetch: fake.fetch,
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_REFUSED")).toBe(true);
    expect(isUnauthError(error) && error.cause).toMatchObject({
      error: "access_denied",
      error_description: "The user said no",
    });
    expect(flowCookieCleared(headers)).toBe(true);
  });

  it("throws ERR_AUTHN_TOKEN_EXCHANGE when the token endpoint refuses the code", async () => {
    const fake = await createFakeProvider();
    const { request } = await beginSignIn(fakeOAuth2(), fake);
    fake.nextTokenResponse(Response.json({ error: "invalid_grant" }, { status: 400 }));

    const error = await rejection(
      completeFlow(fakeOAuth2(), request, { key, headers: new Headers(), fetch: fake.fetch }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
  });

  it("throws ERR_AUTHN_ID_TOKEN_INVALID on a nonce mismatch", async () => {
    const { fake, provider } = await oidcSetup();
    const { request } = await beginSignIn(provider, fake);
    fake.idTokenClaims.nonce = "replayed";

    const error = await rejection(
      completeFlow(provider, request, { key, headers: new Headers(), fetch: fake.fetch }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
  });

  it("throws ERR_AUTHN_PROFILE_INVALID when userinfo names another subject than the id_token", async () => {
    const { fake, provider } = await oidcSetup();
    const { request } = await beginSignIn(provider, fake);
    fake.userinfo = { ...fake.userinfo, sub: "user-2" };

    const error = await rejection(
      completeFlow(provider, request, { key, headers: new Headers(), fetch: fake.fetch }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("reads a form_post callback from the request body", async () => {
    const fake = await createFakeProvider();
    const provider = defineOAuth2Provider({
      id: "fake",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      userinfo: `${ISSUER}/userinfo`,
      responseMode: "form_post",
    });
    const { back, request } = await beginSignIn(provider, fake);
    const post = new Request(REDIRECT_URI, {
      method: "POST",
      headers: {
        "cookie": request.headers.get("cookie")!,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: back.searchParams.toString(),
    });

    const result = await completeFlow(provider, post, {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
  });

  it("verifies the id_token of a provider that sends one without the openid scope", async () => {
    const issuer = `https://${crypto.randomUUID()}.idp.test`;
    const fake = await createFakeProvider({ issuer });
    fake.alwaysIdToken = true;
    const provider = defineProvider({
      id: "no-openid",
      kind: "oidc",
      issuer,
      authorization: `${issuer}/authorize`,
      token: `${issuer}/token`,
      jwks: `${issuer}/jwks`,
      scopes: ["email"],
      openidScope: false,
      client: { id: CLIENT_ID, secret: CLIENT_SECRET },
      profile: ({ claims }) => ({ subject: claims!.sub, profile: claims! }),
    });

    const { location, request } = await beginSignIn(provider, fake);
    const result = await completeFlow(provider, request, {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });
    expect(location.searchParams.get("scope")).toBe("email");
    expect(location.searchParams.get("nonce")).toMatch(/^[\w-]{43}$/);
    expect(result.identity.subject).toBe("user-1");

    const replayed = await beginSignIn(provider, fake);
    fake.idTokenClaims.nonce = "replayed";
    const error = await rejection(
      completeFlow(provider, replayed.request, { key, headers: new Headers(), fetch: fake.fetch }),
    );
    expect(isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
  });
});

describe("RFC 9207 iss parameter", () => {
  async function callbackWithIss(
    iss: string | undefined,
    setup?: (fake: Awaited<ReturnType<typeof createFakeProvider>>) => void,
  ) {
    const { fake, provider } = await oidcSetup();
    setup?.(fake);
    const { back, request } = await beginSignIn(provider, fake);
    if (iss === undefined) back.searchParams.delete("iss");
    else back.searchParams.set("iss", iss);
    return completeFlow(provider, new Request(back, { headers: request.headers }), {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });
  }

  it("accepts the issuer's own iss when the issuer advertises the parameter", async () => {
    const { fake, provider } = await oidcSetup();
    const { back, request } = await beginSignIn(provider, fake);

    const result = await completeFlow(provider, request, {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(back.searchParams.get("iss")).toBe(provider.issuer);
    expect(result.identity.subject).toBe("user-1");
  });

  it("throws ERR_AUTHN_STATE_MISMATCH on another iss", async () => {
    const error = await rejection(callbackWithIss("https://evil.test"));

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(isUnauthError(error) && error.cause).toEqual({ provider: "oidc", reason: "issuer" });
  });

  it("throws ERR_AUTHN_STATE_MISMATCH when a required iss is missing", async () => {
    const error = await rejection(callbackWithIss(undefined));

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(isUnauthError(error) && error.cause).toEqual({ provider: "oidc", reason: "issuer" });
  });

  it("accepts a missing iss when not required, but never a contradicting one", async () => {
    const silent = (fake: Awaited<ReturnType<typeof createFakeProvider>>) => {
      fake.discovery.authorization_response_iss_parameter_supported = false;
    };

    await expect(callbackWithIss(undefined, silent)).resolves.toBeDefined();
    const error = await rejection(callbackWithIss("https://evil.test", silent));
    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
  });

  it("reads iss from a form_post body", async () => {
    const issuer = `https://${crypto.randomUUID()}.idp.test`;
    const fake = await createFakeProvider({ issuer });
    const provider = defineOidcProvider({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      responseMode: "form_post",
    });
    const { back, request } = await beginSignIn(provider, fake);
    const post = (iss: string) => {
      const body = new URLSearchParams(back.searchParams);
      body.set("iss", iss);
      return new Request(REDIRECT_URI, {
        method: "POST",
        headers: {
          "cookie": request.headers.get("cookie")!,
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
      });
    };

    const error = await rejection(
      completeFlow(provider, post("https://evil.test"), {
        key,
        headers: new Headers(),
        fetch: fake.fetch,
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
  });
});

describe("flow lifetime", () => {
  it("keeps a flow for maxAge, in the cookie and in the store", async () => {
    const fake = await createFakeProvider();
    const ttls: number[] = [];
    const records = new Map<string, FlowRecord>();
    const store: FlowStore = {
      put: async (id, record, { ttl }) => {
        ttls.push(ttl);
        records.set(id, record);
      },
      take: async (id) => records.get(id),
    };
    const { response, request } = await beginSignIn(fakeOAuth2(), fake, { store, maxAge: 30 });

    expect(ttls).toEqual([30]);
    const line = response.headers.getSetCookie().find((l) => l.startsWith(`${FLOW_COOKIE}=`))!;
    const expires = Date.parse(/; Expires=([^;]+)/i.exec(line)![1]!) - Date.now();
    expect(expires).toBeGreaterThan(28_000);
    expect(expires).toBeLessThanOrEqual(30_000);

    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 31_000 });
    const error = await rejection(
      completeFlow(fakeOAuth2(), request, {
        key,
        store,
        maxAge: 30,
        headers: new Headers(),
        fetch: fake.fetch,
      }),
    );
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
  });

  it("refuses a maxAge that is not a positive duration", async () => {
    const error = await rejection(
      startFlow(fakeOAuth2(), new Request(`${APP}/auth/fake`), {
        key,
        redirectUri: REDIRECT_URI,
        maxAge: 0,
      }),
    );

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });
});

describe("cache driver", () => {
  it("carries discovery and the JWK Set through both legs", async () => {
    const { fake, provider } = await oidcSetup();
    const entries = new Map<string, unknown>();
    const sets: (number | undefined)[] = [];
    const cache: CacheDriver = {
      get: async <T>(name: string) => (entries.get(name) ?? null) as T | null,
      set: async (name, value, options) => {
        sets.push(options?.ttl);
        entries.set(name, value);
      },
    };
    const { request } = await beginSignIn(provider, fake, { cache });

    await completeFlow(provider, request, {
      key,
      cache,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(sets).toEqual([600, 600]);
    expect(entries.size).toBe(2);
    const discoveries = fake.requests.filter((r) =>
      r.url.pathname.endsWith("openid-configuration"),
    );
    expect(discoveries).toHaveLength(1);
  });
});

describe("FlowStore", () => {
  function memoryStore() {
    const records = new Map<string, { record: FlowRecord; ttl: number }>();
    const store: FlowStore = {
      put: async (id, record, { ttl }) => {
        records.set(id, { record, ttl });
      },
      take: async (id) => {
        const entry = records.get(id);
        records.delete(id);
        return entry?.record;
      },
    };
    return { store, records };
  }

  it("keeps the flow record in the store and only a reference in the cookie", async () => {
    const fake = await createFakeProvider();
    const { store, records } = memoryStore();
    const { location, request } = await beginSignIn(fakeOAuth2(), fake, { store, redirect: "/x" });

    expect(records.size).toBe(1);
    const [entry] = records.values();
    expect(entry!.ttl).toBe(600);
    expect(entry!.record).toMatchObject({
      provider: "fake",
      state: location.searchParams.get("state"),
      redirectUri: REDIRECT_URI,
      redirect: "/x",
    });

    const result = await completeFlow(fakeOAuth2(), request, {
      key,
      store,
      headers: new Headers(),
      fetch: fake.fetch,
    });
    expect(result.redirect).toBe("/x");
    expect(records.size).toBe(0);
  });

  it("throws ERR_AUTHN_FLOW_EXPIRED when the store no longer has the record", async () => {
    const fake = await createFakeProvider();
    const { store, records } = memoryStore();
    const { request } = await beginSignIn(fakeOAuth2(), fake, { store });
    records.clear();

    const error = await rejection(
      completeFlow(fakeOAuth2(), request, {
        key,
        store,
        headers: new Headers(),
        fetch: fake.fetch,
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
  });
});
