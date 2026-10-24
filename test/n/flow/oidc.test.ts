import { describe, expect, it } from "vitest";
import { generateJWK, sign } from "unjwt";

import {
  defineProvider,
  discover,
  fetchJwks,
  isUnauthError,
  resolveProvider,
  defineOidcProvider,
  verifyIdToken,
} from "../../../src/n/index.ts";
import { CLIENT_ID, ISSUER, CLIENT_SECRET, atHash, createFakeProvider } from "./_fake-provider.ts";

const NOW = Date.UTC(2026, 9, 1, 12);
const now = () => NOW;
const iat = Math.floor(NOW / 1000);

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    sub: "user-1",
    aud: CLIENT_ID,
    iat,
    exp: iat + 300,
    nonce: "n1",
    ...overrides,
  };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

/** A fresh issuer per test keeps the module-level JWKS cache out of the way. */
async function fakeAt(name: string) {
  return createFakeProvider({ issuer: `https://${name}.idp.test` });
}

describe("discover", () => {
  it("reads the provider metadata", async () => {
    const fake = await fakeAt("discover-read");
    const issuer = "https://discover-read.idp.test";

    const metadata = await discover(issuer, { fetch: fake.fetch, now });

    expect(metadata.token_endpoint).toBe(`${issuer}/token`);
    expect(fake.requests[0]!.url.href).toBe(`${issuer}/.well-known/openid-configuration`);
  });

  it("keeps an issuer path and drops a trailing slash before the well-known suffix", async () => {
    const seen: string[] = [];
    const issuer = "https://discover-path.idp.test/tenant/";
    await discover(issuer, {
      now,
      fetch: async (input) => {
        seen.push(String(input instanceof Request ? input.url : input));
        return Response.json({
          issuer,
          authorization_endpoint: "https://idp.test/a",
          token_endpoint: "https://idp.test/t",
          jwks_uri: "https://idp.test/j",
        });
      },
    });
    expect(seen).toEqual([
      "https://discover-path.idp.test/tenant/.well-known/openid-configuration",
    ]);
  });

  it("caches the document per issuer for ten minutes", async () => {
    const fake = await fakeAt("discover-cache");
    const issuer = "https://discover-cache.idp.test";

    const first = await discover(issuer, { fetch: fake.fetch, now });
    expect(await discover(issuer, { fetch: fake.fetch, now: () => NOW + 10 * 60_000 })).toBe(first);
    await discover(issuer, { fetch: fake.fetch, now: () => NOW + 10 * 60_000 + 1 });

    expect(fake.requests).toHaveLength(2);
  });

  it("throws ERR_AUTHN_PROVIDER_ERROR when the document names another issuer, and keeps only the failure", async () => {
    const fake = await fakeAt("discover-mismatch");
    const issuer = "https://discover-mismatch.idp.test";
    fake.discovery.issuer = "https://evil.test";

    const error = await rejection(discover(issuer, { fetch: fake.fetch, now }));
    delete fake.discovery.issuer;
    await discover(issuer, { fetch: fake.fetch, now: () => NOW + 5000 });

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(fake.requests).toHaveLength(2);
  });

  it("throws ERR_UNAUTH_CONFIG_INVALID for a non-https issuer", async () => {
    const fake = await createFakeProvider();

    const error = await rejection(discover("http://idp.test", { fetch: fake.fetch }));

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(fake.requests).toHaveLength(0);
  });

  it("throws ERR_AUTHN_PROVIDER_ERROR on a missing endpoint or a failed fetch", async () => {
    const fake = await fakeAt("discover-missing");
    fake.discovery.token_endpoint = undefined;
    const missing = rejection(
      discover("https://discover-missing.idp.test", { fetch: fake.fetch, now }),
    );
    expect(isUnauthError(await missing, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);

    const down = rejection(
      discover("https://discover-down.idp.test", {
        now,
        fetch: async () => new Response(null, { status: 503 }),
      }),
    );
    expect(isUnauthError(await down, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
  });

  it("answers a failed discovery from its failure for five seconds", async () => {
    const issuer = "https://discover-failing.idp.test";
    let requests = 0;
    const fetch = async () => {
      requests++;
      return new Response(null, { status: 503 });
    };

    const first = await rejection(discover(issuer, { fetch, now }));
    const second = await rejection(discover(issuer, { fetch, now: () => NOW + 1000 }));

    expect(isUnauthError(first, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(second, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(requests).toBe(1);
  });

  it("throws ERR_UNAUTH_CONFIG_INVALID for an issuer longer than 2048 characters", async () => {
    const fake = await createFakeProvider();
    const issuer = `https://idp.test/${"a".repeat(2049 - "https://idp.test/".length)}`;
    expect(issuer).toHaveLength(2049);

    const error = await rejection(discover(issuer, { fetch: fake.fetch, now }));

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(fake.requests).toHaveLength(0);
  });

  it("resolveProvider fills the endpoints of a discovery provider from the cached document", async () => {
    const fake = await fakeAt("resolve");
    const issuer = "https://resolve.idp.test";
    const provider = defineOidcProvider({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    const resolved = await resolveProvider(provider, { fetch: fake.fetch, now });
    await resolveProvider(provider, { fetch: fake.fetch, now });

    expect(resolved).toMatchObject({
      authorization: `${issuer}/authorize`,
      token: `${issuer}/token`,
      userinfo: `${issuer}/userinfo`,
      jwks: `${issuer}/jwks`,
      discovery: false,
    });
    expect(provider.discovery).toBe(true);
    expect(fake.requests).toHaveLength(1);
  });

  it("reaches an http issuer only on a host listed in insecureHosts", async () => {
    const issuer = "http://192.168.1.20:8080";
    const fake = await createFakeProvider({ issuer });

    const refused = await rejection(discover(issuer, { fetch: fake.fetch, now }));
    expect(isUnauthError(refused, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(fake.requests).toHaveLength(0);

    const metadata = await discover(issuer, {
      fetch: fake.fetch,
      now,
      insecureHosts: ["192.168.1.20"],
    });
    expect(metadata.token_endpoint).toBe(`${issuer}/token`);
  });

  it("resolveProvider discovers with the provider's insecureHosts", async () => {
    const issuer = "http://idp.lan";
    const fake = await createFakeProvider({ issuer });
    const descriptor = {
      id: "lan",
      kind: "oidc" as const,
      discovery: true,
      issuer,
      scopes: ["openid"],
      client: { id: CLIENT_ID, secret: CLIENT_SECRET },
      profile: () => ({ subject: "s", profile: {} }),
    };
    expect(
      isUnauthError(
        rejectionSync(() => defineProvider(descriptor)),
        "ERR_UNAUTH_CONFIG_INVALID",
      ),
    ).toBe(true);

    const provider = defineProvider({ ...descriptor, insecureHosts: ["idp.lan"] });
    const resolved = await resolveProvider(provider, { fetch: fake.fetch, now });

    expect(resolved).toMatchObject({ token: `${issuer}/token`, jwks: `${issuer}/jwks` });
  });

  it("resolveProvider turns issuerParameter on when the metadata advertises it, unless set", async () => {
    const fake = await fakeAt("iss-param");
    const issuer = "https://iss-param.idp.test";
    const provider = defineOidcProvider({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    expect(provider.issuerParameter).toBeUndefined();
    expect((await resolveProvider(provider, { fetch: fake.fetch, now })).issuerParameter).toBe(
      true,
    );
    const off = { ...provider, issuerParameter: false };
    expect((await resolveProvider(off, { fetch: fake.fetch, now })).issuerParameter).toBe(false);

    const silent = await fakeAt("iss-param-silent");
    silent.discovery.authorization_response_iss_parameter_supported = undefined;
    const quiet = defineOidcProvider({
      issuer: "https://iss-param-silent.idp.test",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });
    expect(
      (await resolveProvider(quiet, { fetch: silent.fetch, now })).issuerParameter,
    ).toBeUndefined();
  });
});

function rejectionSync(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe("fetchJwks", () => {
  it("caches a key set per URL and refetches on force once the cooldown ran out", async () => {
    const fake = await fakeAt("jwks-cache");
    const url = "https://jwks-cache.idp.test/jwks";

    const first = await fetchJwks(url, { fetch: fake.fetch, now });
    const second = await fetchJwks(url, { fetch: fake.fetch, now });
    expect(await fetchJwks(url, { fetch: fake.fetch, now, force: true })).toBe(first);
    await fetchJwks(url, { fetch: fake.fetch, now: () => NOW + 30_000, force: true });

    expect(first.keys[0]!.kid).toBe("k0");
    expect(second).toBe(first);
    expect(fake.jwksFetches()).toBe(2);
  });

  it("expires the cache after ten minutes", async () => {
    const fake = await fakeAt("jwks-ttl");
    const url = "https://jwks-ttl.idp.test/jwks";

    await fetchJwks(url, { fetch: fake.fetch, now });
    await fetchJwks(url, { fetch: fake.fetch, now: () => NOW + 10 * 60_000 + 1 });

    expect(fake.jwksFetches()).toBe(2);
  });

  it("refuses an http JWKS URL unless its host is in insecureHosts", async () => {
    const fake = await createFakeProvider({ issuer: "http://idp.lan" });

    const error = await rejection(fetchJwks("http://idp.lan/jwks", { fetch: fake.fetch, now }));
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(fake.requests).toHaveLength(0);

    const set = await fetchJwks("http://idp.lan/jwks", {
      fetch: fake.fetch,
      now,
      insecureHosts: ["idp.lan"],
    });
    expect(set.keys).toHaveLength(1);
  });

  it("throws ERR_AUTHN_PROVIDER_ERROR on a body without keys", async () => {
    const error = await rejection(
      fetchJwks("https://nokeys.idp.test/jwks", { fetch: async () => Response.json({}), now }),
    );
    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
  });
});

describe("verifyIdToken", () => {
  async function setup(name: string) {
    const fake = await fakeAt(name);
    const issuer = `https://${name}.idp.test`;
    const options = {
      issuer,
      clientId: CLIENT_ID,
      nonce: "n1",
      jwks: `${issuer}/jwks`,
      fetch: fake.fetch,
      now,
    };
    return { fake, issuer, options };
  }

  it("returns the claims of a valid token", async () => {
    const { fake, issuer, options } = await setup("valid");
    const token = await fake.signIdToken(claims({ iss: issuer, email: "ada@idp.test" }));

    const verified = await verifyIdToken(token, options);

    expect(verified).toMatchObject({ sub: "user-1", email: "ada@idp.test", nonce: "n1" });
  });

  it.each([
    ["another issuer", { iss: "https://evil.test" }],
    ["another audience", { aud: "someone-else" }],
    ["several audiences without azp", { aud: [CLIENT_ID, "other"] }],
    ["an azp naming another client", { azp: "other" }],
    ["an expired token", { exp: iat - 60 }],
    ["a missing iat", { iat: undefined }],
    ["a missing sub", { sub: undefined }],
    ["another nonce", { nonce: "n2" }],
    ["an iat in the future", { iat: iat + 120, exp: iat + 600 }],
    ["an iat after exp", { iat: iat + 10, exp: iat + 5 }],
    ["an empty sub", { sub: "" }],
    ["a numeric sub", { sub: 5 }],
    ["no nonce", { nonce: undefined }],
  ])("throws ERR_AUTHN_ID_TOKEN_INVALID for %s", async (label, overrides) => {
    const { fake, issuer, options } = await setup(`bad-${label.replaceAll(" ", "-")}`);
    const token = await fake.signIdToken(claims({ iss: issuer, ...overrides }));

    const error = await rejection(verifyIdToken(token, options));

    expect(isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(401);
  });

  it("accepts several audiences when azp names the client", async () => {
    const { fake, issuer, options } = await setup("azp");
    const token = await fake.signIdToken(
      claims({ iss: issuer, aud: [CLIENT_ID, "other"], azp: CLIENT_ID }),
    );

    await expect(verifyIdToken(token, options)).resolves.toMatchObject({ azp: CLIENT_ID });
  });

  it("refuses a symmetric (HS256) token, even one signed with the client secret", async () => {
    const { issuer, options } = await setup("hs256");
    const secret = await generateJWK("HS256");
    const token = await sign(claims({ iss: issuer }), secret);

    const error = await rejection(verifyIdToken(token, { ...options, jwks: { keys: [secret] } }));

    expect(isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
  });

  it("refetches the key set once for an unknown kid, so rotated keys verify", async () => {
    const { fake, issuer, options } = await setup("rotate");
    await verifyIdToken(await fake.signIdToken(claims({ iss: issuer })), options);
    await fake.rotateKey();

    const verified = await verifyIdToken(await fake.signIdToken(claims({ iss: issuer })), {
      ...options,
      now: () => NOW + 30_000,
    });

    expect(verified.sub).toBe("user-1");
    expect(fake.jwksFetches()).toBe(2);
  });

  it("does not refetch for an unknown kid within 30 seconds of the last fetch", async () => {
    const { fake, issuer, options } = await setup("rotate-cooldown");
    await verifyIdToken(await fake.signIdToken(claims({ iss: issuer })), options);
    await fake.rotateKey();

    const error = await rejection(
      verifyIdToken(await fake.signIdToken(claims({ iss: issuer })), {
        ...options,
        now: () => NOW + 1000,
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
    expect(fake.jwksFetches()).toBe(1);
  });

  it("fails without a refetch inside the cooldown, and after one past it, when the kid stays unknown", async () => {
    const { fake, issuer, options } = await setup("unknown-kid");
    const stranger = await generateJWK("RS256", { kid: "stranger" });
    const token = await sign(claims({ iss: issuer }), stranger.privateKey);

    const early = await rejection(verifyIdToken(token, options));
    expect(isUnauthError(early, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
    expect(fake.jwksFetches()).toBe(1);

    const late = await rejection(verifyIdToken(token, { ...options, now: () => NOW + 30_000 }));
    expect(isUnauthError(late, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
    expect(fake.jwksFetches()).toBe(2);
  });

  it("collapses a storm of unknown kids into one refetch", async () => {
    const { fake, issuer, options } = await setup("kid-storm");
    await fetchJwks(options.jwks, { fetch: fake.fetch, now: () => NOW - 30_000 });
    const stranger = await generateJWK("RS256", { kid: "stranger" });
    const token = await sign(claims({ iss: issuer }), stranger.privateKey);

    const errors = await Promise.all(
      Array.from({ length: 100 }, () => rejection(verifyIdToken(token, options))),
    );

    expect(errors.every((error) => isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID"))).toBe(true);
    expect(fake.jwksFetches()).toBe(2);
  });

  it("surfaces an unreachable JWKS as ERR_AUTHN_PROVIDER_ERROR", async () => {
    const { fake, issuer, options } = await setup("jwks-down");
    const token = await fake.signIdToken(claims({ iss: issuer }));

    const error = await rejection(
      verifyIdToken(token, { ...options, fetch: async () => new Response(null, { status: 502 }) }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
  });

  it("checks at_hash against the access token", async () => {
    const { fake, issuer, options } = await setup("at-hash");
    const token = await fake.signIdToken(claims({ iss: issuer, at_hash: await atHash("at-1") }));

    await expect(verifyIdToken(token, { ...options, accessToken: "at-1" })).resolves.toBeDefined();
    const error = await rejection(verifyIdToken(token, { ...options, accessToken: "at-2" }));
    expect(isUnauthError(error, "ERR_AUTHN_ID_TOKEN_INVALID")).toBe(true);
  });
});
