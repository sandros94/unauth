import { beforeAll, describe, expect, it } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type CustomProvider,
  type UnauthError,
  defineOAuth2Provider,
  defineProvider,
  defineSignInHandler,
  isUnauthError,
  startFlow,
} from "../../../src/n/index.ts";
import { defineAtprotoHandler } from "../../../src/n/providers/atproto.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./_fake-provider.ts";
import {
  ALICE,
  CLIENT_ID as ATPROTO_CLIENT_ID,
  DNS,
  ISSUER as ATPROTO_ISSUER,
  PLC,
  REDIRECT_URI as ATPROTO_REDIRECT_URI,
  createFakeAtproto,
} from "../providers/_fake-atproto.ts";
import { formStart } from "../_session.ts";

const APP = "https://app.test";
const REDIRECT_URI = `${APP}/auth/fake`;
const MOVED = "https://ip.test";

let key: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
});

function oauth() {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
  });
}

/** A custom provider that sends the user to `custom.test`, naming the account when it has one. */
function custom(options: { relocateFrom?: string } = {}): CustomProvider {
  return defineProvider({
    id: "custom",
    kind: "custom",
    start: async (context) => {
      const here = new URL(context.request.url);
      if (options.relocateFrom !== undefined && here.origin === options.relocateFrom) {
        return { relocate: new URL(here.pathname + here.search, MOVED) };
      }
      const url = new URL("https://custom.test/authorize");
      url.searchParams.set("state", context.record.state);
      if (context.loginHint !== undefined) url.searchParams.set("login", context.loginHint);
      return { url };
    },
    complete: async () => ({ identity: { subject: "acct-1", profile: {} } }),
  });
}

async function refusal(promise: Promise<unknown>): Promise<UnauthError> {
  const error: unknown = await promise.then(
    () => {
      throw new Error("expected a refusal");
    },
    (thrown: unknown) => thrown,
  );
  if (!isUnauthError(error, "ERR_AUTHN_CROSS_SITE_START")) throw error;
  expect(error.status).toBe(403);
  return error;
}

describe("a start that links an account", () => {
  const options = () => ({ key, redirectUri: REDIRECT_URI, memo: { userId: "u1" } });

  it("refuses a GET, whatever Sec-Fetch-Site says", async () => {
    const fake = await createFakeProvider();
    for (const site of [undefined, "none", "same-origin", "cross-site"]) {
      const headers: Record<string, string> = site === undefined ? {} : { "sec-fetch-site": site };
      const request = new Request(REDIRECT_URI, { headers });
      const error = await refusal(startFlow(oauth(), request, { ...options(), fetch: fake.fetch }));
      expect(error.cause).toEqual({ reason: "method" });
    }
    expect(fake.requests).toHaveLength(0);
  });

  it("refuses a POST without an Origin, or from another origin", async () => {
    const fake = await createFakeProvider();
    const bare = new Request(REDIRECT_URI, { method: "POST" });
    expect(
      (await refusal(startFlow(oauth(), bare, { ...options(), fetch: fake.fetch }))).cause,
    ).toEqual({
      reason: "origin",
    });
    const foreign = new Request(REDIRECT_URI, {
      method: "POST",
      headers: { origin: "https://evil.test" },
    });
    expect(
      (await refusal(startFlow(oauth(), foreign, { ...options(), fetch: fake.fetch }))).cause,
    ).toEqual({ reason: "origin" });
    const nullOrigin = new Request(REDIRECT_URI, { method: "POST", headers: { origin: "null" } });
    expect(
      (await refusal(startFlow(oauth(), nullOrigin, { ...options(), fetch: fake.fetch }))).cause,
    ).toEqual({ reason: "origin" });
  });

  it("refuses a POST claiming the application's origin from another site", async () => {
    const fake = await createFakeProvider();
    for (const site of ["cross-site", "same-site", "none"]) {
      const request = formStart(REDIRECT_URI, { headers: { "sec-fetch-site": site } });
      const error = await refusal(startFlow(oauth(), request, { ...options(), fetch: fake.fetch }));
      expect(error.cause).toEqual({ reason: "cross-site" });
    }
  });

  it("starts from a form on the application's own pages", async () => {
    const fake = await createFakeProvider();
    const forms: Record<string, string>[] = [{}, { "sec-fetch-site": "same-origin" }];
    for (const headers of forms) {
      const request = formStart(REDIRECT_URI, { headers });
      const response = await startFlow(oauth(), request, { ...options(), fetch: fake.fetch });
      expect(response.status).toBe(302);
      expect(new URL(response.headers.get("location")!).origin).toBe(ISSUER);
      expect(response.headers.getSetCookie().join("\n")).toMatch(/__Host-unauth-flow=/);
    }
  });

  it("starts from a form on a trusted origin, which the browser reports as another site", async () => {
    const fake = await createFakeProvider();
    const request = new Request(REDIRECT_URI, {
      method: "POST",
      headers: { "origin": "https://www.app.test", "sec-fetch-site": "same-site" },
    });
    const response = await startFlow(oauth(), request, {
      ...options(),
      trustedOrigins: ["https://www.app.test/"],
      fetch: fake.fetch,
    });
    expect(response.status).toBe(302);
  });

  it("leaves a start without a link or login as it was: a plain GET link signs in", async () => {
    const fake = await createFakeProvider();
    const response = await startFlow(oauth(), new Request(REDIRECT_URI), {
      key,
      redirectUri: REDIRECT_URI,
      redirect: "/after",
      fetch: fake.fetch,
    });
    expect(response.status).toBe(302);
  });
});

describe("a start naming the account of a custom provider", () => {
  it("refuses a GET and accepts a form", async () => {
    const provider = custom();
    const error = await refusal(
      startFlow(provider, new Request(`${APP}/auth/custom?login=alice`), {
        key,
        redirectUri: `${APP}/auth/custom`,
        loginHint: "alice",
      }),
    );
    expect(error.cause).toEqual({ reason: "method" });

    const response = await startFlow(provider, formStart(`${APP}/auth/custom?login=alice`), {
      key,
      redirectUri: `${APP}/auth/custom`,
      loginHint: "alice",
    });
    expect(new URL(response.headers.get("location")!).searchParams.get("login")).toBe("alice");
  });

  it("does not gate a relocated start opened from a sealed intent: it was checked where it began", async () => {
    const provider = custom({ relocateFrom: APP });
    const moved = await startFlow(provider, formStart(`${APP}/auth/custom`), {
      key,
      redirectUri: `${MOVED}/auth/custom`,
      trustedOrigins: [APP],
      loginHint: "alice",
      memo: { userId: "u1" },
    });
    const relocated = moved.headers.get("location")!;
    expect(new URL(relocated).origin).toBe(MOVED);

    const started = await startFlow(provider, new Request(relocated), {
      key,
      redirectUri: `${MOVED}/auth/custom`,
    });
    expect(started.status).toBe(302);
    expect(new URL(started.headers.get("location")!).searchParams.get("login")).toBe("alice");
  });

  it("gates the relocation itself, before any intent is sealed", async () => {
    const provider = custom({ relocateFrom: APP });
    const error = await refusal(
      startFlow(provider, new Request(`${APP}/auth/custom?login=alice`), {
        key,
        redirectUri: `${MOVED}/auth/custom`,
        loginHint: "alice",
      }),
    );
    expect(error.cause).toEqual({ reason: "method" });
  });
});

describe("through the sign-in handler", () => {
  it("answers a cross-site link start with 403 and runs nothing else", async () => {
    const fake = await createFakeProvider();
    const errors: UnauthError[] = [];
    const handler = defineSignInHandler(oauth(), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onStart: () => ({ memo: { userId: "victim" } }),
      onSuccess: () => "linked",
      onError: (_event, error) => {
        errors.push(error);
        return new Response(error.message, { status: error.status });
      },
    });
    const res = { headers: new Headers() };
    const answer = await handler({
      req: new Request(REDIRECT_URI, { headers: { "sec-fetch-site": "cross-site" } }),
      res,
    });
    expect((answer as Response).status).toBe(403);
    expect(errors.map((error) => error.code)).toEqual(["ERR_AUTHN_CROSS_SITE_START"]);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(fake.requests).toHaveLength(0);
  });

  it("answers it with a plain 403 without onError", async () => {
    const fake = await createFakeProvider();
    const handler = defineSignInHandler(oauth(), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onStart: () => ({ memo: { userId: "victim" } }),
      onSuccess: () => "linked",
    });
    const answer = await handler({
      req: new Request(REDIRECT_URI),
      res: { headers: new Headers() },
    });
    expect((answer as Response).status).toBe(403);
    expect(await (answer as Response).text()).toMatch(/from this site/);
  });

  it("refuses any method but GET and POST before doing anything", async () => {
    const fake = await createFakeProvider();
    const handler = defineSignInHandler(oauth(), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: () => "ok",
    });
    for (const method of ["PUT", "DELETE", "HEAD", "OPTIONS"]) {
      const res = { headers: new Headers() };
      const answer = await handler({ req: new Request(REDIRECT_URI, { method }), res });
      expect((answer as Response).status).toBe(405);
      expect((answer as Response).headers.get("allow")).toBe("GET, POST");
      expect(res.headers.getSetCookie()).toEqual([]);
    }
    expect(fake.requests).toHaveLength(0);
  });

  it("keeps a signed-in user's link out of an AT Protocol sign-in another site started", async () => {
    const fake = createFakeAtproto();
    const seen: unknown[] = [];
    const handler = defineAtprotoHandler({
      clientId: ATPROTO_CLIENT_ID,
      redirectUri: ATPROTO_REDIRECT_URI,
      dnsResolver: DNS,
      plcDirectory: PLC,
      key,
      fetch: fake.fetch,
      onStart: (event) => ({
        loginHint: new URL(event.req.url).searchParams.get("login") ?? undefined,
        memo: { userId: "victim" },
      }),
      onSuccess: (_event, result) => {
        seen.push(result);
        return "linked";
      },
    });
    const url = `${ATPROTO_REDIRECT_URI}?login=${ALICE.handle}`;

    // The navigation an attacker page triggers: the account it names picks the server that
    // would learn the flow's state. Nothing is pushed anywhere.
    const crossSite = await handler({
      req: new Request(url, { headers: { "sec-fetch-site": "cross-site" } }),
      res: { headers: new Headers() },
    });
    expect((crossSite as Response).status).toBe(403);
    expect(fake.pushed.size).toBe(0);
    expect(seen).toEqual([]);

    // The same sign-in from the application's own form goes to the server.
    const started = await handler({ req: formStart(url), res: { headers: new Headers() } });
    expect((started as Response).status).toBe(302);
    expect(new URL((started as Response).headers.get("location")!).origin).toBe(ATPROTO_ISSUER);
    expect(fake.pushed.size).toBe(1);
  });
});
