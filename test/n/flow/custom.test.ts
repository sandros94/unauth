import { beforeAll, describe, expect, it, vi } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type CustomProvider,
  type FlowRecord,
  completeFlow,
  defineProvider,
  isUnauthError,
  startFlow,
} from "../../../src/n/index.ts";
import { cookieHeader, isExpired } from "../_session.ts";

const APP = "https://app.test";
const REDIRECT_URI = `${APP}/auth/custom`;
const IDP = "https://custom.test";

let key: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
});

interface Account {
  id: string;
  handle: string;
}

/** A provider that sends the user to `IDP` with an opaque ticket it seals, and reads the account back from the callback. */
function ticketProvider(options: { tokens?: boolean } = {}) {
  const start = vi.fn(async (context: Parameters<CustomProvider["start"]>[0]) => {
    const url = new URL(`${IDP}/authorize`);
    url.searchParams.set("state", context.record.state);
    url.searchParams.set("redirect_uri", context.redirectUri);
    if (context.login !== undefined) url.searchParams.set("login", context.login);
    return { url, data: { ticket: `t-${context.login ?? "anonymous"}` } };
  });
  const complete = vi.fn(async (context: Parameters<CustomProvider<Account>["complete"]>[0]) => {
    const { ticket } = context.record.data ?? {};
    if (context.params.ticket !== ticket) {
      throw new TypeError("the callback carries another ticket");
    }
    const handle = context.params.handle ?? "anonymous";
    return {
      identity: {
        subject: `acct-${handle}`,
        profile: { id: `acct-${handle}`, handle },
        name: handle,
      },
      tokens: options.tokens
        ? { access_token: "at-1", token_type: "Custom", raw: { access_token: "at-1" } }
        : undefined,
    };
  });
  const provider = defineProvider<Account>({ id: "custom", kind: "custom", start, complete });
  return { provider, start, complete };
}

/** The provider's consent screen: the URL it sends the user back to. */
function approve(authorizationUrl: string, extra: Record<string, string> = {}): URL {
  const url = new URL(authorizationUrl);
  const back = new URL(url.searchParams.get("redirect_uri")!);
  back.searchParams.set("state", url.searchParams.get("state")!);
  back.searchParams.set("code", "c-1");
  back.searchParams.set("ticket", `t-${url.searchParams.get("login") ?? "anonymous"}`);
  back.searchParams.set("handle", url.searchParams.get("login") ?? "anonymous");
  for (const [name, value] of Object.entries(extra)) back.searchParams.set(name, value);
  return back;
}

async function run(
  provider: CustomProvider<Account>,
  options: Partial<Parameters<typeof startFlow>[2]> = {},
) {
  const response = await startFlow(provider, new Request(`${APP}/auth/custom`), {
    key,
    redirectUri: REDIRECT_URI,
    ...options,
  });
  const back = approve(response.headers.get("location")!);
  const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });
  const headers = new Headers();
  const result = await completeFlow(provider, request, { key, headers });
  return { response, back, result, headers };
}

describe("a custom provider", () => {
  it("runs both legs: the engine keeps state and the record, the provider its data", async () => {
    const { provider, start, complete } = ticketProvider();
    const { response, result, headers } = await run(provider, { login: "alice" });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin).toBe(IDP);
    expect(location.searchParams.get("login")).toBe("alice");

    const context = start.mock.calls[0]![0];
    expect(context.redirectUri).toBe(REDIRECT_URI);
    expect(context.record).toMatchObject({ provider: "custom", redirectUri: REDIRECT_URI });
    expect(context.record.state).toBe(location.searchParams.get("state"));

    const record: FlowRecord = complete.mock.calls[0]![0].record;
    expect(record.data).toEqual({ ticket: "t-alice" });
    expect(complete.mock.calls[0]![0].params).toMatchObject({ code: "c-1", handle: "alice" });

    expect(result.identity).toEqual({
      provider: "custom",
      subject: "acct-alice",
      profile: { id: "acct-alice", handle: "alice" },
      name: "alice",
    });
    expect(result.tokens).toBeUndefined();
    const line = headers.getSetCookie().find((l) => l.startsWith("__Host-unauth-flow="))!;
    expect(isExpired(line)).toBe(true);
  });

  it("hands tokens on when the provider returns them", async () => {
    const { provider } = ticketProvider({ tokens: true });
    const { result } = await run(provider);

    expect(result.tokens?.access_token).toBe("at-1");
    expect(result.tokens?.token_type).toBe("Custom");
    expect(Object.hasOwn(result.identity, "tokens")).toBe(false);
  });

  it("carries redirect and link through the record", async () => {
    const { provider } = ticketProvider();
    const { result } = await run(provider, { redirect: "/home", link: { userId: "u1" } });

    expect(result.redirect).toBe("/home");
    expect(result.link).toEqual({ userId: "u1" });
  });

  it("refuses a callback whose state is not the flow's before calling the provider", async () => {
    const { provider, complete } = ticketProvider();
    const response = await startFlow(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const back = approve(response.headers.get("location")!, { state: "forged" });
    const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });

    const error = await completeFlow(provider, request, { key, headers: new Headers() }).catch(
      (rejection: unknown) => rejection,
    );

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(complete).not.toHaveBeenCalled();
  });

  it("reports the provider's error parameter without calling the provider", async () => {
    const { provider, complete } = ticketProvider();
    const response = await startFlow(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const back = approve(response.headers.get("location")!, { error: "access_denied" });
    back.searchParams.delete("code");
    const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });

    const error = await completeFlow(provider, request, { key, headers: new Headers() }).catch(
      (rejection: unknown) => rejection,
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_REFUSED")).toBe(true);
    expect(complete).not.toHaveBeenCalled();
  });

  it("wraps a provider failure that is not an UnauthError as ERR_AUTHN_PROVIDER_ERROR", async () => {
    const { provider } = ticketProvider();
    const response = await startFlow(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const back = approve(response.headers.get("location")!, { ticket: "t-other" });
    const request = new Request(back, { headers: { cookie: cookieHeader(response.headers) } });

    const error = await completeFlow(provider, request, { key, headers: new Headers() }).catch(
      (rejection: unknown) => rejection,
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(error) && error.cause).toMatchObject({
      reason: "failed",
      cause: expect.any(TypeError),
    });
  });

  it("refuses an identity without a subject", async () => {
    const provider = defineProvider<Account>({
      id: "custom",
      kind: "custom",
      start: async ({ record }) => ({
        url: `${IDP}/authorize?state=${record.state}&redirect_uri=${REDIRECT_URI}`,
      }),
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a provider returning the wrong shape
      complete: async () => ({ identity: { profile: {} } }) as never,
    });
    const response = await startFlow(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const state = new URL(response.headers.get("location")!).searchParams.get("state")!;
    const request = new Request(`${REDIRECT_URI}?code=c&state=${state}`, {
      headers: { cookie: cookieHeader(response.headers) },
    });

    const error = await completeFlow(provider, request, { key, headers: new Headers() }).catch(
      (rejection: unknown) => rejection,
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("answers a relocation with a redirect and no flow cookie", async () => {
    const provider = defineProvider<Account>({
      id: "custom",
      kind: "custom",
      start: async () => ({ relocate: new URL("/auth/custom", "https://ip.test") }),
      complete: async () => ({ identity: { subject: "x", profile: { id: "x", handle: "x" } } }),
    });

    const response = await startFlow(provider, new Request(`${APP}/auth/custom?login=a`), {
      key,
      redirectUri: REDIRECT_URI,
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin + location.pathname).toBe("https://ip.test/auth/custom");
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("defineProvider refuses a custom provider without its legs", () => {
    expect(() =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the shape under test
      defineProvider({ id: "custom", kind: "custom", start: async () => ({ url: "" }) } as never),
    ).toThrow(/"start" and "complete"/);
  });
});
