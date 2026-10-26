import { describe, expect, it } from "vitest";

import { isUnauthError } from "../../../src/n/index.ts";
import type { CustomProvider, CustomStart, FlowRecord } from "../../../src/n/flow/types.ts";
import {
  type SteamProfile,
  defineSteamHandler,
  defineSteamProvider,
} from "../../../src/n/providers/steam.ts";

const OP_ENDPOINT = "https://steamcommunity.com/openid/login";
const NS = "http://specs.openid.net/auth/2.0";
const REDIRECT_URI = "https://app.test/auth/steam";
const STATE = "st4te";
const RETURN_TO = `${REDIRECT_URI}?state=${STATE}`;
const STEAMID = "76561197960287930";
const CLAIMED_ID = `https://steamcommunity.com/openid/id/${STEAMID}`;
const API_KEY = "0123456789ABCDEF0123456789ABCDEF";
const VALID = `ns:${NS}\nis_valid:true\n`;

const PLAYER = {
  steamid: STEAMID,
  communityvisibilitystate: 3,
  profilestate: 1,
  personaname: "Gordon",
  profileurl: `https://steamcommunity.com/profiles/${STEAMID}/`,
  avatar: "https://avatars.steamstatic.com/abc.jpg",
  avatarmedium: "https://avatars.steamstatic.com/abc_medium.jpg",
  avatarfull: "https://avatars.steamstatic.com/abc_full.jpg",
  avatarhash: "abc",
  lastlogoff: 1_790_000_000,
  personastate: 1,
  realname: "Gordon Freeman",
  primaryclanid: "103582791429521412",
  timecreated: 1_063_407_589,
  personastateflags: 0,
  loccountrycode: "US",
};

type Fetch = CustomProvider<SteamProfile>["complete"] extends (context: infer C) => unknown
  ? C extends { fetch: infer F }
    ? F
    : never
  : never;

interface Fake {
  fetch: Fetch;
  requests: { url: URL; method: string; headers: Headers; body: string }[];
}

function fake(answers: { check?: Response | string; summary?: unknown } = {}): Fake {
  const requests: Fake["requests"] = [];
  const fetch: Fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    requests.push({
      url,
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
    if (url.href === OP_ENDPOINT) {
      const check = answers.check ?? VALID;
      return check instanceof Response
        ? check
        : new Response(check, { headers: { "content-type": "text/plain" } });
    }
    if (url.hostname === "api.steampowered.com") {
      const summary = answers.summary ?? { response: { players: [PLAYER] } };
      return summary instanceof Response ? summary : Response.json(summary);
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch, requests };
}

function record(
  options: { data?: Record<string, unknown> } = { data: { returnTo: RETURN_TO } },
): FlowRecord {
  const flow: FlowRecord = { provider: "steam", state: STATE, redirectUri: REDIRECT_URI };
  if (options.data !== undefined) flow.data = options.data;
  return flow;
}

function assertion(overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const params: Record<string, string | undefined> = {
    "state": STATE,
    "openid.ns": NS,
    "openid.mode": "id_res",
    "openid.op_endpoint": OP_ENDPOINT,
    "openid.claimed_id": CLAIMED_ID,
    "openid.identity": CLAIMED_ID,
    "openid.return_to": RETURN_TO,
    "openid.response_nonce": "2026-10-24T10:00:00Zabcdef",
    "openid.assoc_handle": "1234567890",
    "openid.signed": "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle",
    "openid.sig": "c2lnbmF0dXJl",
    ...overrides,
  };
  return Object.fromEntries(
    Object.entries(params).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

async function begin(provider: CustomProvider<SteamProfile>, fetch: Fetch) {
  return provider.start({
    request: new Request("https://app.test/login"),
    record: record({}),
    redirectUri: REDIRECT_URI,
    fetch,
    now: Date.now,
  });
}

async function finish(
  provider: CustomProvider<SteamProfile>,
  fetch: Fetch,
  options: { params?: Record<string, string>; record?: FlowRecord } = {},
) {
  return provider.complete({
    request: new Request(RETURN_TO),
    params: options.params ?? assertion(),
    record: options.record ?? record(),
    fetch,
    now: Date.now,
  });
}

function started(start: CustomStart): { url: URL; data: Record<string, unknown> | undefined } {
  if (start.relocate !== undefined) throw new Error("expected a start, got a relocation");
  return { url: new URL(start.url), data: start.data };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("start", () => {
  it("sends the user to Steam with the callback and its state as return_to, the origin as realm", async () => {
    const { fetch, requests } = fake();
    const { url, data } = started(await begin(defineSteamProvider({}), fetch));

    expect(url.origin + url.pathname).toBe(OP_ENDPOINT);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      "openid.ns": NS,
      "openid.mode": "checkid_setup",
      "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
      "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
      "openid.return_to": RETURN_TO,
      "openid.realm": "https://app.test",
    });
    expect(data).toEqual({ returnTo: RETURN_TO });
    expect(requests).toHaveLength(0);
  });

  it("keeps the callback's own query before state", async () => {
    const provider = defineSteamProvider({});
    const { url } = started(
      await provider.start({
        request: new Request("https://app.test/login"),
        record: record({}),
        redirectUri: `${REDIRECT_URI}?tenant=acme`,
        fetch: fake().fetch,
        now: Date.now,
        loginHint: "ignored",
        scopes: ["ignored"],
        params: { prompt: "ignored" },
      }),
    );
    expect(url.searchParams.get("openid.return_to")).toBe(
      `${REDIRECT_URI}?tenant=acme&state=${STATE}`,
    );
    expect(url.searchParams.has("prompt")).toBe(false);
  });
});

describe("complete", () => {
  it("verifies the assertion at Steam and proves the SteamID alone without an apiKey", async () => {
    const { fetch, requests } = fake();
    const result = await finish(defineSteamProvider({}), fetch);

    expect(result).toEqual({ identity: { subject: STEAMID, profile: { steamid: STEAMID } } });
    expect(requests).toHaveLength(1);
    const [check] = requests;
    expect(check!.method).toBe("POST");
    expect(check!.url.href).toBe(OP_ENDPOINT);
    expect(check!.headers.get("content-type")).toContain("application/x-www-form-urlencoded");
    const sent = Object.fromEntries(new URLSearchParams(check!.body));
    const { state: _state, ...expected } = assertion();
    expect(sent).toEqual({ ...expected, "openid.mode": "check_authentication" });
  });

  it("fetches the player summary with the apiKey, which the browser never sees", async () => {
    const { fetch, requests } = fake();
    const provider = defineSteamProvider({ apiKey: API_KEY });
    expect(started(await begin(provider, fetch)).url.href).not.toContain(API_KEY);

    const result = await finish(provider, fetch);

    expect(result.identity).toEqual({
      subject: STEAMID,
      profile: PLAYER,
      name: "Gordon",
      avatar: PLAYER.avatarfull,
    });
    expect(result.tokens).toBeUndefined();
    const summary = requests[1]!;
    expect(summary.method).toBe("GET");
    expect(summary.url.origin + summary.url.pathname).toBe(
      "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
    );
    expect(Object.fromEntries(summary.url.searchParams)).toEqual({
      key: API_KEY,
      steamids: STEAMID,
    });
  });

  it("falls back to the smaller avatars and skips an empty persona name", async () => {
    const { fetch } = fake({
      summary: {
        response: {
          players: [{ steamid: STEAMID, personaname: "", avatarmedium: "m", avatar: "s" }],
        },
      },
    });
    const result = await finish(defineSteamProvider({ apiKey: API_KEY }), fetch);
    expect(result.identity.name).toBeUndefined();
    expect(result.identity.avatar).toBe("m");
  });

  it.each([
    [
      "an op_endpoint that is not Steam's",
      { "openid.op_endpoint": "https://evil.test/openid/login" },
      "op_endpoint",
    ],
    [
      "a return_to that is not the one sent",
      { "openid.return_to": `${REDIRECT_URI}?state=other` },
      "return_to",
    ],
    [
      "a claimed_id outside steamcommunity.com",
      {
        "openid.claimed_id": `https://evil.test/openid/id/${STEAMID}`,
        "openid.identity": `https://evil.test/openid/id/${STEAMID}`,
      },
      "claimed_id",
    ],
    [
      "a claimed_id that is not a SteamID64",
      {
        "openid.claimed_id": "https://steamcommunity.com/openid/id/123",
        "openid.identity": "https://steamcommunity.com/openid/id/123",
      },
      "claimed_id",
    ],
    [
      "an identity other than the claimed_id",
      { "openid.identity": "https://steamcommunity.com/openid/id/76561197960287931" },
      "identity",
    ],
    [
      "a signature that does not cover response_nonce",
      { "openid.signed": "signed,op_endpoint,claimed_id,identity,return_to,assoc_handle" },
      "signed",
    ],
    [
      "a signed field the assertion does not carry",
      {
        "openid.signed":
          "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle,extra",
      },
      "signed",
    ],
  ])("refuses %s before asking Steam", async (_name, overrides, reason) => {
    const { fetch, requests } = fake();
    const error = await rejection(
      finish(defineSteamProvider({}), fetch, { params: assertion(overrides) }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(401);
    expect(isUnauthError(error) && error.cause).toMatchObject({ provider: "steam", reason });
    expect(requests).toHaveLength(0);
  });

  it("refuses a record start did not seal", async () => {
    const { fetch, requests } = fake();
    const error = await rejection(finish(defineSteamProvider({}), fetch, { record: record({}) }));

    expect(isUnauthError(error, "ERR_AUTHN_STATE_MISMATCH")).toBe(true);
    expect(requests).toHaveLength(0);
  });

  it("reports a cancelled sign-in as the provider's refusal", async () => {
    const { fetch, requests } = fake();
    const params = assertion({
      "openid.mode": "cancel",
      "openid.claimed_id": undefined,
      "openid.identity": undefined,
      "openid.signed": undefined,
      "openid.sig": undefined,
    });
    const error = await rejection(finish(defineSteamProvider({}), fetch, { params }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_REFUSED")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(401);
    expect(isUnauthError(error) && error.cause).toEqual({ error: "cancel" });
    expect(requests).toHaveLength(0);
  });

  it("refuses a mode that is neither id_res nor cancel", async () => {
    const { fetch } = fake();
    for (const mode of ["setup_needed", undefined]) {
      const error = await rejection(
        finish(defineSteamProvider({}), fetch, { params: assertion({ "openid.mode": mode }) }),
      );
      expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
      expect(isUnauthError(error) && error.cause).toMatchObject({ reason: "malformed" });
    }
  });

  it("refuses an assertion Steam does not confirm", async () => {
    const { fetch, requests } = fake({ check: `ns:${NS}\nis_valid:false\n` });
    const error = await rejection(finish(defineSteamProvider({ apiKey: API_KEY }), fetch));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_REFUSED")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(401);
    expect(requests).toHaveLength(1);
  });

  it.each([
    ["a failed status", new Response("", { status: 500 }), "status"],
    ["no Key-Value Form", "<html>", "malformed"],
    ["no is_valid", `ns:${NS}\n`, "malformed"],
  ])(
    "reports a check_authentication answer with %s as a provider error",
    async (_name, check, reason) => {
      const error = await rejection(finish(defineSteamProvider({}), fake({ check }).fetch));

      expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
      expect(isUnauthError(error) && error.cause).toMatchObject({ reason });
    },
  );

  it("refuses a player summary that is empty or names another account", async () => {
    const empty = await rejection(
      finish(
        defineSteamProvider({ apiKey: API_KEY }),
        fake({ summary: { response: { players: [] } } }).fetch,
      ),
    );
    expect(isUnauthError(empty, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);

    const other = await rejection(
      finish(
        defineSteamProvider({ apiKey: API_KEY }),
        fake({ summary: { response: { players: [{ ...PLAYER, steamid: "76561197960287931" }] } } })
          .fetch,
      ),
    );
    expect(isUnauthError(other, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("keeps the apiKey out of a failed summary fetch's message", async () => {
    const error = await rejection(
      finish(
        defineSteamProvider({ apiKey: API_KEY }),
        fake({ summary: new Response("", { status: 403 }) }).fetch,
      ),
    );
    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(error) && error.message).not.toContain(API_KEY);
    expect(isUnauthError(error) && error.cause).toMatchObject({ reason: "status", status: 403 });
  });
});

describe("defineSteamProvider", () => {
  it("is a custom provider with the callback it was given", () => {
    const provider = defineSteamProvider({
      redirectUri: REDIRECT_URI,
      id: "steam-2",
      label: "Valve",
    });
    expect(provider).toMatchObject({
      id: "steam-2",
      kind: "custom",
      label: "Valve",
      redirectUri: REDIRECT_URI,
    });
    expect(defineSteamProvider({})).toMatchObject({ id: "steam", label: "Steam" });
    expect(Object.hasOwn(defineSteamProvider({}), "redirectUri")).toBe(false);
  });

  it("refuses an empty apiKey", () => {
    expect(() => defineSteamProvider({ apiKey: "" })).toThrow(/apiKey/);
  });

  it("has a handler", () => {
    expect(defineSteamHandler).toBeTypeOf("function");
  });
});
