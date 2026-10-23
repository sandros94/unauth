import { describe, expect, expectTypeOf, it } from "vitest";
import { type SessionManager, defineJWESession, generateJWK } from "unjwt/session";

import {
  type AuthSessionData,
  type HandlerEvent,
  type ProvenIdentity,
  type SessionAccess,
  type SessionWriter,
  toSessionData,
} from "../../src/n/index.ts";

const NOW = Date.UTC(2026, 9, 22, 12);

function identity(extra: Partial<ProvenIdentity<unknown>> = {}): ProvenIdentity<unknown> {
  return {
    provider: "github",
    subject: "42",
    profile: { login: "octocat" },
    tokens: { access_token: "secret", token_type: "bearer", raw: {} },
    ...extra,
  };
}

describe("toSessionData", () => {
  it("copies the members the identity has and stamps signedInAt from now", () => {
    const data = toSessionData(
      identity({
        name: "Octo Cat",
        email: "octo@example.com",
        emailVerified: false,
        avatar: "https://example.com/a.png",
      }),
      { now: NOW },
    );

    expect(data).toStrictEqual({
      provider: "github",
      subject: "42",
      name: "Octo Cat",
      email: "octo@example.com",
      emailVerified: false,
      avatar: "https://example.com/a.png",
      signedInAt: NOW,
    });
  });

  it("leaves the members the identity lacks absent, not undefined", () => {
    const data = toSessionData(identity(), { now: NOW });

    expect(data).toStrictEqual({ provider: "github", subject: "42", signedInAt: NOW });
    for (const member of ["name", "email", "emailVerified", "avatar"]) {
      expect(Object.hasOwn(data, member)).toBe(false);
    }
  });

  it("never copies the profile or the tokens", () => {
    const data = toSessionData(identity({ name: "Octo Cat" }), { now: NOW });

    expect(Object.hasOwn(data, "profile")).toBe(false);
    expect(Object.hasOwn(data, "tokens")).toBe(false);
  });
});

describe("SessionWriter", () => {
  it("is what an unjwt/session manager for the same data already is", async () => {
    expectTypeOf<SessionManager<AuthSessionData, "1h">>().toExtend<
      SessionWriter<AuthSessionData>
    >();

    const definition = defineJWESession<AuthSessionData, "1h">({
      key: await generateJWK("A256GCM"),
      maxAge: "1h",
    });
    const useAppSession = (event: HandlerEvent) => definition.use(event);
    expectTypeOf(useAppSession).toExtend<SessionAccess<AuthSessionData>>();

    const event = { req: new Request("https://app.test/"), res: { headers: new Headers() } };
    const writer: SessionWriter<AuthSessionData> = await useAppSession(event);
    await writer.update(toSessionData(identity(), { now: NOW }));

    expect(event.res.headers.getSetCookie()).toHaveLength(1);
  });
});
