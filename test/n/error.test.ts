import { describe, expect, expectTypeOf, it } from "vitest";

import { UnauthError, isUnauthError } from "../../src/n/index.ts";

describe("UnauthError", () => {
  it("carries name, code, message, status and cause", () => {
    const cause = new Error("upstream");
    const error = new UnauthError("[unauth/n] No session.", "ERR_AUTHN_UNAUTHENTICATED", {
      cause,
      status: 401,
    });

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(UnauthError);
    expect(error.name).toBe("UnauthError");
    expect(error.message).toBe("[unauth/n] No session.");
    expect(error.code).toBe("ERR_AUTHN_UNAUTHENTICATED");
    expect(error.status).toBe(401);
    expect(error.cause).toBe(cause);
  });

  it("leaves status and cause undefined when not given", () => {
    const error = new UnauthError("[unauth/n] Bad config.", "ERR_UNAUTH_CONFIG_INVALID");

    expect(error.status).toBeUndefined();
    expect(error.cause).toBeUndefined();
    expect("cause" in error).toBe(true);
  });

  it("accepts codes outside the known set", () => {
    const error = new UnauthError("custom", "ERR_APP_SPECIFIC");

    expect(error.code).toBe("ERR_APP_SPECIFIC");
    expectTypeOf(error.code).toEqualTypeOf<"ERR_APP_SPECIFIC">();
  });
});

describe("isUnauthError", () => {
  const error: unknown = new UnauthError("[unauth/n] No flow.", "ERR_AUTHN_FLOW_EXPIRED", {
    status: 401,
    cause: { reason: "unreadable" },
  });

  it("matches any UnauthError without a code", () => {
    expect(isUnauthError(error)).toBe(true);
  });

  it("matches only the given code", () => {
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    expect(isUnauthError(error, "ERR_AUTHN_UNAUTHENTICATED")).toBe(false);
  });

  it("rejects other errors and non-errors", () => {
    const lookalike = Object.assign(new Error("x"), { code: "ERR_AUTHN_UNAUTHENTICATED" });

    expect(isUnauthError(lookalike)).toBe(false);
    expect(isUnauthError(undefined)).toBe(false);
    expect(isUnauthError("ERR_AUTHN_UNAUTHENTICATED")).toBe(false);
  });

  it("narrows code and the typed cause", () => {
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    if (!isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")) return;
    expectTypeOf(error.code).toEqualTypeOf<"ERR_AUTHN_FLOW_EXPIRED">();
    expectTypeOf(error.cause).toEqualTypeOf<{
      reason: "missing" | "unreadable" | "consumed";
    }>();
    expect(error.cause.reason).toBe("unreadable");
  });

  it("leaves cause unknown for codes without a cause shape", () => {
    const unauthenticated: unknown = new UnauthError("x", "ERR_AUTHN_UNAUTHENTICATED");
    expect(isUnauthError(unauthenticated, "ERR_AUTHN_UNAUTHENTICATED")).toBe(true);
    if (!isUnauthError(unauthenticated, "ERR_AUTHN_UNAUTHENTICATED")) return;
    expectTypeOf(unauthenticated.cause).toEqualTypeOf<unknown>();
  });

  it("refuses unknown codes at the type level", () => {
    // @ts-expect-error misspelled codes do not compile
    expect(isUnauthError(error, "ERR_AUTHN_UNAUTHENTICATD")).toBe(false);
  });
});
