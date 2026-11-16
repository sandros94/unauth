import { describe, expect, expectTypeOf, it } from "vitest";
import { type AskOptions, ask } from "../../../src/z/ask.ts";
import { defineAuthz } from "../../../src/z/authz.ts";
import { defineCatalog } from "../../../src/z/catalog.ts";
import {
  type AssertGrantsOptions,
  type CouldOptions,
  type DivergedOptions,
  type IssueGrantsOptions,
  type RolesOfOptions,
  assertGrants,
  could,
  diverged,
  issueGrants,
  rolesOf,
} from "../../../src/z/grants.ts";
import type { Statement } from "../../../src/z/types.ts";
import {
  type ValidateRoleOptions,
  type ValidateStatementOptions,
  validateStatement,
} from "../../../src/z/validate.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const END = MONDAY + 3600;
const catalog = defineCatalog({
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { viewer: ["report:read"] },
});
const issued = issueGrants(
  catalog,
  { subject: "ann", statements: [{ kind: "assign", subject: "ann", value: "viewer" }] },
  { now: () => MONDAY * 1000 },
);
const question = { permission: "report:read" } as const;
const allow: Statement = { kind: "allow", subject: "ann", value: "report:read", expiresAt: END };

function at(seconds: number, clockTolerance?: number) {
  return clockTolerance === undefined
    ? { now: () => seconds * 1000 }
    : { now: () => seconds * 1000, clockTolerance };
}

const reads: [string, (options: CouldOptions) => unknown][] = [
  ["could", (options) => could(catalog, issued, question, options)],
  ["diverged", (options) => diverged(catalog, issued, options)],
  ["assertGrants", (options) => assertGrants(catalog, issued, options)],
  ["rolesOf", (options) => rolesOf(catalog, issued, undefined, options)],
];

describe("a clock tolerance is for reads of grants only (Section 8.3)", () => {
  it("is no option of `ask`, `issueGrants` or a validation", () => {
    type Has<T> = "clockTolerance" extends keyof T ? true : false;
    expectTypeOf<Has<AskOptions>>().toEqualTypeOf<false>();
    expectTypeOf<Has<IssueGrantsOptions>>().toEqualTypeOf<false>();
    expectTypeOf<Has<ValidateStatementOptions>>().toEqualTypeOf<false>();
    expectTypeOf<Has<ValidateRoleOptions>>().toEqualTypeOf<false>();
    expectTypeOf<Has<CouldOptions>>().toEqualTypeOf<true>();
    expectTypeOf<Has<DivergedOptions>>().toEqualTypeOf<true>();
    expectTypeOf<Has<AssertGrantsOptions>>().toEqualTypeOf<true>();
    expectTypeOf<Has<RolesOfOptions>>().toEqualTypeOf<true>();
    expectTypeOf<CouldOptions["clockTolerance"]>().toEqualTypeOf<number | undefined>();
    expectTypeOf<Parameters<typeof ask>[3]>().toEqualTypeOf<AskOptions | undefined>();
    expectTypeOf<Parameters<typeof could>[3]>().toEqualTypeOf<CouldOptions | undefined>();
    expectTypeOf<Parameters<typeof diverged>[2]>().toEqualTypeOf<DivergedOptions | undefined>();
    expectTypeOf<Parameters<typeof assertGrants>[2]>().toEqualTypeOf<
      AssertGrantsOptions | undefined
    >();
    expectTypeOf<Parameters<typeof rolesOf>[3]>().toEqualTypeOf<RolesOfOptions | undefined>();
  });

  it("changes nothing when smuggled into `ask`, `issueGrants` or a validation", () => {
    const smuggled = (seconds: number): AskOptions => at(seconds, 10);
    const read = { subject: "ann", statements: [allow] };
    expect(ask(catalog, read, question, smuggled(END + 5))).toStrictEqual(
      ask(catalog, read, question, at(END + 5)),
    );
    expect(ask(catalog, read, question, smuggled(END + 5)).allowed).toBe(false);
    const negative: AskOptions = at(END - 1, -1);
    expect(ask(catalog, read, question, negative).allowed).toBe(true);
    const issue: IssueGrantsOptions = at(END + 5, 10);
    expect(issueGrants(catalog, read, issue)).toStrictEqual(
      issueGrants(catalog, read, at(END + 5)),
    );
    expect(issueGrants(catalog, read, issue).nt).toStrictEqual({});
    const options: ValidateStatementOptions = at(END, 10);
    expect(validateStatement(catalog, allow, options)).toMatchObject([
      { code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["expiresAt"] },
    ]);
  });
});

describe("a clock tolerance in a read of grants (Section 8.3)", () => {
  const behind = {
    v: "1",
    ct: catalog.fingerprint,
    at: MONDAY,
    nt: { "report:read": { a: [[null, END]] }, "viewer": { a: [[null, END]] } },
  };

  it("counts an item that ended 5 seconds ago with 10, and not without", () => {
    expect(could(catalog, behind, question, at(END + 5)).allowed).toBe(false);
    expect(could(catalog, behind, question, at(END + 5, 10))).toMatchObject({
      allowed: true,
      by: { kind: "allow", value: "report:read", expiresAt: END },
    });
    expect(could(catalog, behind, question, at(END + 10, 10)).allowed).toBe(false);
    expect(could(catalog, behind, question, at(END + 9, 10)).allowed).toBe(true);
    expect(rolesOf(catalog, behind, undefined, at(END + 5))).toStrictEqual([]);
    expect(rolesOf(catalog, behind, undefined, at(END + 5, 10))).toStrictEqual(["viewer"]);
    expect(rolesOf(catalog, behind, undefined, at(END + 10, 10))).toStrictEqual([]);
  });

  it("blocks with a deny item that ended 5 seconds ago with 10", () => {
    const denied = { ...behind, nt: { ...behind.nt, "report:*": { d: [[null, END]] } } };
    expect(could(catalog, denied, question, at(END - 1)).by?.kind).toBe("deny");
    expect(could(catalog, denied, question, at(END + 5)).by).toBeUndefined();
    expect(could(catalog, denied, question, at(END + 5, 10)).by?.kind).toBe("deny");
  });

  it.each(reads)("%s refuses a clock behind the issue when no tolerance is given", (_, run) => {
    expect(() => run(at(MONDAY))).not.toThrow();
    expect(refused(() => run(at(MONDAY - 5)))).toMatchObject({ code: "ERR_AUTHZ_GRANTS_FUTURE" });
    expect(refused(() => run(at(MONDAY - 1, 0)))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FUTURE",
    });
  });

  it.each(reads)("%s reads a clock behind the issue up to the tolerance", (_, run) => {
    expect(() => run(at(MONDAY - 5, 10))).not.toThrow();
    expect(() => run(at(MONDAY - 10, 10))).not.toThrow();
    expect(refused(() => run(at(MONDAY - 11, 10)))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FUTURE",
    });
    expect(() => run(at(MONDAY - 300, 300))).not.toThrow();
    expect(refused(() => run(at(MONDAY - 301, 300)))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FUTURE",
    });
  });

  it("answers behind the issue from what the grants hold", () => {
    expect(could(catalog, issued, question, at(MONDAY - 5, 10))).toStrictEqual(
      could(catalog, issued, question, at(MONDAY)),
    );
    expect(rolesOf(catalog, issued, undefined, at(MONDAY - 5, 10))).toStrictEqual(
      rolesOf(catalog, issued, undefined, at(MONDAY)),
    );
  });
});

describe("`ask` and `could` differ on what ended less than the tolerance ago (Section 8.3, G8)", () => {
  it("denies by `ask` and allows by `could` an allow that ended 5 seconds ago, then agrees", () => {
    const read = { subject: "ann", statements: [allow] };
    const grants = issueGrants(catalog, read, at(END - 60));
    expect(ask(catalog, read, question, at(END - 1)).allowed).toBe(true);
    expect(could(catalog, grants, question, at(END - 1, 10)).allowed).toBe(true);
    expect(ask(catalog, read, question, at(END + 5)).allowed).toBe(false);
    expect(could(catalog, grants, question, at(END + 5, 10))).toMatchObject({
      allowed: true,
      by: { kind: "allow", value: "report:read", expiresAt: END },
    });
    expect(ask(catalog, read, question, at(END + 15)).allowed).toBe(false);
    expect(could(catalog, grants, question, at(END + 15, 10)).allowed).toBe(false);
  });
});

describe("a clock tolerance that is not a non-negative whole number of seconds", () => {
  const bad: unknown[] = [
    -1,
    -0.5,
    0.5,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    "30s",
    "30",
    "5m",
    "10",
    "soon",
    "-5s",
    "",
    null,
    10n,
    {},
    [10],
    true,
  ];

  it.each(reads)("is a configuration that cannot work for %s", (_, run) => {
    for (const clockTolerance of bad) {
      const options = { now: () => MONDAY * 1000, clockTolerance } as CouldOptions;
      const error = refused(() => run(options));
      expect(error).toMatchObject({ code: "ERR_UNAUTH_CONFIG_INVALID", status: 500 });
      expect(error.message).toMatch(/^\[unauth\/z\] /);
    }
  });

  it("names the option and the value refused", () => {
    const options = { clockTolerance: "30s" } as unknown as CouldOptions;
    expect(refused(() => could(catalog, issued, question, options)).message).toBe(
      '[unauth/z] clockTolerance needs a non-negative whole number of seconds, got "30s".',
    );
    expect(refused(() => could(catalog, issued, question, { clockTolerance: 0.5 })).message).toBe(
      "[unauth/z] clockTolerance needs a non-negative whole number of seconds, got 0.5.",
    );
  });

  it("takes 0, a whole number and absent", () => {
    for (const clockTolerance of [0, 10, undefined]) {
      expect(could(catalog, issued, question, at(MONDAY, clockTolerance)).allowed).toBe(true);
    }
  });
});

describe("the bound engine", () => {
  const authz = defineAuthz(catalog);
  const read = { subject: "ann", statements: [allow] };

  it("passes the tolerance to the reads as the functions do", () => {
    const grants = authz.issueGrants(read, at(END - 60));
    expect(authz.could(grants, question, at(END + 5, 10)).allowed).toBe(true);
    expect(authz.could(grants, question, at(END + 5)).allowed).toBe(false);
    expect(refused(() => authz.could(grants, question, at(END - 61)))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FUTURE",
    });
    expect(() => authz.diverged(grants, at(END - 61, 1))).not.toThrow();
    expect(authz.rolesOf(issued, undefined, at(MONDAY - 1, 1))).toStrictEqual(
      rolesOf(catalog, issued, undefined, at(MONDAY)),
    );
    expect(refused(() => authz.could(issued, question, { clockTolerance: -1 }))).toMatchObject({
      code: "ERR_UNAUTH_CONFIG_INVALID",
    });
    expectTypeOf<Parameters<typeof authz.ask>[2]>().toEqualTypeOf<AskOptions | undefined>();
    expectTypeOf<Parameters<typeof authz.could>[2]>().toEqualTypeOf<CouldOptions | undefined>();
    expectTypeOf<Parameters<typeof authz.diverged>[1]>().toEqualTypeOf<
      DivergedOptions | undefined
    >();
    expectTypeOf<Parameters<typeof authz.rolesOf>[2]>().toEqualTypeOf<RolesOfOptions | undefined>();
    expectTypeOf<Parameters<typeof authz.issueGrants>[1]>().toEqualTypeOf<
      IssueGrantsOptions | undefined
    >();
  });
});
