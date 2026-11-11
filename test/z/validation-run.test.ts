import { describe, expect, it } from "vitest";

import { type KnownUnauthErrorCode, UnauthError } from "../../src/error.ts";
import type { Catalog, CatalogData } from "../../src/z/catalog.ts";
import type { Grants, Question, Statement } from "../../src/z/types.ts";
import {
  runCatalogCase,
  runGrantsCase,
  runPlaceCase,
  runScenario,
  validateEngine,
} from "../../src/z/validation/run.ts";
import { decisionDepthScenarios } from "../../src/z/validation/scenarios/decision-depth.ts";
import { decisionExclusionScenarios } from "../../src/z/validation/scenarios/decision-exclusions.ts";
import { decisionInvalidScenarios } from "../../src/z/validation/scenarios/decision-invalid.ts";
import { decisionPlatformScenarios } from "../../src/z/validation/scenarios/decision-platforms.ts";
import { decisionStructureScenarios } from "../../src/z/validation/scenarios/decision-structure.ts";
import { decisionWorkspaceScenarios } from "../../src/z/validation/scenarios/decision-workspace.ts";
import { decisionScenarios } from "../../src/z/validation/scenarios/decision.ts";
import { grantsBundleScenarios } from "../../src/z/validation/scenarios/grants-bundles.ts";
import { grantsCases } from "../../src/z/validation/scenarios/grants-cases.ts";
import { grantsScenarios } from "../../src/z/validation/scenarios/grants.ts";
import { roleScenarios } from "../../src/z/validation/scenarios/roles.ts";
import type {
  Engine,
  GrantsCase,
  Scenario,
  ValidationFailure,
} from "../../src/z/validation/types.ts";

const MONDAY = 1794214800;

const catalogData: CatalogData = {
  permissions: ["doc:read", "doc:write", "access:manage"],
  manager: "access:manage",
};

const scenario: Scenario = {
  id: "fake/office",
  title: "An office where the owner allows Bob to read and later stops",
  proves: ["D1"],
  catalog: catalogData,
  statements: [
    { kind: "allow", subject: "owner", value: "*" },
    { kind: "allow", subject: "ann", value: "doc:read", place: "/org=acme" },
    { kind: "allow", subject: "bob", value: "doc:read", place: "/org=globex" },
  ],
  steps: [
    {
      step: "ask",
      at: MONDAY,
      question: { subject: "bob", permission: "doc:read", place: "/org=acme" },
      expect: "denied",
    },
    {
      step: "change",
      at: MONDAY + 60,
      author: "owner",
      change: {
        action: "place",
        statement: { kind: "allow", subject: "bob", value: "doc:read", place: "/org=acme" },
      },
      expect: "accepted",
    },
    {
      step: "ask",
      at: MONDAY + 120,
      question: {
        subject: "bob",
        groups: ["staff"],
        permission: "doc:read",
        place: "/org=acme/unit=u1",
      },
      expect: "allowed",
      issuedAt: MONDAY + 120,
      bases: ["/org=acme"],
    },
    {
      step: "ask",
      at: MONDAY + 120,
      question: { subject: "bob", permission: "doc:read", place: "/org=initech" },
      expect: "denied",
      issuedAt: MONDAY + 120,
      bases: ["/org=acme"],
      fromGrants: "not-covered",
    },
    {
      step: "ask",
      at: MONDAY + 120,
      question: { subject: "bob", permission: "" },
      expect: "ERR_AUTHZ_QUESTION_INVALID",
    },
    { step: "issue", at: MONDAY + 180, as: "bob", subject: "bob" },
    {
      step: "read",
      at: MONDAY + 180,
      grants: "bob",
      question: { permission: "doc:read", place: "/org=acme" },
      expect: "allowed",
    },
    {
      step: "read",
      at: MONDAY + 179,
      grants: ["bob"],
      question: { permission: "doc:read", place: "/org=acme" },
      expect: "ERR_AUTHZ_GRANTS_EARLY",
    },
    {
      step: "change",
      at: MONDAY + 200,
      author: "bob",
      change: {
        action: "place",
        statement: { kind: "allow", subject: "bob", value: "doc:write", place: "/org=acme" },
      },
      expect: "ERR_AUTHZ_CHANGE_REFUSED",
      reasons: ["not-manager", "about-self"],
    },
    {
      step: "write",
      remove: [{ kind: "allow", subject: "bob", value: "doc:read", place: "/org=acme" }],
    },
    {
      step: "ask",
      at: MONDAY + 240,
      question: { subject: "bob", permission: "doc:read", place: "/org=acme" },
      expect: "denied",
    },
    {
      step: "read",
      at: MONDAY + 240,
      grants: "bob",
      question: { permission: "doc:read", place: "/org=acme" },
      expect: "allowed",
    },
  ],
};

const grantsCase: GrantsCase = {
  id: "fake/grants",
  title: "Grants written by hand for the catalog",
  catalog: catalogData,
  grants: { v: "1", ct: "$ct", at: MONDAY, fid: "hand", nt: {} },
  at: MONDAY,
  question: { permission: "doc:read", place: "/org=acme" },
  expect: "allowed",
};

const handWritten = new Map<string, { identifiers: string[]; statements: Statement[] }>([
  [
    "hand",
    {
      identifiers: ["ann"],
      statements: [{ kind: "allow", subject: "ann", value: "doc:read", place: "/org=acme" }],
    },
  ],
]);

const issued = new Map<string, { identifiers: string[]; statements: Statement[] }>(handWritten);

const fake: Engine = {
  defineCatalog: (data) => {
    if (!Array.isArray(data.permissions)) refuse("ERR_AUTHZ_CATALOG_INVALID");
    return { data, fingerprint: `fp:${data.permissions.join(",")}` };
  },
  decide: (catalog, question, options) => {
    const allowed = fakeDecide(catalog, question, options.statements, seconds(options.now));
    return { allowed, covered: true };
  },
  issueGrants: (catalog, subject, options) => {
    const at = seconds(options.now);
    const identifiers = [subject, ...(options.groups ?? [])];
    const fid = `g${issued.size}`;
    issued.set(fid, {
      identifiers,
      statements: options.statements.filter(
        (statement) => identifiers.includes(statement.subject) && live(statement, at),
      ),
    });
    const grants: Grants = { v: "1", ct: catalog.fingerprint, at, nt: {}, fid };
    if (options.bases !== undefined) grants.bs = [...options.bases];
    return grants;
  },
  readGrants: (catalog, grants, question, options) => {
    const at = seconds(options?.now);
    const sets: unknown[] = Array.isArray(grants) ? grants : [grants];
    const answers: boolean[] = [];
    for (const value of sets) {
      if (typeof value !== "object" || value === null) refuse("ERR_AUTHZ_MALFORMED");
      const set = value as Grants;
      if (set.ct !== catalog.fingerprint) refuse("ERR_AUTHZ_GRANTS_CATALOG");
      if (at < set.at) refuse("ERR_AUTHZ_GRANTS_EARLY");
      const place = question.place ?? "/";
      if (set.bs !== undefined && !set.bs.some((base) => covers(base, place))) continue;
      const kept = typeof set.fid === "string" ? issued.get(set.fid) : undefined;
      if (kept === undefined) refuse("ERR_AUTHZ_MALFORMED");
      answers.push(
        fakeDecide(
          catalog,
          { ...question, subject: kept.identifiers[0] ?? "", groups: kept.identifiers.slice(1) },
          kept.statements,
          at,
        ),
      );
    }
    if (answers.length === 0) return { allowed: false, covered: false };
    return { allowed: answers.every(Boolean), covered: true };
  },
  checkChange: (_catalog, change, options) => {
    const reasons: ("not-manager" | "about-self")[] = [];
    const manager = options.statements.some(
      (statement) => statement.subject === options.author && statement.value === "*",
    );
    if (!manager) reasons.push("not-manager");
    if (change.action !== "define" && change.statement.subject === options.author) {
      reasons.push("about-self");
    }
    if (reasons.length > 0) refuse("ERR_AUTHZ_CHANGE_REFUSED", { reasons });
  },
  checkGenesis: (_catalog, _statement, options) => {
    if (options.managers.length > 0) refuse("ERR_AUTHZ_CHANGE_REFUSED", { reasons: ["not-first"] });
  },
  placeChain: (key) => {
    if (!key.startsWith("/")) refuse("ERR_AUTHZ_MALFORMED");
    const chain = [key];
    let current = key;
    while (current !== "/") {
      current = current.slice(0, current.lastIndexOf("/")) || "/";
      chain.push(current);
    }
    return chain;
  },
  placeRange: (key) => {
    if (!key.startsWith("/")) refuse("ERR_AUTHZ_MALFORMED");
    return key === "/" ? { after: "/", before: "0" } : { after: `${key}/`, before: `${key}0` };
  },
};

describe("runScenario", () => {
  it("passes an engine that answers as each step expects", () => {
    expect(() => runScenario(fake, scenario)).not.toThrow();
  });

  it("fails an engine that answers the opposite", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          decide: (catalog, question, options) => {
            const decision = fake.decide(catalog, question, options);
            return { ...decision, allowed: !decision.allowed };
          },
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({
      id: "fake/office",
      step: 0,
      given: "everything",
      expected: "denied",
      received: "allowed",
    });
  });

  it("fails an engine that throws another code", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          decide: (catalog, question, options) => {
            if (question.permission === "") refuse("ERR_AUTHZ_MALFORMED");
            return fake.decide(catalog, question, options);
          },
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({
      step: 4,
      expected: "ERR_AUTHZ_QUESTION_INVALID",
      received: "ERR_AUTHZ_MALFORMED",
    });
  });

  it("fails an engine that names other reasons", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          checkChange: (catalog, change, options) => {
            if (options.author === "bob")
              refuse("ERR_AUTHZ_CHANGE_REFUSED", { reasons: ["not-manager"] });
            fake.checkChange(catalog, change, options);
          },
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({
      step: 8,
      expected: { reasons: ["about-self", "not-manager"] },
      received: { reasons: ["not-manager"] },
    });
  });

  it("fails an engine whose answer changes when handed more statements", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          decide: (catalog, question, options) => {
            const decision = fake.decide(catalog, question, options);
            const extra = options.statements.some((statement) => statement.subject === "ann");
            return extra ? { ...decision, allowed: true } : decision;
          },
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({ step: 0, given: "everything", received: "allowed" });
  });

  it("fails an engine that fails only when handed what the call needs", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          issueGrants: (catalog, subject, options) => {
            if (!options.statements.some((statement) => statement.subject === "ann")) {
              refuse("ERR_AUTHZ_MALFORMED");
            }
            return fake.issueGrants(catalog, subject, options);
          },
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({ step: 2, given: "needed", received: "ERR_AUTHZ_MALFORMED" });
  });

  it("fails an engine that mutates its input", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          decide: (catalog, question, options) => {
            question.place = "/";
            return fake.decide(catalog, question, options);
          },
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({ step: 0, received: "its input changed" });
    expect(scenario.steps[0]).toMatchObject({ question: { place: "/org=acme" } });
  });

  it("fails grants that answer otherwise than the statements", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          readGrants: (catalog, grants, question, options) => ({
            ...fake.readGrants(catalog, grants, question, options),
            covered: true,
          }),
        },
        scenario,
      ),
    );
    expect(failure).toMatchObject({ step: 3, expected: "not-covered", received: "denied" });
  });

  it("fails a read of grants that were never issued", () => {
    const failure = failureOf(() =>
      runScenario(fake, {
        ...scenario,
        steps: [
          {
            step: "read",
            at: MONDAY,
            grants: "nobody",
            question: { permission: "doc:read" },
            expect: "denied",
          },
        ],
      }),
    );
    expect(failure).toMatchObject({ step: 0, received: "none" });
  });
});

describe("genesis steps", () => {
  const owner: Statement = { kind: "allow", subject: "owner", value: "*" };
  const founding: Scenario = {
    id: "fake/founding",
    title: "The owner founds the office, and nobody founds it twice",
    proves: ["A5"],
    catalog: catalogData,
    statements: [{ kind: "allow", subject: "ops", value: "*", expiresAt: MONDAY + 3600 }],
    steps: [
      { step: "genesis", at: MONDAY, statement: owner, expect: "accepted" },
      {
        step: "change",
        at: MONDAY + 60,
        author: "owner",
        change: {
          action: "place",
          statement: { kind: "allow", subject: "bob", value: "doc:read", place: "/org=acme" },
        },
        expect: "accepted",
      },
      {
        step: "genesis",
        at: MONDAY + 120,
        statement: { kind: "allow", subject: "eve", value: "*" },
        expect: "ERR_AUTHZ_CHANGE_REFUSED",
        reasons: ["not-first"],
      },
    ],
  };

  it("hands in the stored permanent managers, and stores the statement accepted", () => {
    const handed: unknown[] = [];
    const engine: Engine = {
      ...fake,
      checkGenesis: (catalog, statement, options) => {
        handed.push(structuredClone(options.managers));
        fake.checkGenesis(catalog, statement, options);
      },
    };
    expect(() => runScenario(engine, founding)).not.toThrow();
    expect(handed).toEqual([[], [owner]]);
  });

  it("fails an engine that accepts a second genesis", () => {
    const failure = failureOf(() => runScenario({ ...fake, checkGenesis: () => {} }, founding));
    expect(failure).toMatchObject({
      id: "fake/founding",
      step: 2,
      expected: "ERR_AUTHZ_CHANGE_REFUSED",
      received: "accepted",
    });
  });

  it("fails an engine that names other reasons", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          checkGenesis: (_catalog, _statement, options) => {
            if (options.managers.length > 0) {
              refuse("ERR_AUTHZ_CHANGE_REFUSED", { reasons: ["not-manager", "not-first"] });
            }
          },
        },
        founding,
      ),
    );
    expect(failure).toMatchObject({
      step: 2,
      expected: { reasons: ["not-first"] },
      received: { reasons: ["not-manager", "not-first"] },
    });
  });
});

describe("runCatalogCase", () => {
  it("checks acceptance and the fingerprint", () => {
    const accepted = {
      id: "fake/catalog",
      title: "",
      catalog: catalogData,
      expect: "accepted",
    } as const;
    expect(() =>
      runCatalogCase(fake, { ...accepted, fingerprint: "fp:doc:read,doc:write,access:manage" }),
    ).not.toThrow();
    expect(
      failureOf(() => runCatalogCase(fake, { ...accepted, fingerprint: "other" })),
    ).toMatchObject({
      expected: { fingerprint: "other" },
    });
    expect(
      failureOf(() => runCatalogCase(fake, { ...accepted, catalog: { permission: "x" } })),
    ).toMatchObject({
      expected: "accepted",
      received: "ERR_AUTHZ_CATALOG_INVALID",
    });
    expect(() =>
      runCatalogCase(fake, { ...accepted, catalog: 42, expect: "ERR_AUTHZ_CATALOG_INVALID" }),
    ).not.toThrow();
  });
});

describe("runPlaceCase", () => {
  it("checks the chain, the range and the refusal", () => {
    const place = {
      id: "fake/place",
      key: "/org=acme/unit=u7",
      expect: "canonical",
      chain: ["/org=acme/unit=u7", "/org=acme", "/"],
      range: { after: "/org=acme/unit=u7/", before: "/org=acme/unit=u70" },
    } as const;
    expect(() => runPlaceCase(fake, place)).not.toThrow();
    expect(
      failureOf(() => runPlaceCase(fake, { ...place, chain: ["/org=acme/unit=u7", "/"] })),
    ).toMatchObject({
      id: "fake/place",
    });
    expect(() =>
      runPlaceCase(fake, { id: "fake/bad", key: "org=acme", expect: "ERR_AUTHZ_MALFORMED" }),
    ).not.toThrow();
    expect(
      failureOf(() =>
        runPlaceCase(fake, { id: "fake/bad", key: "/org=acme", expect: "ERR_AUTHZ_MALFORMED" }),
      ),
    ).toMatchObject({
      expected: { placeChain: "ERR_AUTHZ_MALFORMED" },
    });
  });
});

describe("runGrantsCase", () => {
  it("replaces $ct with the fingerprint before reading", () => {
    expect(() => runGrantsCase(fake, grantsCase)).not.toThrow();
    expect(failureOf(() => runGrantsCase(fake, { ...grantsCase, expect: "denied" }))).toMatchObject(
      {
        expected: "denied",
        received: "allowed",
      },
    );
    expect(() =>
      runGrantsCase(fake, {
        ...grantsCase,
        grants: { v: "1", ct: "other", at: MONDAY, fid: "hand", nt: {} },
        expect: "ERR_AUTHZ_GRANTS_CATALOG",
      }),
    ).not.toThrow();
  });
});

describe("validateEngine", () => {
  it("reports every case and never throws for a wrong answer", () => {
    const opposite: Engine = {
      ...fake,
      decide: (catalog, question, options) => {
        const decision = fake.decide(catalog, question, options);
        return { ...decision, allowed: !decision.allowed };
      },
    };
    const cases = {
      scenarios: [scenario],
      catalogCases: [],
      placeCases: [],
      grantsCases: [grantsCase],
    };
    expect(validateEngine(fake, cases)).toEqual({
      passed: ["fake/office", "fake/grants"],
      failed: [],
    });
    const report = validateEngine(opposite, cases);
    expect(report.passed).toEqual(["fake/grants"]);
    expect(report.failed).toMatchObject([{ id: "fake/office", step: 0 }]);
  });

  it("reports an engine that throws something else than an UnauthError", () => {
    const broken: Engine = {
      ...fake,
      decide: () => {
        throw new TypeError("boom");
      },
    };
    const report = validateEngine(broken, {
      scenarios: [scenario],
      catalogCases: [],
      placeCases: [],
      grantsCases: [],
    });
    expect(report.failed).toMatchObject([{ id: "fake/office", received: "TypeError: boom" }]);
  });
});

describe("scenario data", () => {
  const scenarios = [
    ...decisionScenarios,
    ...decisionDepthScenarios,
    ...decisionExclusionScenarios,
    ...decisionInvalidScenarios,
    ...decisionStructureScenarios,
    ...decisionPlatformScenarios,
    ...decisionWorkspaceScenarios,
    ...grantsScenarios,
    ...grantsBundleScenarios,
    ...roleScenarios,
  ];

  it("names every case once, under its prefix", () => {
    const ids = [...scenarios.map((item) => item.id), ...grantsCases.map((item) => item.id)];
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^(decision|grants|roles)\/[a-z0-9-]+$/);
  });

  it("lets time move forward, but for a clock running behind", () => {
    const backwards: string[] = [];
    for (const item of scenarios) {
      let last = 0;
      for (const [index, step] of item.steps.entries()) {
        if (step.step === "write") continue;
        if (step.step === "read" && step.expect === "ERR_AUTHZ_GRANTS_EARLY") continue;
        if (step.at < last) backwards.push(`${item.id} step ${index}`);
        if (step.step === "ask" && (step.issuedAt ?? step.at) > step.at) {
          backwards.push(`${item.id} step ${index} issued later`);
        }
        last = step.at;
      }
    }
    expect(backwards).toEqual([]);
  });
});

function fakeDecide(
  catalog: Catalog,
  question: Question,
  statements: readonly Statement[],
  at: number,
): boolean {
  const { permission } = question;
  if (permission === "") refuse("ERR_AUTHZ_QUESTION_INVALID");
  if (!catalog.data.permissions.includes(permission)) refuse("ERR_AUTHZ_PERMISSION_UNKNOWN");
  const identifiers = [question.subject, ...(question.groups ?? [])];
  const place = question.place ?? "/";
  const applying = statements.filter(
    (statement) =>
      identifiers.includes(statement.subject) &&
      live(statement, at) &&
      covers(statement.place ?? "/", place),
  );
  return (
    !applying.some((statement) => statement.kind === "deny" && statement.value === permission) &&
    applying.some(
      (statement) =>
        statement.kind === "allow" && (statement.value === permission || statement.value === "*"),
    )
  );
}

function live(statement: Statement, at: number): boolean {
  return statement.expiresAt === undefined || statement.expiresAt > at;
}

function covers(outer: string, inner: string): boolean {
  return outer === "/" || inner === outer || inner.startsWith(`${outer}/`);
}

function seconds(now: (() => number) | undefined): number {
  return Math.floor((now ?? Date.now)() / 1000);
}

function refuse(code: KnownUnauthErrorCode, cause?: unknown): never {
  throw new UnauthError("Refused.", code, { cause });
}

function isFailure(value: unknown): value is ValidationFailure {
  return typeof value === "object" && value !== null && "id" in value && "received" in value;
}

function failureOf(run: () => void): ValidationFailure {
  try {
    run();
  } catch (error) {
    if (error instanceof Error && isFailure(error.cause)) return error.cause;
    throw error;
  }
  throw new Error("expected the run to fail");
}
