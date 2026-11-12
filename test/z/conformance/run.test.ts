import { describe, expect, it } from "vitest";

import { type KnownUnauthErrorCode, UnauthError } from "../../../src/error.ts";
import type { Catalog, CatalogData } from "../../../src/z/catalog.ts";
import type { Statement, StoredRole } from "../../../src/z/types.ts";
import { cases } from "../../../src/z/conformance/cases.ts";
import type { Engine, Issue, Question } from "../../../src/z/conformance/engine.ts";
import {
  runCatalogCase,
  runConformance,
  runGrantsCase,
  runPlaceCase,
  runRoleCase,
  runScenario,
  runStatementCase,
} from "../../../src/z/conformance/run.ts";
import type {
  Cases,
  ConformanceFailure,
  ExpectedIssue,
  GrantsCase,
  RoleCase,
  Scenario,
  StatementCase,
} from "../../../src/z/conformance/types.ts";

const MONDAY = 1794214800;

const catalogData: CatalogData = {
  permissions: ["doc:read", "doc:write", "access:manage"],
};

const scenario: Scenario = {
  id: "fake/office",
  title: "An office where the owner allows Bob to read and later stops",
  proves: ["G1"],
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
      step: "write",
      save: [{ kind: "allow", subject: "bob", value: "doc:read", place: "/org=acme" }],
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

const issued = new Map<string, Statement[]>([
  ["hand", [{ kind: "allow", subject: "ann", value: "doc:read", place: "/org=acme" }]],
]);

const fake: Engine = {
  defineCatalog: (data) => {
    if (!Array.isArray(data.permissions)) refuse("ERR_AUTHZ_CATALOG_INVALID");
    return { data, fingerprint: `fp:${data.permissions.join(",")}` };
  },
  ask: (catalog, read, question, options) => {
    const allowed = fakeDecide(catalog, question, read.statements, seconds(options?.now));
    return { allowed, covered: true };
  },
  issueGrants: (catalog, read, options) => {
    const at = seconds(options?.now);
    const fid = `g${issued.size}`;
    issued.set(
      fid,
      read.statements.filter((statement) => live(statement, at)),
    );
    const grants: Record<string, unknown> = { v: "1", ct: catalog.fingerprint, at, nt: {}, fid };
    if (options?.bases !== undefined) grants.bs = [...options.bases];
    return grants;
  },
  could: (catalog, grants, question, options) => {
    const at = seconds(options?.now);
    const sets: unknown[] = Array.isArray(grants) ? grants : [grants];
    const answers: boolean[] = [];
    for (const set of sets) {
      if (!isRecord(set)) refuse("ERR_AUTHZ_MALFORMED");
      if (set.ct !== catalog.fingerprint) refuse("ERR_AUTHZ_GRANTS_CATALOG");
      if (typeof set.at !== "number" || at < set.at) refuse("ERR_AUTHZ_GRANTS_EARLY");
      const place = question.place ?? "/";
      const bases = Array.isArray(set.bs) ? (set.bs as string[]) : undefined;
      if (bases !== undefined && !bases.some((base) => covers(base, place))) continue;
      const kept = typeof set.fid === "string" ? issued.get(set.fid) : undefined;
      if (kept === undefined) refuse("ERR_AUTHZ_MALFORMED");
      answers.push(fakeDecide(catalog, question, kept, at));
    }
    if (answers.length === 0) return { allowed: false, covered: false };
    return { allowed: answers.every(Boolean), covered: true };
  },
  validateStatement: (catalog, value, options) => {
    refuseTwoOfOneName(options?.roles);
    if (!isRecord(value)) return [issue("ERR_AUTHZ_MALFORMED")];
    const issues: Issue[] = [];
    if (!["allow", "assign", "deny", "exclude"].includes(String(value.kind))) {
      issues.push(issue("ERR_AUTHZ_MALFORMED", "kind"));
    }
    if (typeof value.subject !== "string" || value.subject === "") {
      issues.push(issue("ERR_AUTHZ_MALFORMED", "subject"));
    }
    if (value.kind === "assign") {
      if (!(options?.roles ?? []).some((role) => role.name === value.value)) {
        issues.push(issue("ERR_AUTHZ_ROLE_INVALID", "value"));
      }
    } else if (!catalog.data.permissions.includes(String(value.value))) {
      issues.push(issue("ERR_AUTHZ_PERMISSION_UNKNOWN", "value"));
    }
    if (typeof value.expiresAt === "number" && value.expiresAt <= seconds(options?.now)) {
      issues.push(issue("ERR_AUTHZ_STATEMENT_ENDED", "expiresAt"));
    }
    return issues;
  },
  validateRole: (catalog, value, options) => {
    refuseTwoOfOneName(options?.roles);
    if (!isRecord(value) || !Array.isArray(value.entries)) return [issue("ERR_AUTHZ_MALFORMED")];
    const names = new Set((options?.roles ?? []).map((stored) => stored.name));
    const issues: Issue[] = [];
    for (const [index, entry] of (value.entries as string[]).entries()) {
      if (entry.includes(":")) {
        if (!catalog.data.permissions.includes(entry)) {
          issues.push(issue("ERR_AUTHZ_PERMISSION_UNKNOWN", "entries", index));
        }
      } else if (entry === value.name || !names.has(entry)) {
        issues.push(issue("ERR_AUTHZ_ROLE_INVALID", "entries", index));
      }
    }
    return issues;
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
          ask: (catalog, read, question, options) => {
            const decision = fake.ask(catalog, read, question, options);
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
          ask: (catalog, read, question, options) => {
            if (question.permission === "") refuse("ERR_AUTHZ_MALFORMED");
            return fake.ask(catalog, read, question, options);
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

  it("fails an engine whose answer changes when handed more statements", () => {
    const failure = failureOf(() =>
      runScenario(
        {
          ...fake,
          ask: (catalog, read, question, options) => {
            const decision = fake.ask(catalog, read, question, options);
            const extra = read.statements.some((statement) => statement.place === "/org=globex");
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
          issueGrants: (catalog, read, options) => {
            if (!read.statements.some((statement) => statement.place === "/org=globex")) {
              refuse("ERR_AUTHZ_MALFORMED");
            }
            return fake.issueGrants(catalog, read, options);
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
          ask: (catalog, read, question, options) => {
            question.place = "/";
            return fake.ask(catalog, read, question, options);
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
          could: (catalog, grants, question, options) => ({
            ...fake.could(catalog, grants, question, options),
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

describe("what the runner hands over", () => {
  const ACME = "/org=acme";
  const selecting: Scenario = {
    id: "fake/selection",
    title: "Ann and her staff group, with statements about others and elsewhere",
    proves: [],
    catalog: {
      permissions: ["doc:read", "doc:write", "access:manage"],
      implies: { "doc:write": ["doc:read"] },
      presets: { writer: ["doc:write"], admin: ["access:manage"] },
    },
    roles: [{ name: "custom", entries: ["access:manage"] }],
    statements: [
      { kind: "allow", subject: "ann", value: "doc:read", place: ACME },
      { kind: "allow", subject: "ann", value: "doc:read", place: "/org=globex" },
      {
        kind: "allow",
        subject: "ann",
        value: "doc:read",
        place: `${ACME}/unit=u1`,
        expiresAt: MONDAY,
      },
      { kind: "deny", subject: "staff", value: "doc:write", place: ACME },
      { kind: "allow", subject: "staff", value: "access:manage" },
      { kind: "exclude", subject: "staff", value: "doc:read", place: `${ACME}/unit=u2` },
      { kind: "exclude", subject: "staff", value: "doc:write", place: `${ACME}/unit=u1` },
      { kind: "assign", subject: "staff", value: "writer", place: ACME },
      { kind: "assign", subject: "staff", value: "admin", place: ACME },
      { kind: "assign", subject: "ann", value: "custom" },
      { kind: "allow", subject: "bob", value: "doc:read", place: ACME },
    ],
    steps: [
      {
        step: "ask",
        at: MONDAY,
        question: {
          subject: "ann",
          groups: ["staff"],
          permission: "doc:read",
          place: `${ACME}/unit=u1`,
        },
        expect: "allowed",
        issuedAt: MONDAY,
        bases: [`${ACME}/unit=u1`],
      },
    ],
  };

  it("hands the statements about the subject and its groups, then only those the question needs", () => {
    const asked: Statement[][] = [];
    const issuing: Statement[][] = [];
    const subjects: string[] = [];
    const engine: Engine = {
      ...fake,
      ask: (catalog, read, question, options) => {
        asked.push(structuredClone([...read.statements]));
        subjects.push(read.subject);
        return fake.ask(catalog, read, question, options);
      },
      issueGrants: (catalog, read, options) => {
        issuing.push(structuredClone([...read.statements]));
        subjects.push(read.subject);
        return fake.issueGrants(catalog, read, options);
      },
    };
    expect(() => runScenario(engine, selecting)).not.toThrow();
    const stored = selecting.statements ?? [];
    const applying = stored.filter((statement) => statement.subject !== "bob");
    expect(subjects).toEqual(["ann", "ann", "ann", "ann"]);
    expect(asked).toEqual([applying, [stored[0], stored[6], stored[7], stored[9]]]);
    expect(issuing).toEqual([
      applying,
      [stored[0], stored[3], stored[4], stored[6], stored[7], stored[8], stored[9]],
    ]);
  });

  it("hands a `hand` step exactly the statements it lists, to ask and to issue", () => {
    const listed: Statement[] = [
      { kind: "allow", subject: "design", value: "doc:read", place: ACME },
      { kind: "deny", subject: "contractors", value: "doc:write" },
    ];
    const handed: unknown[] = [];
    const engine: Engine = {
      ...fake,
      ask: (catalog, read, question, options) => {
        handed.push(structuredClone(read));
        return fake.ask(catalog, read, question, options);
      },
      issueGrants: (catalog, read, options) => {
        handed.push(structuredClone(read));
        return fake.issueGrants(catalog, read, options);
      },
    };
    const run = (answer: "allowed" | "denied") =>
      runScenario(engine, {
        ...selecting,
        steps: [
          {
            step: "hand",
            at: MONDAY,
            subject: "ann",
            statements: listed,
            question: { permission: "doc:read", place: ACME },
            expect: answer,
            issuedAt: MONDAY,
          },
        ],
      });
    expect(() => run("allowed")).not.toThrow();
    const read = { subject: "ann", statements: listed, roles: selecting.roles };
    expect(handed).toEqual([read, read]);
    expect(failureOf(() => run("denied"))).toMatchObject({
      id: "fake/selection",
      step: 0,
      expected: "denied",
      received: "allowed",
    });
    expect(failureOf(() => run("denied"))).not.toHaveProperty("given");
  });
});

describe("stored roles", () => {
  const analyst: StoredRole = { name: "analyst", entries: ["doc:read"] };
  const twice: StoredRole[] = [analyst, { name: "analyst", entries: ["doc:write"] }];
  const importing: Scenario = {
    id: "fake/import",
    title: "Two roles of one name arrive, and one is removed",
    proves: [],
    catalog: catalogData,
    roles: twice,
    statements: [{ kind: "assign", subject: "kim", value: "analyst" }],
    steps: [
      {
        step: "ask",
        at: MONDAY,
        question: { subject: "kim", permission: "doc:read" },
        expect: "denied",
        issuedAt: MONDAY,
      },
      { step: "write", roles: [analyst] },
      { step: "issue", at: MONDAY + 60, as: "kim", subject: "kim" },
    ],
  };

  it("hands every stored role as written, two of one name included, and a write replaces them", () => {
    const handed: unknown[] = [];
    const engine: Engine = {
      ...fake,
      ask: (catalog, read, question, options) => {
        handed.push(structuredClone(read.roles));
        return fake.ask(catalog, read, question, options);
      },
      issueGrants: (catalog, read, options) => {
        handed.push(structuredClone(read.roles));
        return fake.issueGrants(catalog, read, options);
      },
    };
    expect(() => runScenario(engine, importing)).not.toThrow();
    expect(handed).toEqual([twice, twice, twice, twice, [analyst], [analyst]]);
    expect(importing.roles).toEqual(twice);
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

describe("runStatementCase", () => {
  const statementCase: StatementCase = {
    id: "fake/statement",
    title: "",
    catalog: catalogData,
    at: MONDAY,
    statement: { kind: "allow", subject: "ann", value: "doc:read", expiresAt: MONDAY + 1 },
    expect: [],
  };
  const faults: ExpectedIssue[] = [
    { code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["expiresAt"] },
    { code: "ERR_AUTHZ_MALFORMED", path: ["kind"] },
    { code: "ERR_AUTHZ_PERMISSION_UNKNOWN", path: ["value"] },
    { code: "ERR_AUTHZ_MALFORMED", path: ["subject"] },
  ];
  const faulty: StatementCase = {
    ...statementCase,
    statement: { kind: "grant", value: "doc:delete", expiresAt: MONDAY },
    expect: faults,
  };

  it("validates at the time of the case, with the stored roles of the case", () => {
    const handed: unknown[] = [];
    const engine: Engine = {
      ...fake,
      validateStatement: (catalog, value, options) => {
        handed.push({ roles: options?.roles, now: options?.now?.() });
        return fake.validateStatement(catalog, value, options);
      },
    };
    const roles: StoredRole[] = [{ name: "analyst", entries: ["doc:read"] }];
    expect(() => runStatementCase(engine, statementCase)).not.toThrow();
    expect(() =>
      runStatementCase(engine, {
        ...statementCase,
        roles,
        statement: { kind: "assign", subject: "ann", value: "analyst" },
      }),
    ).not.toThrow();
    expect(handed).toEqual([
      { roles: undefined, now: MONDAY * 1000 },
      { roles, now: MONDAY * 1000 },
    ]);
  });

  it("compares the issues on code and path, in any order", () => {
    expect(() => runStatementCase(fake, faulty)).not.toThrow();
    expect(() => runStatementCase(fake, { ...faulty, expect: faults.toReversed() })).not.toThrow();
  });

  it("fails an issue missing, an issue too many, and another path", () => {
    expect(
      failureOf(() => runStatementCase(fake, { ...faulty, expect: faults.slice(1) })),
    ).toMatchObject({ id: "fake/statement" });
    expect(
      failureOf(() => runStatementCase(fake, { ...statementCase, at: MONDAY + 1 })),
    ).toMatchObject({
      expected: [],
      received: [{ code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["expiresAt"] }],
    });
    expect(
      failureOf(() =>
        runStatementCase(fake, {
          ...faulty,
          expect: [...faults.slice(1), { code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["end"] }],
        }),
      ),
    ).toMatchObject({ id: "fake/statement" });
  });

  it("expects a throw only for what is handed beside the value", () => {
    const twice: StoredRole[] = [
      { name: "analyst", entries: ["doc:read"] },
      { name: "analyst", entries: ["doc:write"] },
    ];
    expect(() =>
      runStatementCase(fake, { ...statementCase, roles: twice, expect: "ERR_AUTHZ_ROLE_INVALID" }),
    ).not.toThrow();
    expect(
      failureOf(() => runStatementCase(fake, { ...statementCase, roles: twice })),
    ).toMatchObject({ expected: [], received: "ERR_AUTHZ_ROLE_INVALID" });
    expect(
      failureOf(() =>
        runStatementCase(fake, { ...statementCase, expect: "ERR_AUTHZ_ROLE_INVALID" }),
      ),
    ).toMatchObject({ expected: "ERR_AUTHZ_ROLE_INVALID", received: [] });
  });

  it("fails what is not a list of issues", () => {
    const engine = (result: unknown): Engine => ({
      ...fake,
      validateStatement: () => result as Issue[],
    });
    expect(failureOf(() => runStatementCase(engine(undefined), statementCase))).toMatchObject({
      received: "no list of issues",
    });
    expect(
      failureOf(() =>
        runStatementCase(engine([{ code: "ERR_AUTHZ_MALFORMED", path: ["kind"] }]), faulty),
      ),
    ).toMatchObject({ received: "an issue without a code, a path or a message" });
  });

  it("fails an engine that changes the statement it validates", () => {
    const engine: Engine = {
      ...fake,
      validateStatement: (_catalog, value) => {
        if (isRecord(value)) value.subject = "eve";
        return [];
      },
    };
    expect(failureOf(() => runStatementCase(engine, statementCase))).toMatchObject({
      received: "its input changed",
    });
  });
});

describe("runRoleCase", () => {
  const roleCase: RoleCase = {
    id: "fake/role",
    title: "",
    catalog: catalogData,
    role: { name: "senior", entries: ["analyst", "doc:write"] },
    roles: [{ name: "analyst", entries: ["doc:read"] }],
    expect: [],
  };

  it("validates with the stored roles of the case, and compares the issues", () => {
    expect(() => runRoleCase(fake, roleCase)).not.toThrow();
    expect(() =>
      runRoleCase(fake, {
        ...roleCase,
        roles: undefined,
        expect: [{ code: "ERR_AUTHZ_ROLE_INVALID", path: ["entries", 0] }],
      }),
    ).not.toThrow();
    expect(
      failureOf(() =>
        runRoleCase(fake, { ...roleCase, role: { name: "loop", entries: ["loop", "doc:delete"] } }),
      ),
    ).toMatchObject({
      id: "fake/role",
      expected: [],
      received: [
        { code: "ERR_AUTHZ_PERMISSION_UNKNOWN", path: ["entries", 1] },
        { code: "ERR_AUTHZ_ROLE_INVALID", path: ["entries", 0] },
      ],
    });
  });
});

describe("runConformance", () => {
  const none: Omit<Cases, "scenarios" | "grantsCases"> = {
    catalogCases: [],
    placeCases: [],
    statementCases: [],
    roleCases: [],
  };

  it("reports every case and never throws for a wrong answer", () => {
    const opposite: Engine = {
      ...fake,
      ask: (catalog, read, question, options) => {
        const decision = fake.ask(catalog, read, question, options);
        return { ...decision, allowed: !decision.allowed };
      },
    };
    const some: Cases = { ...none, scenarios: [scenario], grantsCases: [grantsCase] };
    expect(runConformance(fake, some)).toEqual({
      passed: ["fake/office", "fake/grants"],
      failed: [],
    });
    const report = runConformance(opposite, some);
    expect(report.passed).toEqual(["fake/grants"]);
    expect(report.failed).toMatchObject([{ id: "fake/office", step: 0 }]);
  });

  it("runs statement and role cases", () => {
    const report = runConformance(
      { ...fake, validateStatement: () => [], validateRole: () => [] },
      {
        ...none,
        scenarios: [],
        grantsCases: [],
        statementCases: [
          {
            id: "fake/ended",
            title: "",
            catalog: catalogData,
            at: MONDAY,
            statement: { kind: "deny", subject: "ann", value: "doc:read", expiresAt: MONDAY },
            expect: [{ code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["expiresAt"] }],
          },
        ],
        roleCases: [
          {
            id: "fake/role",
            title: "",
            catalog: catalogData,
            role: { name: "x", entries: ["doc:read"] },
            expect: [],
          },
        ],
      },
    );
    expect(report).toEqual({
      passed: ["fake/role"],
      failed: [
        {
          id: "fake/ended",
          expected: [{ code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["expiresAt"] }],
          received: [],
        },
      ],
    });
  });

  it("reports an engine that throws something else than an UnauthError", () => {
    const broken: Engine = {
      ...fake,
      ask: () => {
        throw new TypeError("boom");
      },
    };
    const report = runConformance(broken, { ...none, scenarios: [scenario], grantsCases: [] });
    expect(report.failed).toMatchObject([{ id: "fake/office", received: "TypeError: boom" }]);
  });
});

describe("the cases themselves", () => {
  const ids = [
    ...cases.scenarios.map((item) => item.id),
    ...cases.catalogCases.map((item) => item.id),
    ...cases.placeCases.map((item) => item.id),
    ...cases.grantsCases.map((item) => item.id),
    ...cases.statementCases.map((item) => item.id),
    ...cases.roleCases.map((item) => item.id),
  ];

  it("names every case once, under its prefix", () => {
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(
        /^(decision|grants|roles|appendix|catalog|place|statement|role)\/[a-z0-9-]+$/,
      );
    }
  });

  it("rebuilds every scenario of the model's Appendix A", () => {
    const appendix = cases.scenarios
      .map((item) => item.id)
      .filter((id) => id.startsWith("appendix/"));
    for (const part of ["a1", "a2", "a3", "a4", "a5", "a6", "a7"]) {
      expect(appendix.some((id) => id.startsWith(`appendix/${part}-`))).toBe(true);
    }
  });

  it("declares no catalog member and no role member the model no longer defines", () => {
    const catalogs = [
      ...cases.scenarios.map((item) => item.catalog),
      ...cases.grantsCases.map((item) => item.catalog),
      ...cases.statementCases.map((item) => item.catalog),
      ...cases.roleCases.map((item) => item.catalog),
    ];
    for (const catalog of catalogs) {
      expect(Object.keys(catalog).every((key) => MEMBERS.has(key))).toBe(true);
    }
    const roles = [
      ...cases.scenarios.flatMap((item) => [
        ...(item.roles ?? []),
        ...item.steps.flatMap((step) => (step.step === "write" ? (step.roles ?? []) : [])),
      ]),
      ...cases.statementCases.flatMap((item) => item.roles ?? []),
      ...cases.roleCases.flatMap((item) => item.roles ?? []),
    ];
    for (const role of roles) expect(Object.keys(role).toSorted()).toEqual(["entries", "name"]);
  });

  it("expects issues only at the members the model names", () => {
    const paths = (expected: StatementCase["expect"]) =>
      typeof expected === "string" ? [] : expected.map((found) => found.path);
    for (const item of cases.statementCases) {
      for (const path of paths(item.expect)) {
        expect(path.length === 0 || STATEMENT_MEMBERS.has(String(path[0]))).toBe(true);
        expect(path.length).toBeLessThanOrEqual(1);
      }
    }
    for (const item of cases.roleCases) {
      for (const path of paths(item.expect)) {
        const member = path.length === 0 || ["name", "entries"].includes(String(path[0]));
        const entry = path.length < 2 || (path[0] === "entries" && typeof path[1] === "number");
        expect([member, entry, path.length <= 2]).toEqual([true, true, true]);
      }
    }
  });

  it("lets time move forward, but for a clock running behind", () => {
    const backwards: string[] = [];
    for (const item of cases.scenarios) {
      let last = 0;
      for (const [index, step] of item.steps.entries()) {
        if (step.step === "write") continue;
        if (step.step === "read" && step.expect === "ERR_AUTHZ_GRANTS_EARLY") continue;
        if (step.at < last) backwards.push(`${item.id} step ${index}`);
        if ((step.step === "ask" || step.step === "hand") && (step.issuedAt ?? step.at) > step.at) {
          backwards.push(`${item.id} step ${index} issued later`);
        }
        last = step.at;
      }
    }
    expect(backwards).toEqual([]);
  });
});

const MEMBERS = new Set(["permissions", "implies", "presets", "places"]);
const STATEMENT_MEMBERS = new Set(["kind", "subject", "value", "place", "expiresAt"]);

function fakeDecide(
  catalog: Catalog,
  question: Question,
  statements: readonly Statement[],
  at: number,
): boolean {
  const { permission } = question;
  if (permission === "") refuse("ERR_AUTHZ_QUESTION_INVALID");
  if (!catalog.data.permissions.includes(permission)) refuse("ERR_AUTHZ_PERMISSION_UNKNOWN");
  const place = question.place ?? "/";
  const applying = statements.filter(
    (statement) => live(statement, at) && covers(statement.place ?? "/", place),
  );
  return (
    !applying.some((statement) => statement.kind === "deny" && statement.value === permission) &&
    applying.some(
      (statement) =>
        statement.kind === "allow" && (statement.value === permission || statement.value === "*"),
    )
  );
}

function refuseTwoOfOneName(roles: readonly StoredRole[] | undefined): void {
  const names = (roles ?? []).map((role) => role.name);
  if (new Set(names).size !== names.length) refuse("ERR_AUTHZ_ROLE_INVALID");
}

function issue(code: KnownUnauthErrorCode, ...path: (string | number)[]): Issue {
  return { code, path, message: "Refused.", cause: {} };
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFailure(value: unknown): value is ConformanceFailure {
  return typeof value === "object" && value !== null && "id" in value && "received" in value;
}

function failureOf(run: () => void): ConformanceFailure {
  try {
    run();
  } catch (error) {
    if (error instanceof Error && isFailure(error.cause)) return error.cause;
    throw error;
  }
  throw new Error("expected the run to fail");
}
