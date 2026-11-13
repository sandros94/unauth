import { describe, expect, it } from "vitest";
import { ask } from "../../src/z/ask.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import { issueGrants } from "../../src/z/grants.ts";
import type { Question, Statement, StoredRole } from "../../src/z/types.ts";
import { validateRole, validateStatement } from "../../src/z/validate.ts";
import { refused } from "./_expect.ts";

const NOW = 1794214800;
const now = () => NOW * 1000;
const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";

const catalog = defineCatalog({
  permissions: ["report:list", "report:read", "report:write", "chat:read", "match:join"],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: { viewer: ["report:read"] },
  places: { "/": ["org"], "org": ["area"] },
});
type P = (typeof catalog.data.permissions)[number];

const roles: StoredRole[] = [{ name: "desk", entries: ["viewer", "-report:list"] }];
const needed: Statement[] = [
  { kind: "assign", subject: "team", value: "desk", place: ACME },
  { kind: "allow", subject: "eva", value: "report:write", place: ARCHIVES },
  { kind: "deny", subject: "eva", value: "chat:read", place: ACME },
  { kind: "exclude", subject: "team", value: "report:read", place: ARCHIVES },
];
const read = { permission: "report:read", place: ARCHIVES } as const;

function answer(statements: unknown[], question: Question<P> = read, stored: unknown = roles) {
  return ask(catalog, { subject: "eva", statements, roles: stored } as never, question, { now });
}

describe("a question reads only the statements at the keys of its chain that it looks up (Section 7)", () => {
  const offChain: [string, unknown][] = [
    ["`null`", null],
    ["a number", 42],
    [
      "a statement under another spelling of a key on the chain",
      { kind: "deny", subject: "eva", value: "report:read", place: "/org=acme/" },
    ],
    [
      "a statement under a key in percent-encoded form",
      { kind: "deny", subject: "eva", value: "*", place: "/org=%61cme" },
    ],
    [
      "a malformed value at another place",
      { kind: "allow", subject: "eva", value: "Report:Read", place: "/org=globex" },
    ],
    [
      "a malformed subject at another place",
      { kind: "deny", subject: 7, value: "*", place: "/org=globex" },
    ],
    ["a place that is not a string", { kind: "deny", subject: "eva", value: "*", place: 7 }],
  ];
  const unrelated: [string, unknown][] = [
    [
      "an allow with a malformed subject and a value it does not look up",
      { kind: "allow", subject: 7, value: "match:join", place: ACME },
    ],
    [
      "a deny with an end that is not a time and a value it does not look up",
      { kind: "deny", subject: "eva", value: "match:join", expiresAt: "soon" },
    ],
    [
      "an exclusion with a malformed subject and a value it does not look up",
      { kind: "exclude", subject: "", value: "match:*" },
    ],
  ];

  it.each([...offChain, ...unrelated])("answers as if it were not there: %s", (_, statement) => {
    for (const question of [
      read,
      { permission: "report:write", place: ARCHIVES },
      { permission: "chat:read", place: ACME },
    ] as const) {
      const alone = answer(needed, question);
      expect(answer([statement, ...needed], question)).toStrictEqual(alone);
      expect(answer([...needed, statement], question)).toStrictEqual(alone);
    }
  });

  const related: [string, unknown, string][] = [
    [
      "a deny it looks up with a subject that is not a string",
      { kind: "deny", subject: 7, value: "report:read" },
      "statement",
    ],
    [
      "an allow it looks up with an end that is not a time",
      { kind: "allow", subject: "eva", value: "report:*", place: ACME, expiresAt: "soon" },
      "time",
    ],
    [
      "an exclusion it looks up with an empty subject",
      { kind: "exclude", subject: "", value: "*", place: ARCHIVES },
      "statement",
    ],
    [
      "an assignment on the chain naming no role",
      { kind: "assign", subject: "eva", value: "Viewer" },
      "statement",
    ],
    [
      "an assignment on the chain with no subject",
      { kind: "assign", value: "anything", place: ACME },
      "statement",
    ],
  ];

  it.each(related)("is refused for what it reads: %s", (_, statement, what) => {
    expect(refused(() => answer([...needed, statement]))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what },
    });
  });

  it.each([...offChain, ...unrelated, ...related])(
    "is refused whole by `validateStatement` and `issueGrants`: %s",
    (...[, statement]) => {
      expect(validateStatement(catalog, statement, { roles, now }).length).toBeGreaterThan(0);
      expect(
        refused(() =>
          issueGrants(
            catalog,
            { subject: "eva", statements: [...needed, statement] as Statement[], roles },
            { now },
          ),
        ).code,
      ).toBe("ERR_AUTHZ_MALFORMED");
    },
  );

  it("refuses statements that are not a list", () => {
    expect(
      refused(() => ask(catalog, { subject: "eva", statements: {} } as never, read)),
    ).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "statement" },
    });
  });
});

describe("stored roles, read by name (Section 7.1)", () => {
  const twice: StoredRole[] = [...roles, { name: "desk", entries: ["report:write"] }];

  it("refuses two of one name when a question reads that name", () => {
    expect(refused(() => answer(needed, read, twice))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "desk", reason: "duplicate" },
    });
  });

  it("does not refuse them for a question that reads no assignment of that name", () => {
    const own = needed.filter(({ kind }) => kind !== "assign");
    expect(answer(own, read, twice)).toStrictEqual(answer(own, read, roles));
    expect(answer(needed, { permission: "report:read", place: "/org=globex" }, twice).allowed).toBe(
      false,
    );
  });

  it("are refused twice of one name by `issueGrants` and `validateRole`, always", () => {
    const duplicate = {
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "desk", reason: "duplicate" },
    };
    const own = needed.filter(({ kind }) => kind !== "assign");
    expect(
      refused(() =>
        issueGrants(catalog, { subject: "eva", statements: own, roles: twice }, { now }),
      ),
    ).toMatchObject(duplicate);
    expect(
      refused(() => validateRole(catalog, { name: "lead", entries: ["viewer"] }, { roles: twice })),
    ).toMatchObject(duplicate);
    const statement = { kind: "allow", subject: "eva", value: "report:read" };
    expect(refused(() => validateStatement(catalog, statement, { roles: twice }))).toMatchObject(
      duplicate,
    );
  });

  it("skip a stored role whose shape is broken while no question reads its name", () => {
    const broken = [...roles, { name: "ghost", entries: 7 }, 7, null];
    expect(answer(needed, read, broken)).toStrictEqual(answer(needed, read, roles));
    const assigned = [...needed, { kind: "assign", subject: "eva", value: "ghost" }];
    expect(refused(() => answer(assigned, read, broken))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "roles" },
    });
  });
});

describe("the size of what a question does not read (Section 1, Section 7)", () => {
  const SIZE = 20000;
  const offChain: Statement[] = Array.from({ length: SIZE }, (_, index) => ({
    kind: index % 2 ? "deny" : "assign",
    subject: `s${index}`,
    value: index % 2 ? "*" : "desk",
    place: `/org=o${index}/area=a${index}`,
  }));
  const statements = [...offChain, ...needed];

  it("answers as without them, in a time that does not check them", () => {
    const questions: Question<P>[] = [
      read,
      { permission: "report:write", place: ARCHIVES },
      { permission: "chat:read", place: ACME },
    ];
    for (const question of questions)
      expect(answer(statements, question)).toStrictEqual(answer(needed, question));
    const rounds = 50;
    const start = performance.now();
    for (let round = 0; round < rounds; round++)
      answer(statements, questions[round % questions.length]);
    const perQuestion = (performance.now() - start) / rounds;
    expect(perQuestion).toBeLessThan(4);
  });
});
