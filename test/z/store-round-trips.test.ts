import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { UnauthError } from "../../src/error.ts";
import { type Change, checkChange } from "../../src/z/change.ts";
import { decide } from "../../src/z/decide.ts";
import { issueGrants, readGrants } from "../../src/z/grants.ts";
import { relatedValues } from "../../src/z/relate.ts";
import type { Decision, Grants, Statement } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";
import {
  applyChange,
  applyGenesis,
  checkRead,
  readForChange,
  writeChange,
} from "./_sqlite/change.ts";
import {
  readRepo,
  saveSession,
  saveSessionRows,
  sessionRowsWithRepo,
  sessionWithRepo,
} from "./_sqlite/content.ts";
import { CountedDatabase, type Measured, type Trip } from "./_sqlite/database.ts";
import { gather } from "./_sqlite/gather.ts";
import { createSchema, everything } from "./_sqlite/schema.ts";
import { ACME, API, NOW, PAT_GROUPS, PLACES, TIMES, forge, seed } from "./_sqlite/world.ts";

type Permission = (typeof forge.data.permissions)[number];
const PERMISSIONS: readonly Permission[] = forge.data.permissions;
const now = (at: number) => () => at * 1000;
const API_REPO = { org: "acme", name: "api" };

let db: CountedDatabase;
beforeEach(() => {
  db = seed();
});
afterEach(() => db.close());

function summary(decision: Decision) {
  return {
    allowed: decision.allowed,
    covered: decision.covered,
    by: decision.by === undefined ? "nothing" : decision.by.kind === "deny" ? "deny" : "gives",
  };
}

function shape(measured: Measured<unknown>) {
  return measured.trips.map(({ kind, label }) => `${kind} ${label}`);
}

function covers(outer: string, inner: string): boolean {
  return outer === "/" || inner === outer || inner.startsWith(`${outer}/`);
}

/** The answer of every stored statement, the groups as the application knows them. */
function whole(permission: Permission, place: string, at: number = NOW): Decision {
  const { statements, roles } = everything(db);
  return decide(
    forge,
    { subject: "pat", groups: PAT_GROUPS, permission, place },
    { statements, roles, now: now(at) },
  );
}

/** Every disagreement between grants and every stored statement, over every place, permission and time. */
function disagreements(
  grants: unknown,
  bases: readonly string[] = ["/"],
  from: number = NOW,
): string[] {
  const found: string[] = [];
  for (const at of TIMES.filter((time) => time >= from)) {
    for (const place of PLACES) {
      for (const permission of PERMISSIONS) {
        const carried = summary(readGrants(forge, grants, { permission, place }, { now: now(at) }));
        const expected = bases.some((base) => covers(base, place))
          ? summary(whole(permission, place, at))
          : { allowed: false, covered: false, by: "nothing" };
        if (JSON.stringify(carried) !== JSON.stringify(expected)) {
          found.push(`${at} ${place} ${permission}: ${JSON.stringify(carried)}`);
        }
      }
    }
  }
  return found;
}

function signIn(bases: readonly string[] = ["/"], at: number = NOW): Measured<Grants> {
  return db.measure(() => {
    const read = gather(db, "sign-in", { subject: "pat", at, chain: bases, under: bases });
    return issueGrants(forge, "pat", {
      groups: read.groups,
      statements: read.statements,
      roles: read.roles,
      bases,
      now: now(at),
    });
  });
}

describe("a request", () => {
  it("answered from grants carried by the client makes no read for authorization, 1 read in all for the content", () => {
    const cookie: unknown = JSON.parse(JSON.stringify(signIn().result));
    const measured = db.measure(() => {
      const decision = readGrants(forge, cookie, { permission: "repo:write", place: API });
      return { decision, repo: decision.allowed ? readRepo(db, "acme", "api") : undefined };
    });
    expect(shape(measured)).toStrictEqual(["read repo"]);
    expect(measured.result.repo).toStrictEqual({ org: "acme", name: "api", visibility: "private" });
    expect(summary(measured.result.decision)).toStrictEqual(summary(whole("repo:write", API)));
    expect(disagreements(cookie)).toStrictEqual([]);
  });

  it("answered from grants kept in a server-side session makes 1 read, which also fetches the content", () => {
    saveSession(db, "s1", "pat", signIn().result);
    const measured = db.measure(() => {
      const found = sessionWithRepo(db, "s1", API_REPO);
      const decision = readGrants(forge, found.grants, { permission: "repo:write", place: API });
      return { ...found, decision };
    });
    expect(shape(measured)).toStrictEqual(["read session+repo"]);
    expect(measured.result.repo?.visibility).toBe("private");
    expect(summary(measured.result.decision)).toStrictEqual(summary(whole("repo:write", API)));
    expect(disagreements(measured.result.grants)).toStrictEqual([]);
  });

  it("answered from a session kept one entry per row makes 1 read of only the related entries, fewer bytes, the same answer", () => {
    const grants = signIn().result;
    saveSessionRows(db, "s2", "pat", grants);
    const rows = db.measure(() => sessionRowsWithRepo(db, "s2", API_REPO));
    expect(rows.result.grants).toStrictEqual(grants);
    for (const permission of PERMISSIONS) {
      const related = relatedValues(forge, permission);
      const measured = db.measure(() => sessionRowsWithRepo(db, "s2", API_REPO, related));
      expect(shape(measured)).toStrictEqual(["read session-related+repo"]);
      const [trip] = measured.trips as [Trip];
      expect(trip.bytes).toBeLessThan(rows.trips[0]!.bytes);
      expect(measured.result.repo?.visibility).toBe("private");
      for (const place of PLACES) {
        for (const at of TIMES) {
          const question = { permission, place };
          const partial = readGrants(forge, measured.result.grants, question, { now: now(at) });
          expect(summary(partial)).toStrictEqual(summary(whole(permission, place, at)));
        }
      }
    }
  });
});

describe("the fresh answer from the statements", () => {
  it("makes 1 read of 10 rows: the groups, the live statements on the chain, the stored roles with their references", () => {
    const measured = db.measure(() =>
      gather(db, "question", { subject: "pat", at: NOW, chain: [API], under: [] }),
    );
    expect(shape(measured)).toStrictEqual(["read question"]);
    expect(measured.trips[0]!.rows).toBe(10);
    const read = measured.result;
    expect(read.groups.toSorted()).toStrictEqual(PAT_GROUPS);
    expect(
      read.statements
        .map((statement) => statement.place)
        .every((place) => [API, ACME, "/"].includes(place!)),
    ).toBe(true);
    expect(read.roles.map((role) => role.name).toSorted()).toStrictEqual(["lead", "triager"]);
    for (const permission of PERMISSIONS) {
      const question = { subject: "pat", groups: read.groups, permission, place: API };
      const answer = decide(forge, question, { ...read, now: now(NOW) });
      expect(summary(answer)).toStrictEqual(summary(whole(permission, API)));
    }
  });

  it("at every place and time answers as every stored statement does, 1 read each", () => {
    for (const place of PLACES) {
      for (const at of TIMES) {
        const measured = db.measure(() =>
          gather(db, "question", { subject: "pat", at, chain: [place], under: [] }),
        );
        expect(measured.trips).toHaveLength(1);
        const read = measured.result;
        for (const permission of PERMISSIONS) {
          const question = { subject: "pat", groups: read.groups, permission, place };
          const answer = decide(forge, question, { ...read, now: now(at) });
          expect(summary(answer)).toStrictEqual(summary(whole(permission, place, at)));
        }
      }
    }
  });

  it("narrowed to the related values makes 1 read with fewer rows and the same answer for every permission", () => {
    let fewer = 0;
    for (const place of PLACES) {
      const full = db.measure(() =>
        gather(db, "question", { subject: "pat", at: NOW, chain: [place], under: [] }),
      );
      for (const permission of PERMISSIONS) {
        const related = relatedValues(forge, permission);
        const measured = db.measure(() =>
          gather(db, "question", { subject: "pat", at: NOW, chain: [place], under: [], related }),
        );
        expect(measured.trips).toHaveLength(1);
        expect(measured.trips[0]!.rows).toBeLessThanOrEqual(full.trips[0]!.rows);
        if (measured.trips[0]!.rows < full.trips[0]!.rows) fewer++;
        const read = measured.result;
        const question = { subject: "pat", groups: read.groups, permission, place };
        const answer = decide(forge, question, { ...read, now: now(NOW) });
        expect(summary(answer)).toStrictEqual(summary(whole(permission, place)));
      }
    }
    expect(fewer).toBeGreaterThan(0);
    const full = db.measure(() =>
      gather(db, "question", { subject: "pat", at: NOW, chain: [API], under: [] }),
    );
    const billing = db.measure(() =>
      gather(db, "question", {
        subject: "pat",
        at: NOW,
        chain: [API],
        under: [],
        related: relatedValues(forge, "billing:read"),
      }),
    );
    expect(billing.trips[0]!.rows).toBeLessThan(full.trips[0]!.rows);
  });
});

describe("sign-in", () => {
  it("issues grants for every place with 1 read of 16 rows: 4 groups, 10 statements, 2 stored roles", () => {
    const measured = signIn();
    expect(shape(measured)).toStrictEqual(["read sign-in"]);
    expect(measured.trips[0]!.rows).toBe(16);
    expect(disagreements(measured.result)).toStrictEqual([]);
  });

  it("issues grants for one base with 1 read of 12 rows: 4 groups, 6 statements, 2 stored roles", () => {
    const measured = signIn([ACME]);
    expect(shape(measured)).toStrictEqual(["read sign-in"]);
    expect(measured.trips[0]!.rows).toBe(12);
    expect(measured.result.bs).toStrictEqual([ACME]);
    expect(disagreements(measured.result, [ACME])).toStrictEqual([]);
  });

  it("issues grants a month later with 1 read of 14 rows, the two ended statements left out", () => {
    const later = TIMES.at(-1)!;
    const measured = signIn(["/"], later);
    expect(shape(measured)).toStrictEqual(["read sign-in"]);
    expect(measured.trips[0]!.rows).toBe(14);
    expect(disagreements(measured.result, ["/"], later)).toStrictEqual([]);
  });

  it("issues grants of 597 bytes as JSON for the person with access in every organisation", () => {
    expect(JSON.stringify(signIn().result).length).toBe(597);
  });
});

describe("a change", () => {
  const assignNewcomer: Change = {
    action: "place",
    statement: { kind: "assign", subject: "newcomer", value: "triager", place: API },
  };

  it("at a place makes 1 read and 1 write in one transaction", () => {
    const measured = db.measure(() =>
      applyChange(db, forge, { subject: "ann", at: NOW }, assignNewcomer),
    );
    expect(shape(measured)).toStrictEqual(["read change.place", "write statements.place"]);
    expectOneTransaction(measured);
    const { statements, roles } = everything(db);
    const before = statements.filter((statement) => statement.subject !== "newcomer");
    expect(() =>
      checkChange(forge, assignNewcomer, {
        author: "ann",
        statements: before,
        roles,
        now: now(NOW),
      }),
    ).not.toThrow();
    const answer = decide(
      forge,
      { subject: "newcomer", permission: "issue:write", place: API },
      { statements, roles, now: now(NOW) },
    );
    expect(answer.allowed).toBe(true);
  });

  it("removing a root allow of * makes 1 read, which returns the root's permanent allows of *, and 1 write", () => {
    const removal: Change = {
      action: "remove",
      statement: { kind: "allow", subject: "ops", value: "*", place: "/" },
    };
    const measured = db.measure(() =>
      applyChange(db, forge, { subject: "root", at: NOW }, removal),
    );
    expect(shape(measured)).toStrictEqual(["read change.remove", "write statements.remove"]);
    expectOneTransaction(measured);
    expect(measured.result.managers.map((statement) => statement.subject).toSorted()).toStrictEqual(
      ["ops", "root"],
    );
    expect(
      everything(db)
        .statements.filter(isRootManagement)
        .map((s) => s.subject),
    ).toStrictEqual(["root"]);
  });

  it("genesis makes 1 read and 1 write in one transaction, and a second genesis is refused without a write", () => {
    const empty = CountedDatabase.create();
    createSchema(empty);
    const first = empty.measure(() =>
      applyGenesis(empty, forge, { kind: "allow", subject: "root", value: "*" }, NOW),
    );
    expect(shape(first)).toStrictEqual(["read genesis", "write statements.place"]);
    expectOneTransaction(first);
    const second = empty.measure(() =>
      refused(() => applyGenesis(empty, forge, { kind: "allow", subject: "eve", value: "*" }, NOW)),
    );
    expect(shape(second)).toStrictEqual(["read genesis"]);
    expect(second.ended.map((ended) => ended.outcome)).toStrictEqual(["rollback"]);
    expect(reasonsOf(second.result)).toStrictEqual(["not-first"]);
    expect(everything(empty).statements).toStrictEqual([
      { kind: "allow", subject: "root", value: "*", place: "/" },
    ]);
    empty.close();
  });
});

describe("two removals of the last two root managers", () => {
  const leaving = (subject: string): Change => ({
    action: "remove",
    statement: { kind: "allow", subject, value: "*", place: "/" },
  });

  it("cannot both be written when each reads, checks and writes in one transaction", () => {
    const other = db.connect();
    db.transaction(() => {
      const read = readForChange(db, { subject: "root", at: NOW }, leaving("root"));
      checkRead(forge, { subject: "root", at: NOW }, leaving("root"), read);
      expect(() => other.transaction(() => undefined)).toThrow(/locked/);
      writeChange(db, leaving("root"));
    });
    const error = refused(() =>
      applyChange(other, forge, { subject: "ops", at: NOW }, leaving("ops")),
    );
    expect(reasonsOf(error)).toStrictEqual(["last-manager"]);
    expect(
      everything(db)
        .statements.filter(isRootManagement)
        .map((s) => s.subject),
    ).toStrictEqual(["ops"]);
    other.close();
  });

  it("is the hazard avoided: both pass the check when the reads happen before either write, and the root is left with none", () => {
    const root = { subject: "root", at: NOW };
    const ops = { subject: "ops", at: NOW };
    const readByRoot = readForChange(db, root, leaving("root"));
    const readByOps = readForChange(db, ops, leaving("ops"));
    expect(() => checkRead(forge, root, leaving("root"), readByRoot)).not.toThrow();
    expect(() => checkRead(forge, ops, leaving("ops"), readByOps)).not.toThrow();
    writeChange(db, leaving("root"));
    writeChange(db, leaving("ops"));
    expect(everything(db).statements.filter(isRootManagement)).toStrictEqual([]);
  });
});

function expectOneTransaction(measured: Measured<unknown>): void {
  const transactions = new Set(measured.trips.map((trip) => trip.transaction));
  expect(transactions.size).toBe(1);
  expect([...transactions][0]).toBeTypeOf("number");
  expect(measured.ended).toStrictEqual([{ transaction: [...transactions][0], outcome: "commit" }]);
}

function reasonsOf(error: UnauthError): unknown {
  expect(error.code).toBe("ERR_AUTHZ_CHANGE_REFUSED");
  const cause = error.cause as { reasons: unknown };
  return cause.reasons;
}

function isRootManagement(statement: Statement): boolean {
  return (
    statement.kind === "allow" &&
    statement.value === "*" &&
    statement.place === "/" &&
    statement.expiresAt === undefined
  );
}
