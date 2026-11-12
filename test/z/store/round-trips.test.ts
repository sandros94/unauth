import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ask } from "../../../src/z/ask.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import { relatedValues } from "../../../src/z/relate.ts";
import type { Decision, Grants, Statement } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";
import {
  readRepo,
  saveSession,
  saveSessionRows,
  sessionRowsWithRepo,
  sessionWithRepo,
} from "./_sqlite/content.ts";
import type { CountedDatabase, Measured, Trip } from "./_sqlite/database.ts";
import { gather } from "./_sqlite/gather.ts";
import { everything } from "./_sqlite/schema.ts";
import { ACME, API, NOW, PAT_GROUPS, PLACES, TIMES, forge, seed } from "./_sqlite/world.ts";
import { ACCESS, Forbidden, type Write, applyWrite } from "./_sqlite/write.ts";

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

/** Every stored statement about `subject` or one of `groups`, with every stored role. */
function everythingOf(subject: string, groups: readonly string[] = []) {
  const identifiers = new Set([subject, ...groups]);
  const { statements, roles } = everything(db);
  const applying = (statement: Statement) => identifiers.has(statement.subject);
  return { subject, statements: statements.filter(applying), roles };
}

/** The answer of every stored statement about Pat and its groups, as the application knows them. */
function whole(permission: Permission, place: string, at: number = NOW): Decision {
  return ask(forge, everythingOf("pat", PAT_GROUPS), { permission, place }, { now: now(at) });
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
        const carried = summary(could(forge, grants, { permission, place }, { now: now(at) }));
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
    return issueGrants(forge, read, { bases, now: now(at) });
  });
}

describe("a request", () => {
  it("answered from grants carried by the client makes no read for authorization, 1 read in all for the content", () => {
    const cookie: unknown = JSON.parse(JSON.stringify(signIn().result));
    const measured = db.measure(() => {
      const decision = could(forge, cookie, { permission: "repo:write", place: API });
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
      const decision = could(forge, found.grants, { permission: "repo:write", place: API });
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
          const partial = could(forge, measured.result.grants, question, { now: now(at) });
          expect(summary(partial)).toStrictEqual(summary(whole(permission, place, at)));
        }
      }
    }
  });
});

describe("the fresh answer from the statements", () => {
  it("makes 1 read of 6 rows: the live statements of Pat and its groups on the chain, the stored roles with their references", () => {
    const measured = db.measure(() =>
      gather(db, "question", { subject: "pat", at: NOW, chain: [API], under: [] }),
    );
    expect(shape(measured)).toStrictEqual(["read question"]);
    expect(measured.trips[0]!.rows).toBe(6);
    const read = measured.result;
    expect(read.subject).toBe("pat");
    expect(
      read.statements.every(({ subject }) => subject === "pat" || PAT_GROUPS.includes(subject)),
    ).toBe(true);
    expect(
      read.statements
        .map((statement) => statement.place)
        .every((place) => [API, ACME, "/"].includes(place!)),
    ).toBe(true);
    expect(read.roles.map((role) => role.name).toSorted()).toStrictEqual(["lead", "triager"]);
    for (const permission of PERMISSIONS) {
      const answer = ask(forge, read, { permission, place: API }, { now: now(NOW) });
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
          const answer = ask(forge, read, { permission, place }, { now: now(at) });
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
        const answer = ask(forge, read, { permission, place }, { now: now(NOW) });
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
  it("issues grants for every place with 1 read of 12 rows: 10 statements, 2 stored roles", () => {
    const measured = signIn();
    expect(shape(measured)).toStrictEqual(["read sign-in"]);
    expect(measured.trips[0]!.rows).toBe(12);
    expect(disagreements(measured.result)).toStrictEqual([]);
  });

  it("issues grants for one base with 1 read of 8 rows: 6 statements, 2 stored roles", () => {
    const measured = signIn([ACME]);
    expect(shape(measured)).toStrictEqual(["read sign-in"]);
    expect(measured.trips[0]!.rows).toBe(8);
    expect(measured.result.bs).toStrictEqual([ACME]);
    expect(disagreements(measured.result, [ACME])).toStrictEqual([]);
  });

  it("issues grants a month later with 1 read of 10 rows, the two ended statements left out", () => {
    const later = TIMES.at(-1)!;
    const measured = signIn(["/"], later);
    expect(shape(measured)).toStrictEqual(["read sign-in"]);
    expect(measured.trips[0]!.rows).toBe(10);
    expect(disagreements(measured.result, ["/"], later)).toStrictEqual([]);
  });

  it("issues grants of 685 bytes as JSON for the person with access in every organisation, 570 with presets by name", () => {
    expect(JSON.stringify(signIn().result).length).toBe(685);
    const read = gather(db, "sign-in", { subject: "pat", at: NOW, chain: ["/"], under: ["/"] });
    const named = issueGrants(forge, read, { omit: ["presets"], now: now(NOW) });
    expect(JSON.stringify(named).length).toBe(570);
    expect(disagreements(named)).toStrictEqual([]);
  });
});

describe("a write", () => {
  const assignNewcomer: Write = {
    action: "place",
    statement: { kind: "assign", subject: "newcomer", value: "triager", place: API },
  };

  it("at a place makes 1 read and 1 write in one transaction: the author's question, then validation", () => {
    const measured = db.measure(() =>
      applyWrite(db, forge, { subject: "ann", at: NOW }, assignNewcomer),
    );
    expect(shape(measured)).toStrictEqual(["read write.place", "write statements.place"]);
    expectOneTransaction(measured);
    expect(measured.result.roles.map((role) => role.name).toSorted()).toStrictEqual(["triager"]);
    const question = { permission: "issue:write", place: API } as const;
    const answer = ask(forge, everythingOf("newcomer"), question, { now: now(NOW) });
    expect(answer.allowed).toBe(true);
  });

  it("refused by the application's own question makes 1 read and no write, rolled back", () => {
    const measured = db.measure(() =>
      thrown(() => applyWrite(db, forge, { subject: "sam", at: NOW }, assignNewcomer)),
    );
    expect(shape(measured)).toStrictEqual(["read write.place"]);
    expect(measured.ended.map((ended) => ended.outcome)).toStrictEqual(["rollback"]);
    expect(measured.result).toBeInstanceOf(Forbidden);
    expect(whole(ACCESS, API).allowed).toBe(false);
  });

  it("refused by validation makes 1 read and no write, rolled back", () => {
    const ghost: Write = {
      action: "place",
      statement: { kind: "assign", subject: "newcomer", value: "ghost", place: API },
    };
    const measured = db.measure(() =>
      refused(() => applyWrite(db, forge, { subject: "ann", at: NOW }, ghost)),
    );
    expect(shape(measured)).toStrictEqual(["read write.place"]);
    expect(measured.ended.map((ended) => ended.outcome)).toStrictEqual(["rollback"]);
    expect(measured.result).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "ghost", reason: "unknown" },
    });
  });

  it("of a stored role makes 1 read, which returns the role and what it references, and 1 write", () => {
    const edit: Write = {
      action: "define",
      role: { name: "triager", entries: ["writer", "-repo:write"] },
    };
    const measured = db.measure(() => applyWrite(db, forge, { subject: "root", at: NOW }, edit));
    expect(shape(measured)).toStrictEqual(["read write.define", "write roles.define"]);
    expectOneTransaction(measured);
    expect(measured.result.roles.map((role) => role.name)).toStrictEqual(["triager"]);
    expect(everything(db).roles.find((role) => role.name === "triager")?.entries).toStrictEqual([
      "writer",
      "-repo:write",
    ]);
  });

  it("removing a permanent allow of `*` at the root is a removal like any other", () => {
    const removal: Write = {
      action: "remove",
      statement: { kind: "allow", subject: "ops", value: "*", place: "/" },
    };
    const measured = db.measure(() => applyWrite(db, forge, { subject: "root", at: NOW }, removal));
    expect(shape(measured)).toStrictEqual(["read write.remove", "write statements.remove"]);
    expectOneTransaction(measured);
    expect(
      everything(db)
        .statements.filter((s) => s.kind === "allow" && s.value === "*")
        .map((s) => s.subject),
    ).toStrictEqual(["root"]);
  });
});

function expectOneTransaction(measured: Measured<unknown>): void {
  const transactions = new Set(measured.trips.map((trip) => trip.transaction));
  expect(transactions.size).toBe(1);
  expect([...transactions][0]).toBeTypeOf("number");
  expect(measured.ended).toStrictEqual([{ transaction: [...transactions][0], outcome: "commit" }]);
}

function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("Expected a refusal, got an answer.");
}
