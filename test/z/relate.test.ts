import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { ask } from "../../src/z/ask.ts";
import { relatedValues } from "../../src/z/relate.ts";
import type { Statement } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "billing:read",
    "chat:send",
    "access:manage",
  ],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: {
    viewer: ["report:read"],
    clerk: ["report:*", "-report:write"],
    cashier: ["billing:read"],
    owner: ["*"],
  },
});

const NOW = 1_794_214_800;
const now = (): number => NOW * 1000;
const ACME = "/org=acme";

describe("the values that relate to a permission", () => {
  it("lists, for the top of a chain of implications, only its own spellings as what gives", () => {
    const related = relatedValues(catalog, "report:write");
    expect(related.allow).toEqual(["*", "*:write", "report:*", "report:write"]);
    expect(related.deny).toEqual([
      "*",
      "*:list",
      "*:read",
      "*:write",
      "report:*",
      "report:list",
      "report:read",
      "report:write",
    ]);
    expect(related.exclude).toEqual(related.deny);
    expect(related.presets).toEqual(["owner"]);
  });

  it("lists, for the bottom of the chain, everything that implies it as what gives", () => {
    const related = relatedValues(catalog, "report:list");
    expect(related.allow).toEqual([
      "*",
      "*:list",
      "*:read",
      "*:write",
      "report:*",
      "report:list",
      "report:read",
      "report:write",
    ]);
    expect(related.deny).toEqual(["*", "*:list", "report:*", "report:list"]);
    expect(related.exclude).toEqual(related.allow);
    expect(related.presets).toEqual(["clerk", "owner", "viewer"]);
  });

  it("names no preset that cannot give the permission", () => {
    expect(relatedValues(catalog, "billing:read").presets).toEqual(["cashier", "owner"]);
    expect(relatedValues(catalog, "chat:send").presets).toEqual(["owner"]);
  });

  it("refuses what a question refuses", () => {
    expect(refused(() => relatedValues(catalog, "report:*" as never)).code).toBe(
      "ERR_AUTHZ_QUESTION_INVALID",
    );
    expect(refused(() => relatedValues(catalog, "report:print" as never)).code).toBe(
      "ERR_AUTHZ_PERMISSION_UNKNOWN",
    );
    expect(refused(() => relatedValues(catalog, "Report:read" as never)).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
  });

  it("keeps every answer when a store returns only the rows it names", () => {
    const stored: Statement[] = [
      { kind: "assign", subject: "ana", value: "clerk", place: ACME },
      { kind: "allow", subject: "ana", value: "billing:read", place: ACME },
      { kind: "deny", subject: "staff", value: "*:list", place: ACME },
      { kind: "allow", subject: "bo", value: "report:*", place: ACME },
      { kind: "exclude", subject: "bo", value: "report:read", place: `${ACME}/area=archives` },
      { kind: "assign", subject: "cy", value: "viewer" },
      { kind: "deny", subject: "cy", value: "chat:send" },
      { kind: "assign", subject: "dee", value: "desk", place: ACME },
    ];
    const roles = [{ name: "desk", entries: ["report:write"] }];
    const presetNames = new Set(Object.keys(catalog.data.presets ?? {}));
    const people = [
      { subject: "ana", groups: ["staff"] },
      { subject: "ana", groups: [] },
      { subject: "bo", groups: [] },
      { subject: "cy", groups: [] },
      { subject: "dee", groups: [] },
    ];
    for (const permission of catalog.data.permissions) {
      const related = relatedValues(catalog, permission);
      const narrowed = stored.filter((statement) => {
        if (statement.kind === "assign") {
          return related.presets.includes(statement.value) || !presetNames.has(statement.value);
        }
        return related[statement.kind].includes(statement.value);
      });
      for (const who of people) {
        for (const place of [ACME, `${ACME}/area=archives`]) {
          const identifiers = new Set([who.subject, ...who.groups]);
          const applying = (statement: Statement) => identifiers.has(statement.subject);
          const read = (statements: Statement[]) => ({
            subject: who.subject,
            statements: statements.filter(applying),
            roles,
          });
          const question = { permission, place };
          const whole = ask(catalog, read(stored), question, { now });
          const part = ask(catalog, read(narrowed), question, { now });
          expect(part.allowed, `${who.subject} ${permission} ${place}`).toBe(whole.allowed);
        }
      }
    }
  });
});
