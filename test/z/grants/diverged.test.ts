import { describe, expect, it } from "vitest";
import { ask } from "../../../src/z/ask.ts";
import { type CatalogData, defineCatalog } from "../../../src/z/catalog.ts";
import { could, diverged, issueGrants } from "../../../src/z/grants.ts";
import type { Statement } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const ACME = "/org=acme";
const now = () => MONDAY * 1000;

const data = {
  permissions: ["post:read", "post:write", "post:publish", "audit:delete", "access:manage"],
  implies: { "post:publish": ["post:read"] },
  presets: {
    viewer: ["*:read"],
    editor: ["viewer", "post:write"],
    admin: ["*"],
  },
  places: { "/": ["org"] },
} satisfies CatalogData;
const catalog = defineCatalog(data);

const ed: Statement[] = [
  { kind: "assign", subject: "ed", value: "editor", place: ACME },
  { kind: "deny", subject: "ed", value: "audit:delete" },
  { kind: "allow", subject: "ed", value: "post:*" },
  { kind: "allow", subject: "ed", value: "invoice:*" },
];
const issued = issueGrants(catalog, { subject: "ed", statements: ed }, { now });
const named = issueGrants(catalog, { subject: "ed", statements: ed }, { omit: ["presets"], now });

describe("diverged", () => {
  it("is undefined for grants issued under the very catalog", () => {
    expect(diverged(catalog, issued, { now })).toBeUndefined();
    expect(diverged(catalog, named, { now })).toBeUndefined();
    expect(diverged(catalog, [issued, named], { now })).toBeUndefined();
  });

  it("names a copy whose preset now has other entries, and only the presets segment", () => {
    const later = defineCatalog({ ...data, presets: { ...data.presets, viewer: ["post:read"] } });
    expect(diverged(later, issued, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["viewer"],
    });
  });

  it("names a copy whose preset is gone", () => {
    const later = defineCatalog({ ...data, presets: { viewer: data.presets.viewer } });
    expect(diverged(later, issued, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["editor"],
    });
  });

  it("names no copy for a preset changed that the grants do not hold", () => {
    const later = defineCatalog({
      ...data,
      presets: { ...data.presets, admin: ["*", "-audit:delete"] },
    });
    expect(diverged(later, issued, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: [],
    });
  });

  it("compares a copy with the preset as sets, whatever order and repeats the catalog writes", () => {
    const later = defineCatalog({
      ...data,
      presets: { ...data.presets, editor: ["post:write", "viewer", "post:write"], admin: [] },
    });
    expect(diverged(later, issued, { now })?.presets).toStrictEqual([]);
  });

  it("names the permissions the grants name that the catalog no longer declares, and only the first segment", () => {
    const later = defineCatalog({
      ...data,
      permissions: data.permissions.filter((permission) => permission !== "audit:delete"),
    });
    const told = { segments: ["permissions"], permissions: ["audit:delete"], presets: [] };
    expect(diverged(later, issued, { now })).toStrictEqual(told);
    expect(diverged(later, named, { now })).toStrictEqual(told);
  });

  it("lists both segments, in their order, and a permission named only inside a copy", () => {
    const later = defineCatalog({
      ...data,
      permissions: [...data.permissions.filter((p) => p !== "post:write"), "post:pin"],
      presets: { viewer: ["*:read"], editor: ["viewer", "post:pin"] },
    });
    expect(issued.pm).toStrictEqual(["audit:delete", "post:write"]);
    expect(diverged(later, issued, { now })).toStrictEqual({
      segments: ["permissions", "presets"],
      permissions: ["post:write"],
      presets: ["editor"],
    });
  });

  it("tells of several sets together, undefined only when every set matches", () => {
    const later = defineCatalog({ ...data, presets: { ...data.presets, viewer: ["post:read"] } });
    const fresh = issueGrants(later, { subject: "ed", statements: ed }, { now });
    expect(diverged(later, [fresh, issued], { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["viewer"],
    });
    expect(diverged(later, [fresh, fresh], { now })).toBeUndefined();
  });

  it("tells what every set holds once one set differs, a set issued under the very catalog included", () => {
    const later = defineCatalog({ ...data, presets: { ...data.presets, viewer: ["post:read"] } });
    const invoice = { kind: "allow", subject: "ed", value: "invoice:read" } satisfies Statement;
    const fresh = issueGrants(later, { subject: "ed", statements: [...ed, invoice] }, { now });
    expect(diverged(later, [fresh], { now })).toBeUndefined();
    expect(diverged(later, [fresh, issued], { now })).toStrictEqual({
      segments: ["presets"],
      permissions: ["invoice:read"],
      presets: ["viewer"],
    });
  });

  it("tells of grants by name under other presets, naming no copy", () => {
    const later = defineCatalog({ ...data, presets: { viewer: ["post:read"] } });
    expect(diverged(later, named, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: [],
    });
  });

  it("reads nothing but `v`, `ct` and `at` when both segments match", () => {
    expect(diverged(catalog, { ...issued, nt: [], pm: 7, ps: [], bs: 1 }, { now })).toBeUndefined();
  });

  it("reads `pm`, `ps` and `sr` whole when a segment differs, and refuses them malformed", () => {
    const later = defineCatalog({ ...data, presets: { ...data.presets, viewer: ["post:read"] } });
    for (const broken of [
      { ...issued, pm: [...issued.pm!, "post:write"] },
      { ...issued, ps: { ...issued.ps, viewer: ["*:*"] } },
      { ...issued, sr: { Desk: [] } },
      { ...named, nt: [] },
    ]) {
      expect(refused(() => diverged(later, broken, { now }))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "grants" },
      });
    }
    expect(diverged(later, { ...issued, sr: { viewer: [] } }, { now })?.presets).toStrictEqual([
      "viewer",
    ]);
    expect(diverged(later, { ...issued, nt: [], bs: 7, pl: 1 }, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["viewer"],
    });
  });

  it("refuses what a read refuses of the head of each set", () => {
    expect(refused(() => diverged(catalog, { ...issued, ct: "x" }, { now })).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
    expect(refused(() => diverged(catalog, { ...issued, v: "2" }, { now })).code).toBe(
      "ERR_AUTHZ_GRANTS_FORMAT",
    );
    expect(refused(() => diverged(catalog, issued, { now: () => (MONDAY - 1) * 1000 })).code).toBe(
      "ERR_AUTHZ_GRANTS_EARLY",
    );
    expect(refused(() => diverged(catalog, [issued, null], { now })).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
  });
});

describe("the answer of `could`", () => {
  const later = defineCatalog({ ...data, presets: { ...data.presets, viewer: ["post:read"] } });
  const told = { segments: ["presets"], permissions: [], presets: ["viewer"] };

  it("carries what has diverged whatever the answer, not covered included", () => {
    const scoped = issueGrants(catalog, { subject: "ed", statements: ed }, { bases: [ACME], now });
    expect(could(later, issued, { permission: "post:read", place: ACME }, { now })).toStrictEqual({
      allowed: true,
      covered: true,
      by: { kind: "allow", value: "post:*", place: "/" },
      diverged: told,
    });
    expect(could(later, issued, { permission: "audit:delete" }, { now })).toMatchObject({
      allowed: false,
      diverged: told,
    });
    expect(
      could(later, scoped, { permission: "post:read", place: "/org=globex" }, { now }),
    ).toStrictEqual({
      allowed: false,
      covered: false,
      diverged: told,
    });
    expect(could(later, [], { permission: "post:read" }, { now })).toStrictEqual({
      allowed: false,
      covered: false,
    });
  });

  it("carries nothing of it under the catalog of issue, and `ask` never does", () => {
    expect(could(catalog, issued, { permission: "post:read" }, { now })).not.toHaveProperty(
      "diverged",
    );
    expect(
      ask(later, { subject: "ed", statements: ed }, { permission: "post:read" }, { now }),
    ).not.toHaveProperty("diverged");
  });
});

describe("a stored role held under a name a later catalog declares as a preset", () => {
  const before = {
    permissions: ["report:read", "report:write", "chat:read"],
    presets: { viewer: ["*:read"], helper: ["chat:read"] },
  } satisfies CatalogData;
  const first = defineCatalog(before);
  const added = defineCatalog({
    ...before,
    presets: { ...before.presets, editor: ["report:read"] },
  });
  const write = { permission: "report:write" } as const;
  const sam = (value: string, roles: { name: string; entries: string[] }[]) => ({
    subject: "sam",
    statements: [{ kind: "assign", subject: "sam", value }] satisfies Statement[],
    roles,
  });
  const editor = { name: "editor", entries: ["report:*"] };

  it.each([
    ["with copies", undefined],
    ["by name", ["presets"] as const],
  ])("is named, and the read still answers from the stored role, %s", (_, omit) => {
    const grants = issueGrants(first, sam("editor", [editor]), { omit, now });
    expect(diverged(added, grants, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["editor"],
    });
    expect(could(added, grants, write, { now })).toStrictEqual({
      allowed: true,
      covered: true,
      by: { kind: "assign", value: "editor", place: "/" },
      diverged: { segments: ["presets"], permissions: [], presets: ["editor"] },
    });
    expect(ask(added, sam("editor", [editor]), write, { now }).allowed).toBe(false);
  });

  it("is named when the grants hold it only because an assigned role references it", () => {
    const lead = { name: "lead", entries: ["editor", "chat:read"] };
    const grants = issueGrants(first, sam("lead", [lead, editor]), { now });
    expect(Object.keys(grants.sr ?? {})).toStrictEqual(["editor", "lead"]);
    expect(diverged(added, grants, { now })?.presets).toStrictEqual(["editor"]);
    expect(could(added, grants, write, { now }).by).toMatchObject({ value: "lead" });
  });

  it("is not named when its definition holds the preset's very entries", () => {
    const same = { name: "editor", entries: ["report:read", "report:read"] };
    const grants = issueGrants(first, sam("editor", [same]), { now });
    expect(diverged(added, grants, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: [],
    });
  });

  it("is not named for a preset removed whose name no stored role of the grants had", () => {
    const removed = defineCatalog({ ...before, presets: { viewer: before.presets.viewer } });
    const desk = { name: "desk", entries: ["viewer", "report:write"] };
    const grants = issueGrants(first, sam("desk", [desk]), { now });
    expect(diverged(removed, grants, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: [],
    });
  });
});
