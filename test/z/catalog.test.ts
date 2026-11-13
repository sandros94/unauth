import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import {
  assertPattern,
  assertQuestionPermission,
  blocking,
  down,
  expand,
  implied,
  implying,
  removed,
  spellings,
  wanted,
} from "../../src/z/_internal/permissions.ts";
import { sha256 } from "../../src/z/_internal/sha256.ts";
import { assertTime, clockSeconds, isLive } from "../../src/z/_internal/time.ts";
import { type CatalogData, defineCatalog } from "../../src/z/catalog.ts";
import { resolveRole } from "../../src/z/roles.ts";
import { refused } from "./_expect.ts";

async function webSegment(canonical: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return btoa(String.fromCharCode(...new Uint8Array(digest).subarray(0, 8)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function webFingerprint(declares: string, presets = "{}"): Promise<string> {
  return `${await webSegment(declares)}.${await webSegment(presets)}`;
}

const sorted = (set: ReadonlySet<string>) => [...set].toSorted();

describe("defineCatalog fingerprint", () => {
  it("is two segments of 11 characters, pinned for a catalog with only permissions", async () => {
    const catalog = defineCatalog({ permissions: ["report:write", "report:read"] });
    expect(catalog.fingerprint).toMatch(/^[A-Za-z0-9_-]{11}\.[A-Za-z0-9_-]{11}$/);
    expect(catalog.fingerprint).toBe("tqH3DB6_4qw.RBNvo1WzZ4o");
    expect(catalog.fingerprint).toBe(
      await webFingerprint('{"permissions":["report:read","report:write"]}'),
    );
  });

  it("hashes permissions, implications and places apart from presets, pinned with every member", async () => {
    const catalog = defineCatalog({
      permissions: ["report:read", "report:write", "access:manage", "user:invite"],
      implies: { "report:write": ["report:read"] },
      presets: { viewer: ["report:read"], owner: ["*"], admin: ["owner", "-user:invite"] },
      places: { "/": ["org"], "org": ["unit", "project"], "*": ["folder"] },
    });
    const declares =
      '{"implies":{"report:write":["report:read"]},' +
      '"permissions":["access:manage","report:read","report:write","user:invite"],' +
      '"places":{"*":["folder"],"/":["org"],"org":["project","unit"]}}';
    const presets =
      '{"presets":{"admin":["-user:invite","owner"],"owner":["*"],"viewer":["report:read"]}}';
    expect(catalog.fingerprint).toBe("85IyG_KLKEo.uG7QYL9EEG8");
    expect(catalog.fingerprint).toBe(await webFingerprint(declares, presets));
  });

  it("changes only the first segment for a permission, an implication or a place, only the second for a preset", () => {
    const base = { permissions: ["a:x", "a:y"], presets: { r: ["a:x"] } } as const;
    const [first, second] = defineCatalog(base).fingerprint.split(".");
    const segments = (data: CatalogData) => defineCatalog(data).fingerprint.split(".");
    expect(segments({ ...base, permissions: ["a:x", "a:y", "a:z"] })).toStrictEqual([
      expect.not.stringMatching(first!),
      second,
    ]);
    expect(segments({ ...base, implies: { "a:y": ["a:x"] } })[1]).toBe(second);
    expect(segments({ ...base, places: false })[1]).toBe(second);
    expect(segments({ ...base, presets: { r: ["a:y"] } })).toStrictEqual([
      first,
      expect.not.stringMatching(second!),
    ]);
  });

  it("ignores order and duplicates, and drops members that declare nothing", async () => {
    const a = defineCatalog({
      permissions: ["b:x", "a:x", "a:y"],
      implies: { "a:y": ["a:x", "b:x", "a:x"], "b:x": [] },
      presets: { r: ["a:x", "b:x", "a:x"], q: ["r", "-a:y"] },
      places: { "org": ["unit", "unit"], "/": ["org"], "unit": [] },
    });
    const b = defineCatalog({
      places: { "/": ["org"], "org": ["unit"] },
      presets: { q: ["-a:y", "r"], r: ["b:x", "a:x"] },
      implies: { "a:y": ["b:x", "a:x"] },
      permissions: ["a:y", "a:x", "b:x"],
    });
    expect(a.fingerprint).toBe(b.fingerprint);
    expect(a.fingerprint).toBe(
      await webFingerprint(
        '{"implies":{"a:y":["a:x","b:x"]},"permissions":["a:x","a:y","b:x"],' +
          '"places":{"/":["org"],"org":["unit"]}}',
        '{"presets":{"q":["-a:y","r"],"r":["a:x","b:x"]}}',
      ),
    );
  });

  it("keeps `places: false` and a preset with no entries, which declare something", async () => {
    const none = defineCatalog({ permissions: ["a:x"], places: false });
    expect(none.fingerprint).toBe(await webFingerprint('{"permissions":["a:x"],"places":false}'));
    expect(none.fingerprint).not.toBe(defineCatalog({ permissions: ["a:x"] }).fingerprint);
    const guest = defineCatalog({ permissions: ["a:x"], presets: { guest: [] } });
    expect(guest.fingerprint).toBe(
      await webFingerprint('{"permissions":["a:x"]}', '{"presets":{"guest":[]}}'),
    );
    expect(guest.fingerprint.split(".")[1]).not.toBe("RBNvo1WzZ4o");
    expect(resolveRole(guest, "guest")).toEqual([]);
  });

  it("gives the empty object's segment to a catalog that declares nothing in a segment", () => {
    expect(defineCatalog({ permissions: [] }).fingerprint).toBe("RBNvo1WzZ4o.RBNvo1WzZ4o");
  });

  it("differs when the catalog declares something else", () => {
    const a = defineCatalog({ permissions: ["a:x", "a:y"] });
    const b = defineCatalog({ permissions: ["a:x", "a:y"], implies: { "a:y": ["a:x"] } });
    const c = defineCatalog({ permissions: ["a:x", "a:y"], presets: { r: ["a:x"] } });
    expect(new Set([a.fingerprint, b.fingerprint, c.fingerprint]).size).toBe(3);
  });

  it("computes SHA-256 synchronously as Web Crypto does", async () => {
    for (const length of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
      const data = Uint8Array.from({ length }, (_, index) => (index * 31 + 7) & 255);
      const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
      expect(sha256(data)).toEqual(expected);
    }
  });
});

describe("defineCatalog result", () => {
  it("is a frozen copy that later mutation of the input does not reach", () => {
    const permissions = ["a:x"];
    const catalog = defineCatalog({ permissions });
    permissions.push("a:y");
    expect(catalog.data.permissions).toEqual(["a:x"]);
    expect(Object.isFrozen(catalog)).toBe(true);
    expect(Object.isFrozen(catalog.data)).toBe(true);
    expect(Object.isFrozen(catalog.data.permissions)).toBe(true);
  });

  it("accepts names that are also members of Object.prototype", () => {
    const catalog = defineCatalog({
      permissions: ["constructor:read", "prototype:read"],
      presets: { constructor: ["*:read"], prototype: ["constructor"] },
      places: { "/": ["constructor"] },
    });
    expect(resolveRole(catalog, "prototype")).toEqual(["constructor:read", "prototype:read"]);
    expect(refused(() => resolveRole(catalog, "toString"))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
    });
    expect(refused(() => resolveRole(catalog, "hasOwnProperty"))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
    });
  });

  it("refuses a hand-built catalog whose fingerprint does not match its data", () => {
    const real = defineCatalog({ permissions: ["a:x"], presets: { r: ["a:x"] } });
    expect(resolveRole({ data: real.data, fingerprint: real.fingerprint }, "r")).toEqual(["a:x"]);
    expect(
      refused(() => resolveRole({ data: real.data, fingerprint: "x".repeat(23) }, "r")),
    ).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      status: 500,
      cause: { reason: "fingerprint" },
    });
    const forged = { data: { permissions: ["a:x", "a:x"] }, fingerprint: real.fingerprint };
    expect(refused(() => compiledOf(forged))).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      cause: { reason: "duplicate" },
    });
  });
});

describe("defineCatalog refusals", () => {
  const refuse = (data: unknown): unknown => {
    const error = refused(() => defineCatalog(data as CatalogData));
    expect(error).toMatchObject({ code: "ERR_AUTHZ_CATALOG_INVALID", status: 500 });
    return (error.cause as { reason?: unknown } | undefined)?.reason;
  };

  it("refuses input that is not catalog data", () => {
    for (const data of [null, [], "x", 1, new Date(0), new Map()])
      expect(refuse(data)).toBe("shape");
    expect(refuse({ permissions: ["a:x"], extra: true })).toBe("shape");
    expect(refuse({ permissions: "a:x" })).toBe("shape");
    expect(refuse({ permissions: ["a:x", 1] })).toBe("shape");
    expect(refuse({ permissions: ["a:x"], implies: [] })).toBe("shape");
    expect(refuse({ permissions: ["a:x"], presets: { r: "a:x" } })).toBe("shape");
    expect(refuse({ permissions: ["a:x"], places: true })).toBe("shape");
    expect(refuse(JSON.parse('{"permissions":["a:x"],"__proto__":{"manager":"a:x"}}'))).toBe(
      "shape",
    );
    expect(refuse({ permissions: ["a:x"], presets: Object.create({ r: ["a:x"] }) })).toBe("shape");
  });

  it("guards keys named __proto__ taken from data", () => {
    expect(refuse(JSON.parse('{"permissions":["a:x"],"presets":{"__proto__":["a:x"]}}'))).toBe(
      "token",
    );
    expect(refuse(JSON.parse('{"permissions":["a:x"],"implies":{"__proto__":["a:x"]}}'))).toBe(
      "implication",
    );
    expect(refuse(JSON.parse('{"permissions":["a:x"],"places":{"__proto__":["org"]}}'))).toBe(
      "token",
    );
    expect(Object.prototype).not.toHaveProperty("r");
  });

  it("refuses a permission declared twice or not written as two tokens", () => {
    expect(refuse({ permissions: ["a:x", "a:x"] })).toBe("duplicate");
    for (const permission of ["Report:read", "report", "report:*", "*:read", "*", "*:*", "a:b:c"]) {
      expect(refuse({ permissions: [permission] })).toBe("token");
    }
    expect(refuse({ permissions: [`a:${"x".repeat(33)}`] })).toBe("token");
    expect(defineCatalog({ permissions: [`a:${"x".repeat(32)}`, "a-1_b:c"] })).toBeTruthy();
  });

  it("refuses implications that are not between declared concrete permissions, or loop", () => {
    expect(refuse({ permissions: ["a:x"], implies: { "a:x": ["a:y"] } })).toBe("implication");
    expect(refuse({ permissions: ["a:x"], implies: { "a:y": ["a:x"] } })).toBe("implication");
    expect(refuse({ permissions: ["a:x", "a:y"], implies: { "a:*": ["a:x"] } })).toBe(
      "implication",
    );
    expect(refuse({ permissions: ["a:x", "a:y"], implies: { "a:y": ["*"] } })).toBe("implication");
    expect(refuse({ permissions: ["a:x"], implies: { "a:x": ["a:x"] } })).toBe("cycle");
    expect(
      refuse({
        permissions: ["a:x", "a:y", "a:z"],
        implies: { "a:x": ["a:y"], "a:y": ["a:z"], "a:z": ["a:x"] },
      }),
    ).toBe("cycle");
  });

  it("refuses `manager` and `assigner` as any member the model does not define", () => {
    const base = { permissions: ["a:x", "u:invite"], presets: { r: ["a:x"] } };
    for (const [member, value] of [
      ["manager", "a:x"],
      ["assigner", { r: "u:invite" }],
      ["extra", true],
    ] as const) {
      const data: unknown = { ...base, [member]: value };
      expect(refused(() => defineCatalog(data as CatalogData))).toMatchObject({
        code: "ERR_AUTHZ_CATALOG_INVALID",
        cause: { reason: "shape", at: member },
      });
    }
  });

  it("refuses a preset that does not resolve", () => {
    const permissions = ["a:x", "a:y"];
    expect(refuse({ permissions, presets: { Viewer: ["a:x"] } })).toBe("token");
    expect(refuse({ permissions, presets: { r: ["a:z"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["-a:z"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["b:*"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["*:z"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["*:*"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["--a:x"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["Owner"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["ghost"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["-ghost"] } })).toBe("preset");
    expect(refuse({ permissions, presets: { r: ["r"] } })).toBe("cycle");
    expect(refuse({ permissions, presets: { r: ["q"], q: ["-r"] } })).toBe("cycle");
    expect(refuse({ permissions, presets: { r: ["a:x", "q"], q: ["s"], s: ["r"] } })).toBe("cycle");
  });

  it("refuses places that declare no level or put levels under a level that sits nowhere", () => {
    const permissions = ["a:x"];
    expect(refuse({ permissions, places: {} })).toBe("places");
    expect(refuse({ permissions, places: { "/": [] } })).toBe("places");
    expect(refuse({ permissions, places: { "/": ["Org"] } })).toBe("token");
    expect(refuse({ permissions, places: { "Org": ["unit"], "/": ["org"] } })).toBe("token");
    expect(refuse({ permissions, places: { "/": ["org"], "unit": ["team"] } })).toBe("places");
    expect(refuse({ permissions, places: { "/": ["org"], "team": ["team"] } })).toBe("places");
    expect(refuse({ permissions, places: { "/": ["org"], "a": ["b"], "b": ["a"] } })).toBe(
      "places",
    );
    expect(defineCatalog({ permissions, places: { "/": ["org"], "org": ["org"] } })).toBeTruthy();
    expect(
      defineCatalog({ permissions, places: { "*": ["folder"], "folder": ["file"] } }),
    ).toBeTruthy();
    expect(defineCatalog({ permissions, places: { "/": ["org"], "team": [] } })).toBeTruthy();
  });
});

describe("compiled permissions", () => {
  const catalog = compiledOf(
    defineCatalog({
      permissions: ["report:list", "report:read", "report:write", "billing:read", "event:manage"],
      implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
    }),
  );

  it("expands patterns to declared permissions only", () => {
    expect(sorted(expand(catalog, "*:read"))).toEqual(["billing:read", "report:read"]);
    expect(sorted(expand(catalog, "report:*"))).toEqual([
      "report:list",
      "report:read",
      "report:write",
    ]);
    expect(expand(catalog, "*").size).toBe(5);
    expect(sorted(expand(catalog, "event:manage"))).toEqual(["event:manage"]);
    for (const unknown of ["event:read", "ghost:*", "*:ghost", "*:*", "nope"]) {
      expect(expand(catalog, unknown).size).toBe(0);
    }
  });

  it("closes implications both ways", () => {
    expect(sorted(implied(catalog, "report:write"))).toEqual(["report:list", "report:read"]);
    expect(sorted(implying(catalog, "report:list"))).toEqual(["report:read", "report:write"]);
    expect(implied(catalog, "report:list").size).toBe(0);
    expect(implying(catalog, "report:write").size).toBe(0);
  });

  it("gives the sets a deny, a question and an exclusion work with", () => {
    expect(sorted(blocking(catalog, "report:read"))).toEqual(["report:list", "report:read"]);
    expect(sorted(wanted(catalog, "report:read"))).toEqual(["report:read", "report:write"]);
    expect(sorted(removed(catalog, "report:read"))).toEqual(["report:read", "report:write"]);
    expect(sorted(removed(catalog, "*:read"))).toEqual([
      "billing:read",
      "report:read",
      "report:write",
    ]);
    expect(sorted(down(catalog, "report:read"))).toEqual([
      "report:list",
      "report:read",
      "report:write",
    ]);
    expect(sorted(down(catalog, "report:write"))).toEqual([
      "report:list",
      "report:read",
      "report:write",
    ]);
    expect(removed(catalog, "ghost:read").size).toBe(0);
  });

  it("lists the four spellings that can carry a permission", () => {
    expect(spellings("report:write")).toEqual(["report:write", "report:*", "*:write", "*"]);
  });

  it("checks a permission asked in a question", () => {
    expect(assertQuestionPermission(catalog, "report:read")).toBe("report:read");
    expect(refused(() => assertQuestionPermission(catalog, "report:*"))).toMatchObject({
      code: "ERR_AUTHZ_QUESTION_INVALID",
      status: 400,
      cause: { reason: "wildcard" },
    });
    expect(refused(() => assertQuestionPermission(catalog, "*"))).toMatchObject({
      code: "ERR_AUTHZ_QUESTION_INVALID",
    });
    expect(refused(() => assertQuestionPermission(catalog, "*:*"))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      status: 400,
    });
    expect(refused(() => assertQuestionPermission(catalog, "Report:read"))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => assertQuestionPermission(catalog, 1))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => assertQuestionPermission(catalog, "event:read"))).toMatchObject({
      code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
      status: 400,
      cause: { permission: "event:read" },
    });
  });

  it("checks a pattern placed in a statement or a role", () => {
    for (const pattern of ["*", "report:*", "*:read", "event:manage"]) {
      expect(assertPattern(catalog, pattern)).toBe(pattern);
    }
    expect(refused(() => assertPattern(catalog, "*:*"))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => assertPattern(catalog, "-report:read"))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => assertPattern(catalog, "ghost:*"))).toMatchObject({
      code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
      cause: { permission: "ghost:*" },
    });
    expect(refused(() => assertPattern(catalog, "event:read"))).toMatchObject({
      code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
    });
  });
});

describe("time", () => {
  it("accepts integer seconds up to the last second of 9999", () => {
    for (const value of [0, 1, 1794214800, 253402300799]) expect(assertTime(value)).toBe(value);
    for (const value of [-1, 1.5, 253402300800, Date.UTC(2026, 0, 1), Number.NaN, "1", null]) {
      expect(refused(() => assertTime(value))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        status: 400,
        cause: { what: "time" },
      });
    }
  });

  it("reads the clock once, in milliseconds, floored to seconds", () => {
    let reads = 0;
    const now = () => {
      reads++;
      return 1794214800999;
    };
    expect(clockSeconds({ now })).toBe(1794214800);
    expect(reads).toBe(1);
    expect(refused(() => clockSeconds({ now: () => -1000 }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => clockSeconds({ now: () => Number.NaN }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(typeof clockSeconds()).toBe("number");
  });

  it("holds a statement live until its end, never at it", () => {
    expect(isLive(undefined, 5)).toBe(true);
    expect(isLive(6, 5)).toBe(true);
    expect(isLive(5, 5)).toBe(false);
  });
});
