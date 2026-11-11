import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import { covers, isCanonicalKey } from "../../src/z/_internal/keys.ts";
import { assertFits, checkPlace, fits } from "../../src/z/_internal/structure.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import { parsePlace, placeChain, placeFits, placeKey, placeRange } from "../../src/z/place.ts";
import { refused } from "./_expect.ts";

const NOT_CANONICAL = [
  "",
  "org=a",
  "/org=a/",
  "//",
  "/org=a//unit=b",
  "/Org=a",
  "/org",
  "/org=",
  "/=a",
  "/org=a b",
  "/org=é",
  "/org=%2f",
  "/org=%2",
  "/org=%G0",
  "/org=%41",
  "/org=%2D",
  "/org=%C3",
  "/org=%C3%28",
  "/org=%ED%A0%80",
  "/org=%C0%AF",
  "/org=a%",
  `/${"x".repeat(33)}=a`,
];

describe("placeKey", () => {
  it("builds keys from an object in insertion order, or from a list with repeated levels", () => {
    expect(placeKey({ org: "acme", unit: "u7" })).toBe("/org=acme/unit=u7");
    expect(
      placeKey(
        [
          ["folder", "a"],
          ["folder", "b"],
        ],
        { under: "/drive=d1" },
      ),
    ).toBe("/drive=d1/folder=a/folder=b");
    expect(placeKey({})).toBe("/");
    expect(placeKey({}, { under: "/org=acme" })).toBe("/org=acme");
    expect(placeKey({ unit: "u7" }, { under: "/" })).toBe("/unit=u7");
  });

  it("writes literal octets literally and percent-encodes the rest in uppercase", () => {
    expect(placeKey({ account: "did:plc:abc" })).toBe("/account=did:plc:abc");
    expect(placeKey({ v: "a=b;c,d@e!$&'()*+~._-" })).toBe("/v=a=b;c,d@e!$&'()*+~._-");
    expect(placeKey({ v: "a/b" })).toBe("/v=a%2Fb");
    expect(placeKey({ v: "50%" })).toBe("/v=50%25");
    expect(placeKey({ v: "a b?#" })).toBe("/v=a%20b%3F%23");
    expect(placeKey({ v: "Café" })).toBe("/v=Caf%C3%A9");
    expect(placeKey({ v: "😀" })).toBe("/v=%F0%9F%98%80");
    expect(placeKey({ v: "﻿" })).toBe("/v=%EF%BB%BF");
  });

  it("refuses a level that is not a token, an empty value or one that is not Unicode text", () => {
    for (const segments of [
      { Org: "a" },
      { "": "a" },
      { "a=b": "c" },
      { org: "" },
      { org: "\uD800" },
      { org: "a\uDC00" },
      [["org"]],
      [["org", "a", "b"]],
      ["org"],
    ]) {
      expect(refused(() => placeKey(segments as never))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        status: 400,
      });
    }
    expect(refused(() => placeKey({ org: 1 } as never))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
  });

  it("refuses to continue from a key that is not canonical", () => {
    for (const under of ["/org=a/", "org=a", "/org=%41"]) {
      expect(refused(() => placeKey({ unit: "u" }, { under }))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "place", value: under },
      });
    }
  });
});

describe("parsePlace", () => {
  it("returns decoded segments from the root down", () => {
    expect(parsePlace("/")).toEqual([]);
    expect(parsePlace("/org=acme/unit=u7")).toEqual([
      ["org", "acme"],
      ["unit", "u7"],
    ]);
    expect(parsePlace("/account=did:plc:abc/v=a=b")).toEqual([
      ["account", "did:plc:abc"],
      ["v", "a=b"],
    ]);
    expect(parsePlace("/v=Caf%C3%A9/v=%EF%BB%BF")).toEqual([
      ["v", "Café"],
      ["v", "﻿"],
    ]);
  });

  it("round-trips with placeKey", () => {
    const segments: [string, string][] = [
      ["org", "Café/50% 😀"],
      ["folder", "a"],
      ["folder", "=:@"],
    ];
    expect(parsePlace(placeKey(segments))).toEqual(segments);
  });

  it("refuses every key that is not canonical, never repairing one", () => {
    for (const key of NOT_CANONICAL) {
      expect(refused(() => parsePlace(key))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "place" },
      });
      expect(isCanonicalKey(key)).toBe(false);
    }
    expect(isCanonicalKey(42)).toBe(false);
  });
});

describe("placeChain", () => {
  it("gives the key, then each place above it, ending with the root", () => {
    expect(placeChain("/org=acme/unit=u7")).toEqual(["/org=acme/unit=u7", "/org=acme", "/"]);
    expect(placeChain("/org=acme")).toEqual(["/org=acme", "/"]);
    expect(placeChain("/")).toEqual(["/"]);
    expect(placeChain("/v=a%2Fb/w=c")).toEqual(["/v=a%2Fb/w=c", "/v=a%2Fb", "/"]);
  });

  it("refuses a key that is not canonical", () => {
    expect(refused(() => placeChain("/org=acme/"))).toMatchObject({ code: "ERR_AUTHZ_MALFORMED" });
  });
});

describe("placeRange", () => {
  it("bounds the places under a key, itself and its siblings left out", () => {
    expect(placeRange("/org=acme")).toEqual({ after: "/org=acme/", before: "/org=acme0" });
    expect(placeRange("/")).toEqual({ after: "/", before: "0" });
    const { after, before } = placeRange("/org=acme");
    const inside = (key: string) => key > after && key < before;
    expect(inside("/org=acme/unit=u7")).toBe(true);
    expect(inside("/org=acme/unit=u7/team=t")).toBe(true);
    expect(inside("/org=acme")).toBe(false);
    expect(inside("/org=acme-x")).toBe(false);
    expect(inside("/org=acme-x/unit=u")).toBe(false);
    expect(inside("/org=acmf")).toBe(false);
    const root = placeRange("/");
    expect("/org=a" > root.after && "/org=a" < root.before).toBe(true);
    expect("/" > root.after).toBe(false);
  });

  it("refuses a key that is not canonical", () => {
    expect(refused(() => placeRange("org=acme"))).toMatchObject({ code: "ERR_AUTHZ_MALFORMED" });
  });
});

describe("covers", () => {
  it("covers itself and everything under it, and nothing else", () => {
    expect(covers("/", "/org=a")).toBe(true);
    expect(covers("/", "/")).toBe(true);
    expect(covers("/org=a", "/org=a")).toBe(true);
    expect(covers("/org=a", "/org=a/unit=b")).toBe(true);
    expect(covers("/org=a/unit=b", "/org=a")).toBe(false);
    expect(covers("/org=a", "/org=ab")).toBe(false);
    expect(covers("/org=acme", "/org=acme-x")).toBe(false);
    expect(covers("/org=a", "/")).toBe(false);
  });
});

describe("fits", () => {
  const declared = compiledOf(
    defineCatalog({
      permissions: ["a:x"],
      places: { "/": ["org"], "org": ["unit", "project", "org"], "*": ["folder"] },
    }),
  );
  const none = compiledOf(defineCatalog({ permissions: ["a:x"], places: false }));
  const open = compiledOf(defineCatalog({ permissions: ["a:x"] }));

  it("checks each level against the one before it under a declared structure", () => {
    for (const key of [
      "/",
      "/org=a",
      "/org=a/unit=b",
      "/org=a/org=b/project=c",
      "/folder=f",
      "/org=a/unit=b/folder=f/folder=g",
    ]) {
      expect([key, fits(declared, key)]).toEqual([key, true]);
    }
    for (const key of ["/unit=b", "/org=a/unit=b/unit=c", "/team=t", "/folder=f/org=a"]) {
      expect([key, fits(declared, key)]).toEqual([key, false]);
    }
  });

  it("lets only the root fit when the catalog has no places, and every key when it says nothing", () => {
    expect(fits(none, "/")).toBe(true);
    expect(fits(none, "/org=a")).toBe(false);
    expect(fits(open, "/anything=at/all=x")).toBe(true);
  });

  it("refuses a key that does not fit with the place in the cause", () => {
    expect(refused(() => assertFits(declared, "/unit=b"))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
      status: 400,
      cause: { place: "/unit=b" },
    });
    expect(refused(() => checkPlace(none, "/org=a"))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
    });
    expect(refused(() => checkPlace(open, "/org=a/"))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(checkPlace(none, undefined)).toBe("/");
    expect(checkPlace(declared, "/org=a")).toBe("/org=a");
  });
});

describe("whether a key fits the catalog", () => {
  const declared = defineCatalog({
    permissions: ["file:read"],
    places: { "/": ["org"], "org": ["drive"], "*": ["folder"] },
  });
  const flat = defineCatalog({ permissions: ["file:read"], places: false });
  const unchecked = defineCatalog({ permissions: ["file:read"] });

  it("follows the declared structure, a level under `*` sitting anywhere", () => {
    expect(placeFits(declared, "/")).toBe(true);
    expect(placeFits(declared, "/org=acme/drive=d1")).toBe(true);
    expect(placeFits(declared, "/folder=a/folder=b")).toBe(true);
    expect(placeFits(declared, "/org=acme/drive=d1/folder=a")).toBe(true);
    expect(placeFits(declared, "/drive=d1")).toBe(false);
    expect(placeFits(declared, "/org=acme/unit=u7")).toBe(false);
  });

  it("holds only the root for a catalog without places, and every key for one that says nothing", () => {
    expect(placeFits(flat, "/")).toBe(true);
    expect(placeFits(flat, "/org=acme")).toBe(false);
    expect(placeFits(unchecked, "/anything=at/all=here")).toBe(true);
  });

  it("is false for a key that is not canonical, whatever the catalog", () => {
    expect(placeFits(unchecked, "/org=acme/")).toBe(false);
    expect(placeFits(unchecked, "org=acme")).toBe(false);
    expect(placeFits(declared, "/Org=acme")).toBe(false);
  });
});
