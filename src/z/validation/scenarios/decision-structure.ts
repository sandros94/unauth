import type { Scenario } from "../types.ts";
import { MONDAY, allow, ask, assign, deny, issue, read } from "./_internal/scenario-steps.ts";

export const decisionStructureScenarios: readonly Scenario[] = [
  {
    id: "decision/structure-folders-anywhere",
    title:
      "A media library whose folders sit under anything, with statements left from an older structure",
    proves: ["D1"],
    catalog: {
      permissions: ["asset:read", "asset:edit"],
      places: { "/": ["library"], "*": ["folder"], "folder": ["asset"] },
    },
    statements: [
      allow("liv", "asset:read", "/library=brand"),
      allow("liv", "asset:edit", "/library=brand/asset=a1"),
      deny("liv", "asset:read", "/team=design"),
    ],
    steps: [
      ask(
        MONDAY,
        {
          subject: "liv",
          permission: "asset:read",
          place: "/library=brand/folder=logos/folder=2026/asset=a1",
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "liv", permission: "asset:read", place: "/folder=inbox" }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        {
          subject: "liv",
          permission: "asset:edit",
          place: "/library=brand/folder=logos/asset=a1",
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "liv",
          permission: "asset:read",
          place: "/library=brand/folder=f/asset=a1/folder=x",
        },
        "allowed",
      ),
      ask(
        MONDAY,
        { subject: "liv", permission: "asset:read", place: "/library=brand/asset=a1" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "liv", permission: "asset:read", place: "/library=brand/library=old" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
      ),
      ask(
        MONDAY,
        { subject: "liv", permission: "asset:read", place: "/asset=a1" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
      ),
      issue(MONDAY, "outside", "liv", {
        bases: ["/library=brand/asset=a1"],
        expect: "ERR_AUTHZ_PLACE_OUTSIDE",
      }),
      issue(MONDAY, "malformed", "liv", {
        bases: ["/library=brand/"],
        expect: "ERR_AUTHZ_MALFORMED",
      }),
    ],
  },
  {
    id: "decision/structure-none",
    title:
      "A notes app without places refuses every key but the root, and ignores a deny left from its team days",
    proves: ["D1"],
    catalog: {
      permissions: ["note:read", "note:write"],
      presets: { editor: ["note:read", "note:write"] },
      places: false,
    },
    statements: [assign("ed", "editor"), deny("ed", "note:write", "/team=t1")],
    steps: [
      ask(MONDAY, { subject: "ed", permission: "note:write" }, "allowed", { issuedAt: MONDAY }),
      ask(MONDAY, { subject: "ed", permission: "note:write", place: "/" }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "fay", permission: "note:read" }, "denied", { issuedAt: MONDAY }),
      ask(
        MONDAY,
        { subject: "ed", permission: "note:write", place: "/team=t1" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
        {
          issuedAt: MONDAY,
        },
      ),
      issue(MONDAY, "team", "ed", { bases: ["/team=t1"], expect: "ERR_AUTHZ_PLACE_OUTSIDE" }),
      issue(MONDAY, "root", "ed", { bases: ["/"] }),
      read(MONDAY, "root", { permission: "note:read" }, "allowed"),
    ],
  },
  {
    id: "decision/structure-unchecked",
    title:
      "Without a declared structure every canonical key is a place, and a key in another spelling is refused",
    proves: ["D1"],
    catalog: { permissions: ["doc:read"] },
    statements: [allow("gus", "doc:read", "/tenant=t1")],
    steps: [
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=t1/anything=x/deeper=y" },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/account=did:plc:abc" },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(MONDAY, { subject: "gus", permission: "doc:read", place: "/tenant=caf%C3%A9" }, "denied"),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=t1/" },
        "ERR_AUTHZ_MALFORMED",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=caf%c3%a9" },
        "ERR_AUTHZ_MALFORMED",
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=t%31" },
        "ERR_AUTHZ_MALFORMED",
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "tenant=t1" },
        "ERR_AUTHZ_MALFORMED",
      ),
      issue(MONDAY, "bad-base", "gus", { bases: ["/Tenant=t1"], expect: "ERR_AUTHZ_MALFORMED" }),
    ],
  },
];
