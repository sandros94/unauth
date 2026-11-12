import type { CatalogData } from "../../catalog.ts";
import type { StoredRole } from "../../types.ts";
import type { StatementCase, ValidationExpect } from "../types.ts";
import { ended, malformed, outside, roleInvalid, unknownPermission } from "./_internal/issues.ts";

const statementCatalog: CatalogData = {
  permissions: ["billing:read", "report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { viewer: ["report:read"], editor: ["viewer", "report:write"] },
  places: { "/": ["org"], "org": ["unit"] },
};

const auditor: StoredRole = { name: "auditor", entries: ["report:read", "billing:read"] };
const twoAuditors: readonly StoredRole[] = [
  auditor,
  { name: "auditor", entries: ["report:write"] },
];

/** Monday 2026-11-09 09:00 UTC, in seconds: when every case is validated. */
const VALIDATED_AT = 1794214800;
/** The last second of the year 9999, the largest time the model allows. */
const LAST_TIME = 253402300799;

const DAY = 86400;

export const statementCases: readonly StatementCase[] = [
  valid("allow-permission", "An allow of one permission at an organisation", {
    kind: "allow",
    subject: "ann",
    value: "report:read",
    place: "/org=acme",
  }),
  valid("allow-everything-no-place", "An allow of `*` with no place, which is the root", {
    kind: "allow",
    subject: "owner",
    value: "*",
  }),
  valid("root-written-out", "A place written out as `/`", {
    kind: "deny",
    subject: "ann",
    value: "billing:read",
    place: "/",
  }),
  valid("deny-every-action", "A deny of every action on reports in one unit", {
    kind: "deny",
    subject: "contractors",
    value: "report:*",
    place: "/org=acme/unit=u1",
  }),
  valid("exclude-every-resource", "An exclusion of every read", {
    kind: "exclude",
    subject: "ann",
    value: "*:read",
    place: "/org=acme",
  }),
  valid("assign-preset", "An assignment of a preset", {
    kind: "assign",
    subject: "ann",
    value: "editor",
    place: "/org=acme",
  }),
  valid(
    "assign-stored-handed",
    "An assignment of a stored role handed in",
    { kind: "assign", subject: "ann", value: "auditor" },
    [auditor],
  ),
  valid(
    "assign-preset-beside-stored-of-its-name",
    "An assignment of a preset while a stored role of its name is handed in",
    { kind: "assign", subject: "ann", value: "viewer" },
    [{ name: "viewer", entries: ["billing:read"] }],
  ),
  {
    id: "statement/assign-preset-with-no-entries",
    title:
      "An assignment of a preset declared with no entries, a role that exists and gives nothing",
    catalog: { ...statementCatalog, presets: { viewer: [] } },
    at: VALIDATED_AT,
    statement: { kind: "assign", subject: "ann", value: "viewer", place: "/org=acme" },
    expect: [],
  },
  valid("end-a-second-later", "An end one second after the validation", {
    kind: "allow",
    subject: "ann",
    value: "report:read",
    expiresAt: VALIDATED_AT + 1,
  }),
  valid("end-at-the-cap", "An end at the last second of the year 9999", {
    kind: "allow",
    subject: "ann",
    value: "report:read",
    expiresAt: LAST_TIME,
  }),
  valid("members-of-the-application", "A statement carrying a row id and a note of its own", {
    kind: "allow",
    subject: "ann",
    value: "report:read",
    id: 42,
    note: "onboarding",
  }),
  refused("kind-unknown", "A kind that is not one of the four", [malformed("kind")], {
    kind: "grant",
    subject: "ann",
    value: "report:read",
  }),
  refused("kind-uppercase", "A kind spelled with an uppercase letter", [malformed("kind")], {
    kind: "Allow",
    subject: "ann",
    value: "report:read",
  }),
  refused("null", "`null` in place of a statement", [malformed()], null),
  refused("string", "A sentence in place of a statement", [malformed()], "allow ann"),
  refused("list", "A list in place of a statement", [malformed()], ["allow", "ann"]),
  refused("no-subject", "A statement about nobody", [malformed("subject")], {
    kind: "allow",
    value: "report:read",
  }),
  refused("empty-subject", "A statement about the empty string", [malformed("subject")], {
    kind: "allow",
    subject: "",
    value: "report:read",
  }),
  refused(
    "unknown-permission",
    "An allow of an undeclared permission",
    [unknownPermission("value")],
    {
      kind: "allow",
      subject: "ann",
      value: "billing:write",
    },
  ),
  refused(
    "deny-unknown-permission",
    "A deny of an undeclared permission",
    [unknownPermission("value")],
    { kind: "deny", subject: "ann", value: "legacy:export" },
  ),
  refused(
    "exclude-unknown-permission",
    "An exclusion of an undeclared permission",
    [unknownPermission("value")],
    { kind: "exclude", subject: "ann", value: "legacy:export", place: "/org=acme" },
  ),
  refused(
    "pattern-matching-nothing",
    "An allow of every invoice action, and the catalog declares no invoice",
    [unknownPermission("value")],
    { kind: "allow", subject: "ann", value: "invoice:*" },
  ),
  refused(
    "action-matching-nothing",
    "A deny of every delete, and the catalog declares none",
    [unknownPermission("value")],
    { kind: "deny", subject: "ann", value: "*:delete" },
  ),
  refused("permission-uppercase", "A permission spelled otherwise", [malformed("value")], {
    kind: "allow",
    subject: "ann",
    value: "Report:read",
  }),
  refused("star-star", "`*:*`, which is not a spelling of `*`", [malformed("value")], {
    kind: "allow",
    subject: "ann",
    value: "*:*",
  }),
  refused(
    "allow-role-name",
    "An allow naming a role in place of a permission",
    [malformed("value")],
    {
      kind: "allow",
      subject: "ann",
      value: "viewer",
    },
  ),
  refused("allow-excluded", "An allow with the `-` of a role entry", [malformed("value")], {
    kind: "allow",
    subject: "ann",
    value: "-report:read",
  }),
  refused("empty-value", "A deny of nothing", [malformed("value")], {
    kind: "deny",
    subject: "ann",
    value: "",
  }),
  refused(
    "assign-unknown-role",
    "An assignment of a role that is neither a preset nor handed in",
    [roleInvalid("value")],
    { kind: "assign", subject: "ann", value: "intern" },
    [auditor],
  ),
  refused(
    "assign-stored-not-handed",
    "An assignment of a stored role the application did not hand in",
    [roleInvalid("value")],
    { kind: "assign", subject: "ann", value: "auditor" },
  ),
  refused("assign-permission", "An assignment of a permission", [malformed("value")], {
    kind: "assign",
    subject: "ann",
    value: "report:read",
  }),
  refused("assign-uppercase", "An assignment of a role spelled otherwise", [malformed("value")], {
    kind: "assign",
    subject: "ann",
    value: "Viewer",
  }),
  refused(
    "assign-with-two-of-one-name",
    "An assignment while two stored roles of one name are handed in: what is handed is refused",
    "ERR_AUTHZ_ROLE_INVALID",
    { kind: "assign", subject: "ann", value: "auditor" },
    twoAuditors,
  ),
  refused(
    "preset-with-two-of-one-name",
    "An assignment of a preset while two stored roles of one name are handed in",
    "ERR_AUTHZ_ROLE_INVALID",
    { kind: "assign", subject: "ann", value: "viewer" },
    twoAuditors,
  ),
  refused(
    "allow-with-two-of-one-name",
    "An allow, valid by itself, while two stored roles of one name are handed in",
    "ERR_AUTHZ_ROLE_INVALID",
    { kind: "allow", subject: "ann", value: "report:read" },
    twoAuditors,
  ),
  refused(
    "place-lowercase-hex",
    "A key with lowercase hexadecimal",
    [malformed("place")],
    at("/org=caf%c3%a9"),
  ),
  refused("place-no-slash", "A key without its leading `/`", [malformed("place")], at("org=acme")),
  refused("place-trailing-slash", "A key ending in `/`", [malformed("place")], at("/org=acme/")),
  refused("place-empty", "An empty key", [malformed("place")], at("")),
  refused("place-number", "A place written as a number", [malformed("place")], at(7)),
  refused(
    "place-unit-at-root",
    "A unit directly under the root",
    [outside("place")],
    at("/unit=u1"),
  ),
  refused(
    "place-undeclared-level",
    "A team, a level the structure lacks",
    [outside("place")],
    at("/org=acme/team=t1"),
  ),
  {
    id: "statement/place-without-places",
    title: "A place in an application that declares it has none",
    catalog: { permissions: ["report:read"], places: false },
    at: VALIDATED_AT,
    statement: at("/org=acme"),
    expect: [outside("place")],
  },
  {
    id: "statement/root-without-places",
    title: "The root in an application that declares it has no places",
    catalog: { permissions: ["report:read"], places: false },
    at: VALIDATED_AT,
    statement: { kind: "allow", subject: "ann", value: "report:read" },
    expect: [],
  },
  {
    id: "statement/place-unchecked",
    title: "Any canonical key where the catalog says nothing about places",
    catalog: { permissions: ["report:read"] },
    at: VALIDATED_AT,
    statement: at("/account=did:plc:abc"),
    expect: [],
  },
  refused(
    "end-now",
    "An end at the very second of the validation",
    [ended("expiresAt")],
    until(VALIDATED_AT),
  ),
  refused(
    "end-yesterday",
    "An end a day before the validation",
    [ended("expiresAt")],
    until(VALIDATED_AT - DAY),
  ),
  refused("end-zero", "An end at time 0", [ended("expiresAt")], until(0)),
  refused("end-negative", "An end before 1970", [malformed("expiresAt")], until(-1)),
  refused(
    "end-fraction",
    "An end with a fraction of a second",
    [malformed("expiresAt")],
    until(VALIDATED_AT + 0.5),
  ),
  refused(
    "end-milliseconds",
    "An end counted in milliseconds",
    [malformed("expiresAt")],
    until(VALIDATED_AT * 1000),
  ),
  refused(
    "end-past-the-cap",
    "An end one second after the year 9999",
    [malformed("expiresAt")],
    until(LAST_TIME + 1),
  ),
  refused(
    "end-string",
    "An end written as text",
    [malformed("expiresAt")],
    until(String(VALIDATED_AT)),
  ),
  refused(
    "end-fraction-in-the-past",
    "An end with a fraction of a second, before the validation: not a time, so not ended either",
    [malformed("expiresAt")],
    until(VALIDATED_AT - 0.5),
  ),
  refused(
    "end-string-in-the-past",
    "An end written as text, a day before the validation",
    [malformed("expiresAt")],
    until(String(VALIDATED_AT - DAY)),
  ),
  refused(
    "unknown-kind-looks-nothing-up",
    "A kind that is not one of the four, with a permission the catalog lacks: only the kind, since the kind says what the value names",
    [malformed("kind")],
    { kind: "alow", subject: "ann", value: "legacy:export" },
  ),
  refused(
    "unknown-kind-unreadable-value",
    "A kind that is not one of the four, with a value in no form at all: both reported",
    [malformed("kind"), malformed("value")],
    { kind: "alow", subject: "ann", value: "Report Read!" },
  ),
  refused(
    "malformed-and-ended",
    "A kind that is not one of the four, ended yesterday: both reported",
    [malformed("kind"), ended("expiresAt")],
    { kind: "grant", subject: "ann", value: "report:read", expiresAt: VALIDATED_AT - DAY },
  ),
  refused(
    "malformed-permission-and-ended",
    "A permission spelled otherwise, ended yesterday: both reported",
    [malformed("value"), ended("expiresAt")],
    { kind: "allow", subject: "ann", value: "Report:read", expiresAt: VALIDATED_AT - DAY },
  ),
  refused(
    "every-member-malformed",
    "A subject, a value, a place and an end, none in its form",
    [malformed("subject"), malformed("value"), malformed("place"), malformed("expiresAt")],
    { kind: "deny", subject: 42, value: "Report:read", place: "org=acme", expiresAt: "friday" },
  ),
  refused(
    "every-member-refused-its-own-way",
    "Nobody, an undeclared permission, a place outside the structure, an end passed",
    [malformed("subject"), unknownPermission("value"), outside("place"), ended("expiresAt")],
    { kind: "allow", value: "legacy:export", place: "/team=t1", expiresAt: VALIDATED_AT - DAY },
  ),
  refused(
    "unknown-role-outside-and-ended",
    "An assignment of a role nobody handed in, under a level the structure lacks, ended",
    [roleInvalid("value"), outside("place"), ended("expiresAt")],
    { kind: "assign", subject: "ann", value: "intern", place: "/team=t1", expiresAt: 0 },
  ),
  refused(
    "malformed-key-of-an-undeclared-level",
    "A key both in another spelling and under a level the structure lacks: only the spelling",
    [malformed("place")],
    at("/team=caf%c3%a9"),
  ),
  refused(
    "malformed-pattern-of-an-undeclared-resource",
    "A pattern in another spelling over a resource the catalog lacks: only the spelling",
    [malformed("value")],
    { kind: "deny", subject: "ann", value: "Invoice:*" },
  ),
];

function valid(
  id: string,
  title: string,
  statement: unknown,
  roles?: readonly StoredRole[],
): StatementCase {
  return refused(id, title, [], statement, roles);
}

function refused(
  id: string,
  title: string,
  expect: ValidationExpect,
  statement: unknown,
  roles?: readonly StoredRole[],
): StatementCase {
  return {
    id: `statement/${id}`,
    title,
    catalog: statementCatalog,
    at: VALIDATED_AT,
    statement,
    expect,
    ...(roles && { roles }),
  };
}

/** An allow of reading reports at `place`. */
function at(place: unknown): unknown {
  return { kind: "allow", subject: "ann", value: "report:read", place };
}

/** A deny of reading reports ending at `expiresAt`. */
function until(expiresAt: unknown): unknown {
  return { kind: "deny", subject: "ann", value: "report:read", expiresAt };
}
