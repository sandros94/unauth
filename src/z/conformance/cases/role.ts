import type { CatalogData } from "../../catalog.ts";
import type { StoredRole } from "../../types.ts";
import type { RoleCase, ValidationExpect } from "../types.ts";
import { malformed, roleInvalid, unknownPermission } from "./_internal/issues.ts";

const catalog: CatalogData = {
  permissions: ["billing:read", "billing:write", "deploy:run", "report:read", "report:write"],
  implies: { "report:write": ["report:read"], "billing:write": ["billing:read"] },
  presets: { viewer: ["report:read"], ops: ["deploy:run", "billing:*"] },
};

const auditor: StoredRole = { name: "auditor", entries: ["report:read", "billing:read"] };
const oncall: StoredRole = { name: "oncall", entries: ["triage", "deploy:run"] };
const triage: StoredRole = { name: "triage", entries: ["report:read"] };

export const roleCases: readonly RoleCase[] = [
  valid("permissions", "Concrete permissions", { name: "analyst", entries: ["report:write"] }),
  valid("every-read", "Every read", { name: "reader", entries: ["*:read"] }),
  valid("everything", "Everything", { name: "admin", entries: ["*"] }),
  valid("no-entries", "No entries, which is valid and gives nothing", {
    name: "empty",
    entries: [],
  }),
  valid("everything-but", "Everything on reports but writing", {
    name: "report-reader",
    entries: ["report:*", "-report:write"],
  }),
  valid("references-preset", "A role built on a preset", {
    name: "lead",
    entries: ["viewer", "report:write"],
  }),
  valid("excludes-preset", "Everything but what a preset gives", {
    name: "careful",
    entries: ["*", "-ops"],
  }),
  valid(
    "references-stored",
    "A role built on a stored role handed in",
    { name: "senior", entries: ["auditor", "report:write"] },
    [auditor],
  ),
  valid(
    "excludes-stored",
    "Every report action but what a stored role handed in gives",
    { name: "clerk", entries: ["report:*", "-auditor"] },
    [auditor],
  ),
  valid("named-like-preset", "A stored role named like a preset, which the model advises against", {
    name: "viewer",
    entries: ["billing:read"],
  }),
  valid(
    "edit-keeps-references",
    "An edit of a role another stored role references, with no loop",
    { name: "triage", entries: ["report:read", "billing:read"] },
    [triage, oncall],
  ),
  valid("members-of-the-application", "A role carrying a row id of its own", {
    name: "analyst",
    entries: ["report:read"],
    id: 7,
  }),
  refused("name-uppercase", "A name spelled with an uppercase letter", [malformed("name")], {
    name: "Analyst",
    entries: ["report:read"],
  }),
  refused("name-empty", "An empty name", [malformed("name")], {
    name: "",
    entries: ["report:read"],
  }),
  refused("name-missing", "A role without a name", [malformed("name")], {
    entries: ["report:read"],
  }),
  refused("name-excluded", "A name with the `-` of an exclusion", [malformed("name")], {
    name: "-analyst",
    entries: ["report:read"],
  }),
  refused("name-permission", "A permission as a name", [malformed("name")], {
    name: "report:read",
    entries: ["report:read"],
  }),
  refused("entry-uppercase", "An entry spelled otherwise", [malformed("entries", 0)], {
    name: "analyst",
    entries: ["Report:read"],
  }),
  refused("entry-star-star", "An entry spelled `*:*`", [malformed("entries", 0)], {
    name: "admin",
    entries: ["*:*"],
  }),
  refused("entry-double-exclusion", "An entry with two `-`", [malformed("entries", 1)], {
    name: "careful",
    entries: ["*", "--ops"],
  }),
  refused("entry-bare-exclusion", "An entry that is `-` alone", [malformed("entries", 1)], {
    name: "careful",
    entries: ["*", "-"],
  }),
  refused("entry-three-parts", "A permission with two `:`", [malformed("entries", 0)], {
    name: "analyst",
    entries: ["report:read:all"],
  }),
  refused("entry-empty", "An empty entry", [malformed("entries", 0)], {
    name: "analyst",
    entries: [""],
  }),
  refused("entry-not-a-string", "A number among the entries", [malformed("entries", 1)], {
    name: "analyst",
    entries: ["report:read", 42],
  }),
  refused("null", "`null` in place of a role", [malformed()], null),
  refused("entries-not-a-list", "Entries given as one string", [malformed("entries")], {
    name: "analyst",
    entries: "report:read",
  }),
  refused("entries-missing", "A role without entries", [malformed("entries")], { name: "analyst" }),
  refused("unknown-permission", "An undeclared permission", [unknownPermission("entries", 1)], {
    name: "exporter",
    entries: ["report:read", "legacy:export"],
  }),
  refused(
    "excludes-unknown-permission",
    "An exclusion of an undeclared permission",
    [unknownPermission("entries", 1)],
    { name: "careful", entries: ["*", "-legacy:import"] },
  ),
  refused(
    "pattern-matching-nothing",
    "Every invoice action, and the catalog declares no invoice",
    [unknownPermission("entries", 0)],
    { name: "clerk", entries: ["invoice:*"] },
  ),
  refused(
    "action-matching-nothing",
    "Every delete, and the catalog declares none",
    [unknownPermission("entries", 0)],
    { name: "janitor", entries: ["*:delete"] },
  ),
  refused(
    "references-unknown-role",
    "A role built on one that is neither a preset nor handed in",
    [roleInvalid("entries", 0)],
    { name: "senior", entries: ["intern", "report:write"] },
    [auditor],
  ),
  refused(
    "excludes-unknown-role",
    "A role that excludes one that is neither a preset nor handed in",
    [roleInvalid("entries", 1)],
    { name: "clerk", entries: ["report:*", "-auditor"] },
  ),
  refused("references-itself", "A role that names itself", [roleInvalid("entries", 1)], {
    name: "loop",
    entries: ["report:read", "loop"],
  }),
  refused("excludes-itself", "A role that excludes itself", [roleInvalid("entries", 1)], {
    name: "loop",
    entries: ["report:read", "-loop"],
  }),
  refused(
    "cycle-through-stored",
    "A role built on a stored role that is built on it",
    [roleInvalid("entries", 0)],
    { name: "triage", entries: ["oncall"] },
    [oncall],
  ),
  refused(
    "cycle-through-exclusion",
    "A role that excludes a stored role built on it",
    [roleInvalid("entries", 1)],
    { name: "triage", entries: ["report:read", "-oncall"] },
    [oncall],
  ),
  refused(
    "edit-closes-a-cycle",
    "An edit of a role that makes it reference a role built on it",
    [roleInvalid("entries", 1)],
    { name: "triage", entries: ["report:read", "oncall"] },
    [triage, oncall],
  ),
  refused(
    "two-of-one-name-handed",
    "A role built on a name two stored roles handed in share: what is handed is refused",
    "ERR_AUTHZ_ROLE_INVALID",
    { name: "senior", entries: ["auditor"] },
    [auditor, { name: "auditor", entries: ["report:write"] }],
  ),
  refused(
    "every-fault-at-once",
    "A name in another spelling, an undeclared permission, an entry in another spelling and a role nobody handed in: each reported",
    [
      malformed("name"),
      unknownPermission("entries", 1),
      malformed("entries", 2),
      roleInvalid("entries", 3),
    ],
    { name: "Analyst", entries: ["report:read", "legacy:export", "Report:read", "intern"] },
  ),
  refused(
    "no-name-and-no-list",
    "Neither a name nor a list of entries",
    [malformed("name"), malformed("entries")],
    { name: 7, entries: "report:read" },
  ),
  refused(
    "two-unresolvable-references",
    "A role nobody handed in and the role itself, each reported at its entry",
    [roleInvalid("entries", 0), roleInvalid("entries", 2)],
    { name: "loop", entries: ["intern", "report:read", "-loop"] },
    [auditor],
  ),
  refused(
    "entries-in-another-spelling-only",
    "An excluded permission, a role and a pattern in another spelling: never also unknown",
    [malformed("entries", 0), malformed("entries", 1), malformed("entries", 2)],
    { name: "clerk", entries: ["-Legacy:import", "Intern", "Invoice:*"] },
  ),
  refused(
    "through-a-stored-role-naming-an-unknown",
    "A role built on a stored role that names a role nobody handed in",
    [roleInvalid("entries", 0)],
    { name: "senior", entries: ["lead", "report:write"] },
    [{ name: "lead", entries: ["intern", "report:read"] }],
  ),
  refused(
    "through-a-cycle-elsewhere",
    "A role built on a stored role caught in a cycle that does not pass through it",
    [roleInvalid("entries", 1)],
    { name: "senior", entries: ["report:write", "-first"] },
    [
      { name: "first", entries: ["second"] },
      { name: "second", entries: ["first", "deploy:run"] },
    ],
  ),
];

function valid(id: string, title: string, role: unknown, roles?: readonly StoredRole[]): RoleCase {
  return refused(id, title, [], role, roles);
}

function refused(
  id: string,
  title: string,
  expect: ValidationExpect,
  role: unknown,
  roles?: readonly StoredRole[],
): RoleCase {
  return { id: `role/${id}`, title, catalog, role, expect, ...(roles && { roles }) };
}
