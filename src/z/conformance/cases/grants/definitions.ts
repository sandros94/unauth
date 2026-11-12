import type { GrantsCase } from "../../types.ts";
import { ACME, MONDAY, readCase, reports } from "./_internal/model.ts";

/** A permission table of reading and writing, and the grants' place, under `reports`. */
const base = { v: "1", ct: "$ct", at: MONDAY, pl: [ACME], pm: ["report:read", "report:write"] };

/**
 * Roles read from the definitions grants hold (G9 of the model): a role that cannot be resolved
 * gives nothing, and so does every role that names it, with or without `-`.
 */
export const definitionCases: readonly GrantsCase[] = (
  [
    [
      "role-built-on-a-deleted-role",
      "A stored lead built on writer and on a role deleted before issue, beside preset copies: lead gives nothing",
      {
        ...base,
        ps: { writer: [0, 1] },
        sr: { lead: ["writer", "ghost"] },
        nt: { lead: { a: [[0]] } },
      },
      "report:read",
      "denied",
    ],
    [
      "role-excluding-a-deleted-role",
      "A stored role excluding a role in neither table, beside preset copies: it gives nothing, the exclusion is never skipped",
      {
        ...base,
        ps: { writer: [0, 1] },
        sr: { careful: ["writer", "-ghost"] },
        nt: { careful: { a: [[0]] } },
      },
      "report:read",
      "denied",
    ],
    [
      "role-excluding-an-undeclared-preset",
      "Presets by name: a stored role excluding a name that is neither stored nor a preset of the catalog gives nothing",
      { ...base, sr: { careful: ["writer", "-ghost"] }, nt: { careful: { a: [[0]] } } },
      "report:read",
      "denied",
    ],
    [
      "role-naming-an-unresolvable-role",
      "A stored senior naming lead, which names a deleted role: senior gives nothing, even what it names itself",
      {
        ...base,
        ps: { writer: [0, 1] },
        sr: { lead: ["writer", "ghost"], senior: ["lead", 0] },
        nt: { senior: { a: [[0]] } },
      },
      "report:read",
      "denied",
    ],
    [
      "other-roles-unaffected",
      "Beside a stored role that gives nothing, the writer preset assigned on its own still gives",
      {
        ...base,
        ps: { writer: [0, 1] },
        sr: { lead: ["writer", "ghost"] },
        nt: { lead: { a: [[0]] }, writer: { a: [[0]] } },
      },
      "report:read",
      "allowed",
    ],
    [
      "stored-roles-in-a-cycle",
      "Two stored roles written without validation name each other: the one assigned gives nothing",
      {
        ...base,
        sr: { triage: ["oncall", 0], oncall: ["triage", 1] },
        nt: { triage: { a: [[0]] } },
      },
      "report:read",
      "denied",
    ],
    [
      "role-naming-a-cycle",
      "A stored role naming one of two roles in a cycle gives nothing either",
      {
        ...base,
        sr: { triage: ["oncall", 0], oncall: ["triage"], lead: ["oncall", 1] },
        nt: { lead: { a: [[0]] } },
      },
      "report:write",
      "denied",
    ],
    [
      "preset-copies-in-a-cycle",
      "Two preset copies written by hand name each other: the one assigned gives nothing",
      {
        ...base,
        ps: { viewer: ["editor", 0], editor: ["viewer", 1] },
        nt: { viewer: { a: [[0]] } },
      },
      "report:read",
      "denied",
    ],
    [
      "catalog-preset-not-copied",
      "Grants carrying preset copies name writer without its copy: writer is a role that does not exist there, and gives nothing",
      { ...base, ps: { editor: [1] }, nt: { writer: { a: [[0]] } } },
      "report:read",
      "denied",
    ],
  ] as const
).map(([id, title, grants, permission, expect]) =>
  readCase(id, title, { catalog: reports, grants, expect }, permission, ACME),
);
