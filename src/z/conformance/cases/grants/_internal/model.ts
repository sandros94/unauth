import type { CatalogData } from "../../../../catalog.ts";
import type { Diverged } from "../../../engine.ts";
import type { GrantsCase } from "../../../types.ts";

/** Monday 2026-11-09 09:00 UTC, when every object of Section 8.4 is issued. */
export const MONDAY = 1794214800;
export const DAY = 86400;
/** Friday 2026-11-13 00:00 UTC, the end of Sue's own allow. */
export const FRIDAY_MIDNIGHT = 1794528000;
/** Monday 2026-11-16 09:00 UTC, the end of Ed's editor. */
export const NEXT_MONDAY = 1794819600;
/** The last second a time may name. */
export const LAST_TIME = 253402300799;

export const ACME = "/org=acme";
export const ARCHIVES = "/org=acme/area=archives";
export const U7 = "/org=acme/unit=u7";

/** Zoe's and Sue's catalog: reports, a writer preset, archives under organisations. */
export const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { writer: ["report:read", "report:write"] },
  places: { "/": ["org"], "org": ["area"] },
};

/** Ed's catalog: no places, `viewer = ["*:read"]` and `editor = ["viewer", "post:write"]`. */
export const flat: CatalogData = {
  permissions: ["post:read", "post:write"],
  presets: { viewer: ["*:read"], editor: ["viewer", "post:write"] },
  places: false,
};

/** Ada's catalog, as Section 8.4 declares it: four permissions and `viewer = ["*:read"]`. */
export const ada: CatalogData = {
  permissions: ["billing:read", "post:read", "report:read", "report:write"],
  presets: { viewer: ["*:read"] },
};

/** The later catalog of Section 8.4, where `viewer = ["post:read"]`. */
export const adaLater: CatalogData = { ...ada, presets: { viewer: ["post:read"] } };

/** An item: the index of a place, an end, a bundle number. */
type Item = readonly (number | null)[];

/** Grants as Section 8.4 writes them, `ct` possibly `"$ct"`. */
export interface Written {
  v: string;
  ct: string;
  at: number;
  bs?: readonly string[];
  pl?: readonly string[];
  pm?: readonly string[];
  ps?: Readonly<Record<string, readonly (string | number)[]>>;
  sr?: Readonly<Record<string, readonly (string | number)[]>>;
  nt: Readonly<Record<string, { a?: readonly Item[]; d?: readonly Item[]; x?: readonly Item[] }>>;
}

/** Zoe is allowed `report:*` and excluded from `report:write` at the organisation. */
export const zoe: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME],
  nt: { "report:*": { a: [[0]] }, "report:write": { x: [[0]] } },
};

/** Sue's grants, presets by name: her team's `writer` in bundle 1, her own allow until Friday. */
export const sue: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME, ARCHIVES],
  nt: {
    "report:write": { a: [[0, FRIDAY_MIDNIGHT]], x: [[1, null, 1]] },
    "writer": { a: [[0, null, 1]] },
  },
};

/** Ed, presets by name: `viewer` for good, `editor` until next Monday. */
export const edByName: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  nt: { editor: { a: [[null, NEXT_MONDAY]] }, viewer: { a: [[]] } },
};

/** The same grants with copies of both presets. */
export const edCopies: Written = {
  ...edByName,
  pm: ["post:write"],
  ps: { editor: [0, "viewer"], viewer: ["*:read"] },
};

/** Ada: the stored role `reviewer` at the organisation, `billing:read` at one unit, with copies. */
export const adaCopies: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME, U7],
  pm: ["billing:read", "report:write"],
  ps: { viewer: ["*:read"] },
  sr: { reviewer: ["-0", 1, "viewer"] },
  nt: { "0": { a: [[1]] }, "reviewer": { a: [[0]] } },
};

/** The same grants with presets by name. */
export const adaByName: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME, U7],
  pm: ["billing:read", "report:write"],
  sr: { reviewer: ["-0", 1, "viewer"] },
  nt: { "0": { a: [[1]] }, "reviewer": { a: [[0]] } },
};

/** What a read tells has diverged. */
export function diverged(
  segments: Diverged["segments"],
  lists: { permissions?: string[]; presets?: string[] } = {},
): Diverged {
  return { segments, permissions: lists.permissions ?? [], presets: lists.presets ?? [] };
}

/** A case read under `catalog` on Monday, with the question asked at `place`. */
export function readCase(
  id: string,
  title: string,
  read: Pick<GrantsCase, "catalog" | "grants" | "expect"> &
    Partial<Pick<GrantsCase, "issuedUnder" | "diverged" | "at">>,
  permission: string,
  place?: string,
): GrantsCase {
  return {
    id: `grants/${id}`,
    title,
    at: MONDAY,
    question: place === undefined ? { permission } : { permission, place },
    ...read,
  };
}
