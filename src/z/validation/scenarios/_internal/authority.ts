import type { CatalogData } from "../../../catalog.ts";
import type { Statement, StatementKind, StoredRole } from "../../../types.ts";
import type {
  AskStep,
  ChangeReason,
  ChangeStep,
  GenesisStep,
  ScenarioRefusal,
} from "../../types.ts";

export const MINUTE = 60;
export const HOUR = 3600;
export const DAY = 86_400;
/** Monday 2026-11-09 09:00 UTC. */
export const MONDAY = 1_794_214_800;
/** Friday 2026-11-13 00:00 UTC. */
export const FRIDAY = 1_794_528_000;
/** Tuesday 2026-12-01 00:00 UTC, the end of the month. */
export const DEC_1 = 1_796_083_200;
/** Friday 2100-01-01 00:00 UTC. */
export const YEAR_2100 = 4_102_444_800;

export const ACME = "/org=acme";
export const GLOBEX = "/org=globex";
export const ARCHIVES = "/org=acme/area=archives";
export const SALES = "/org=acme/area=sales";
export const HR = "/org=acme/area=hr";
export const P1 = "/org=acme/project=p1";
export const WEB = "/org=acme/project=web";

export const FORGE_ORG = "/org=forge";
export const SITE = "/org=forge/project=site";
export const WWW = "/org=forge/project=site/repo=www";
export const DOCS = "/org=forge/project=docs";

export const CORE = "/team=core";
export const OPS = "/team=ops";

/** Organisations, their areas (which nest) and projects. */
export const CLOUD: CatalogData = {
  permissions: [
    "access:manage",
    "audit-log:delete",
    "audit-log:read",
    "org:own",
    "report:delete",
    "report:read",
    "report:write",
    "vm:start",
  ],
  implies: { "org:own": ["access:manage"], "report:write": ["report:read"] },
  presets: {
    owner: ["*"],
    viewer: ["*:read"],
    editor: ["report:write", "vm:start"],
    support: ["viewer", "-audit-log:read"],
  },
  places: { "/": ["org"], "org": ["area", "project"], "area": ["area"] },
  manager: "access:manage",
};

/** A code forge: organisations, projects, repositories. */
export const FORGE: CatalogData = {
  permissions: [
    "access:manage",
    "code:read",
    "code:write",
    "issue:read",
    "issue:write",
    "member:kick",
    "release:publish",
  ],
  implies: { "code:write": ["code:read"], "issue:write": ["issue:read"] },
  presets: {
    developer: ["code:write", "issue:write"],
    maintainer: ["developer", "member:kick", "release:publish"],
    writer: ["code:write"],
  },
  places: { "/": ["org"], "org": ["project"], "project": ["repo"] },
  manager: "access:manage",
};

/** One person and an agent, no places. */
export const BLOG: CatalogData = {
  permissions: ["access:manage", "post:draft", "post:publish", "post:read"],
  places: false,
  manager: "access:manage",
};

/** The same vocabulary without a manager permission. */
export const BLOG_UNMANAGED: CatalogData = {
  permissions: ["access:manage", "post:draft", "post:publish", "post:read"],
  places: false,
};

/** Teams whose members a user manager adds without reading what they read. */
export const WORKSPACE: CatalogData = {
  permissions: ["access:manage", "billing:read", "doc:read", "doc:write", "member:assign"],
  implies: { "doc:write": ["doc:read"] },
  presets: { member: ["doc:write"], auditor: ["billing:read", "doc:read"] },
  places: { "/": ["team"] },
  manager: "access:manage",
  assigner: { member: "member:assign" },
};

/** Tenants checked by grammar alone, managed through a permission of another name. */
export const TENANTS: CatalogData = {
  permissions: ["doc:read", "doc:write", "tenant:administer"],
  implies: { "doc:write": ["doc:read"] },
  manager: "tenant:administer",
};

/** Where and until when a statement holds. */
export interface StatementOptions {
  place?: string;
  until?: number;
}

export function allow(subject: string, value: string, options?: StatementOptions): Statement {
  return build("allow", subject, value, options);
}

export function assign(subject: string, role: string, options?: StatementOptions): Statement {
  return build("assign", subject, role, options);
}

export function deny(subject: string, value: string, options?: StatementOptions): Statement {
  return build("deny", subject, value, options);
}

export function exclude(subject: string, value: string, options?: StatementOptions): Statement {
  return build("exclude", subject, value, options);
}

/** Who asks for a change, and when. */
export interface Author {
  at: number;
  author: string;
  groups?: readonly string[];
}

/** Accepted, refused with an input error, or refused naming exactly these reasons. */
export type ChangeOutcome = "accepted" | ScenarioRefusal | readonly ChangeReason[];

export function place(by: Author, statement: Statement, outcome?: ChangeOutcome): ChangeStep {
  return changeStep(by, { action: "place", statement }, outcome);
}

export function remove(by: Author, statement: Statement, outcome?: ChangeOutcome): ChangeStep {
  const { expiresAt: _end, ...identity } = statement;
  return changeStep(by, { action: "remove", statement: identity }, outcome);
}

export function define(by: Author, role: StoredRole, outcome?: ChangeOutcome): ChangeStep {
  return changeStep(by, { action: "define", role }, outcome);
}

/** Genesis at `at`, which takes no author. */
export function genesis(at: number, statement: Statement, outcome?: ChangeOutcome): GenesisStep {
  const base = { step: "genesis" as const, at, statement };
  if (outcome === undefined || typeof outcome === "string") {
    return { ...base, expect: outcome ?? "accepted" };
  }
  return { ...base, expect: "ERR_AUTHZ_CHANGE_REFUSED", reasons: outcome };
}

/** Who is asked about, where, and when. */
export interface Asked {
  at: number;
  subject: string;
  groups?: readonly string[];
  place?: string;
}

export function ask(
  asked: Asked,
  permission: string,
  expect: "allowed" | "denied" | ScenarioRefusal,
): AskStep {
  const { at, subject, groups, place: where } = asked;
  return {
    step: "ask",
    at,
    question: {
      subject,
      ...(groups === undefined ? {} : { groups }),
      permission,
      ...(where === undefined ? {} : { place: where }),
    },
    expect,
  };
}

function build(
  kind: StatementKind,
  subject: string,
  value: string,
  options: StatementOptions | undefined,
): Statement {
  return {
    kind,
    subject,
    value,
    ...(options?.place === undefined ? {} : { place: options.place }),
    ...(options?.until === undefined ? {} : { expiresAt: options.until }),
  };
}

function changeStep(
  by: Author,
  change: ChangeStep["change"],
  outcome: ChangeOutcome = "accepted",
): ChangeStep {
  const base = {
    step: "change" as const,
    at: by.at,
    author: by.author,
    ...(by.groups === undefined ? {} : { groups: by.groups }),
    change,
  };
  if (typeof outcome === "string") return { ...base, expect: outcome };
  return { ...base, expect: "ERR_AUTHZ_CHANGE_REFUSED", reasons: outcome };
}
