import { UnauthError } from "../../src/error.ts";
import { type Catalog, defineCatalog } from "../../src/z/catalog.ts";
import { type Change, checkChange, checkGenesis } from "../../src/z/change.ts";
import type { Statement, StoredRole } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

/** A forge: organisations hold projects and areas, archives sit in areas. */
export const forge: Catalog = defineCatalog({
  permissions: [
    "access:manage",
    "member:assign",
    "member:kick",
    "report:list",
    "report:read",
    "report:write",
    "post:read",
    "post:draft",
    "post:publish",
    "repo:push",
    "audit-log:delete",
    "billing:read",
  ],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: {
    viewer: ["report:read"],
    developer: ["report:read", "repo:push"],
    maintainer: ["report:*", "repo:push", "access:manage"],
    moderator: ["access:manage", "member:kick"],
    accountant: ["billing:read", "report:read"],
    owner: ["*"],
  },
  places: { "/": ["org"], "org": ["project", "area"], "area": ["archive"] },
  manager: "access:manage",
  assigner: { accountant: "member:assign" },
});

export const ACME = "/org=acme";
export const P1 = "/org=acme/project=p1";
export const ARCHIVES = "/org=acme/area=archives";
export const GLOBEX = "/org=globex";

export const NOW = 1794214800;
export const HOUR = 3600;
export const DAY = 86400;

/** Who asks: the subject and its groups. */
export interface Asker {
  subject: string;
  groups?: string[];
}

/** How a check is run: `managers: false` hands none in. */
export interface CheckWith {
  managers?: false | Statement[];
  extra?: Statement[];
}

/**
 * A store in memory: every accepted change is applied, a placement replacing its identity's end,
 * a definition replacing the stored role of the same name and home.
 */
export class World {
  statements: Statement[] = [];
  roles: StoredRole[] = [];
  time: number = NOW;

  constructor(readonly catalog: Catalog = forge) {}

  /** A world after genesis about `owner`. */
  static founded(owner = "root", catalog: Catalog = forge): World {
    return new World(catalog).genesis(allow(owner, "*"));
  }

  /** Places the first permanent manager, checked as genesis. */
  genesis(statement: Statement): this {
    checkGenesis(this.catalog, statement, {
      managers: this.managers(),
      now: () => this.time * 1000,
    });
    this.statements.push(statement);
    return this;
  }

  managers(): Statement[] {
    return this.statements.filter(
      (statement) =>
        statement.kind === "allow" &&
        statement.value === "*" &&
        (statement.place ?? "/") === "/" &&
        statement.expiresAt === undefined,
    );
  }

  check(asker: Asker | string, change: Change, using?: CheckWith): void {
    const { subject, groups } = typeof asker === "string" ? { subject: asker } : asker;
    const managers = using?.managers === undefined ? this.managers() : using.managers;
    checkChange(this.catalog, change, {
      author: subject,
      ...(groups && { groups }),
      statements: [...this.statements, ...(using?.extra ?? [])],
      roles: this.roles,
      ...(managers !== false && { managers }),
      now: () => this.time * 1000,
    });
  }

  apply(asker: Asker | string, change: Change, using?: CheckWith): this {
    this.check(asker, change, using);
    if (change.action === "define") {
      const home = change.role.home ?? "/";
      this.roles = this.roles.filter(
        (role) => !(role.name === change.role.name && (role.home ?? "/") === home),
      );
      this.roles.push(change.role);
      return this;
    }
    const same = identity(change.statement);
    this.statements = this.statements.filter((statement) => identity(statement) !== same);
    if (change.action === "place") this.statements.push(change.statement);
    return this;
  }

  /** The reasons of the refusal, failing the test when the change is accepted or refused otherwise. */
  reasons(asker: Asker | string, change: Change, using?: CheckWith): string[] {
    const error = refused(() => this.check(asker, change, using));
    if (error.code !== "ERR_AUTHZ_CHANGE_REFUSED" || error.status !== 403) throw error;
    const cause = error.cause as { reasons: string[] };
    return cause.reasons;
  }

  /** The error a change is refused with, whatever its code. */
  error(asker: Asker | string, change: Change, using?: CheckWith): UnauthError {
    return refused(() => this.check(asker, change, using));
  }

  accepts(asker: Asker | string, change: Change, using?: CheckWith): boolean {
    try {
      this.check(asker, change, using);
      return true;
    } catch (error) {
      if (error instanceof UnauthError && error.code === "ERR_AUTHZ_CHANGE_REFUSED") return false;
      throw error;
    }
  }
}

export const place = (statement: Statement): Change => ({ action: "place", statement });
export const remove = (statement: Statement): Change => ({ action: "remove", statement });
export const define = (role: StoredRole): Change => ({ action: "define", role });

export function allow(subject: string, value: string, at?: string, expiresAt?: number): Statement {
  return make("allow", subject, value, at, expiresAt);
}
export function assign(subject: string, value: string, at?: string, expiresAt?: number): Statement {
  return make("assign", subject, value, at, expiresAt);
}
export function deny(subject: string, value: string, at?: string, expiresAt?: number): Statement {
  return make("deny", subject, value, at, expiresAt);
}
export function exclude(
  subject: string,
  value: string,
  at?: string,
  expiresAt?: number,
): Statement {
  return make("exclude", subject, value, at, expiresAt);
}

function make(
  kind: Statement["kind"],
  subject: string,
  value: string,
  at: string | undefined,
  expiresAt: number | undefined,
): Statement {
  return {
    kind,
    subject,
    value,
    ...(at !== undefined && { place: at }),
    ...(expiresAt !== undefined && { expiresAt }),
  };
}

function identity(statement: Statement): string {
  return JSON.stringify([
    statement.kind,
    statement.subject,
    statement.value,
    statement.place ?? "/",
  ]);
}
