import type { CatalogData } from "../../catalog.ts";
import type { StoredRole } from "../../types.ts";

/** How deep the deep cases reference: well past where a recursive engine overflows its stack. */
export const DEPTH = 5000;

/**
 * How long the implication chain is. An engine may hold what every permission implies, which grows
 * with the square of the chain, so this one stays shorter.
 */
export const IMPLIED = 1500;

/** The name of the role at `index` of a chain or a ring. */
export function link(index: number): string {
  return `link${index}`;
}

/** The permission at `index` of an implication chain. */
export function step(index: number): string {
  return `step${index}:run`;
}

/** `link0` names `link1`, and so on, the last naming `last`. */
export function storedChain(depth: number, last: string): StoredRole[] {
  return Array.from({ length: depth }, (_, index) => ({
    name: link(index),
    entries: [index === depth - 1 ? last : link(index + 1)],
  }));
}

/** `link0` names `link1`, and so on, the last naming `link0`. */
export function storedRing(depth: number): StoredRole[] {
  return Array.from({ length: depth }, (_, index) => ({
    name: link(index),
    entries: [link((index + 1) % depth)],
  }));
}

/** Presets `link0` to the last, each naming the next, the last naming `last`. */
export function presetChain(depth: number, last: string): Record<string, string[]> {
  return Object.fromEntries(storedChain(depth, last).map((role) => [role.name, [...role.entries]]));
}

/** Permissions `step0:run` to the last, each implying the next. */
export function implicationChain(depth: number): Pick<CatalogData, "permissions" | "implies"> {
  const permissions = Array.from({ length: depth }, (_, index) => step(index));
  const implies = Object.fromEntries(
    permissions.slice(0, -1).map((permission, index) => [permission, [step(index + 1)]]),
  );
  return { permissions, implies };
}
