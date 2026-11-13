import type { CompiledCatalog, Structure } from "./compiled.ts";
import { catalogInvalid, placeOutside } from "./errors.ts";
import { isToken } from "./grammar.ts";
import { assertKey, levelsOf } from "./keys.ts";

/**
 * Compiles the `places` member of catalog data, already checked for shape. A structure is refused
 * with `ERR_AUTHZ_CATALOG_INVALID` when it declares no level, names a parent or a level that is not
 * a token, or puts levels under a level no key from the root can reach.
 */
export function compileStructure(
  places: false | Readonly<Record<string, readonly string[]>> | undefined,
): Structure {
  if (places === undefined) return { kind: "open" };
  if (places === false) return { kind: "none" };
  const under = new Map<string, Set<string>>();
  const anywhere = new Set<string>();
  const levels = new Set<string>();
  for (const [parent, children] of Object.entries(places)) {
    if (parent !== "/" && parent !== "*" && !isToken(parent)) {
      throw catalogInvalid("The catalog names a level that is not a token.", {
        reason: "token",
        at: "places",
        value: parent,
      });
    }
    for (const child of children) {
      if (!isToken(child)) {
        throw catalogInvalid("The catalog names a level that is not a token.", {
          reason: "token",
          at: `places.${parent}`,
          value: child,
        });
      }
      levels.add(child);
    }
    if (parent === "*") for (const child of children) anywhere.add(child);
    else if (children.length > 0) under.set(parent, new Set(children));
  }
  if (levels.size === 0) {
    throw catalogInvalid("The catalog's places declare no level.", {
      reason: "places",
      at: "places",
    });
  }
  const reachable = reach(under, anywhere);
  for (const parent of under.keys()) {
    if (parent !== "/" && !reachable.has(parent)) {
      throw catalogInvalid("The catalog puts levels under a level that sits nowhere.", {
        reason: "places",
        at: `places.${parent}`,
        value: parent,
      });
    }
  }
  return { kind: "declared", levels, under, anywhere };
}

/**
 * Whether a canonical key fits the catalog: with a structure, each level is declared and may sit
 * under the one before it, the root for the first; with no places, only the root; else always.
 */
export function fits(catalog: CompiledCatalog, key: string): boolean {
  const structure = catalog.structure;
  if (structure.kind === "open") return true;
  if (structure.kind === "none") return key === "/";
  let parent = "/";
  for (const level of levelsOf(key)) {
    if (!structure.anywhere.has(level) && !structure.under.get(parent)?.has(level)) return false;
    parent = level;
  }
  return true;
}

/** `key` when it fits the catalog, else `ERR_AUTHZ_PLACE_OUTSIDE`. `key` must be canonical. */
export function assertFits(catalog: CompiledCatalog, key: string): string {
  if (!fits(catalog, key)) throw placeOutside(key);
  return key;
}

/**
 * The key of a place handed in, `"/"` when absent: `ERR_AUTHZ_MALFORMED` when not canonical,
 * `ERR_AUTHZ_PLACE_OUTSIDE` when it does not fit the catalog.
 */
export function checkPlace(catalog: CompiledCatalog, place: unknown): string {
  return assertFits(catalog, place === undefined ? "/" : assertKey(place));
}

function reach(
  under: ReadonlyMap<string, ReadonlySet<string>>,
  anywhere: ReadonlySet<string>,
): Set<string> {
  const seen = new Set<string>();
  const queue = ["/"];
  for (let next = queue.pop(); next !== undefined; next = queue.pop()) {
    for (const child of [...(under.get(next) ?? []), ...anywhere]) {
      if (!seen.has(child)) {
        seen.add(child);
        queue.push(child);
      }
    }
  }
  return seen;
}
