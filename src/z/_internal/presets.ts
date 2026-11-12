import type { CompiledCatalog, ResolvedRole } from "./compiled.ts";
import { catalogInvalid } from "./errors.ts";
import { type EntryParts, isToken, readEntry } from "./grammar.ts";
import { expand } from "./permissions.ts";
import { type RoleWalk, isBreak, walkRoles } from "./roles.ts";

/**
 * Resolves the presets of catalog data, against `catalog`, whose permissions, implications and
 * structure are compiled already. `ERR_AUTHZ_CATALOG_INVALID` for a name that is not a token, an
 * entry that does not match its grammar, a permission or wildcard that matches no declared
 * permission, a role that is not a preset, and a cycle of references, `-role` included.
 */
export function resolvePresets(
  catalog: CompiledCatalog,
  presets: Readonly<Record<string, readonly string[]>> | undefined,
): Map<string, ResolvedRole> {
  const parsed = new Map<string, EntryParts[]>();
  for (const [name, entries] of Object.entries(presets ?? {})) {
    if (!isToken(name))
      throw invalid("The catalog names a preset that is not a token.", "token", name);
    parsed.set(
      name,
      entries.map((entry) => {
        const parts = readEntry(entry);
        if (!parts)
          throw invalid("A preset holds an entry that is not well formed.", "preset", entry, name);
        if (parts.kind === "pattern" && expand(catalog, parts.name).size === 0) {
          throw invalid(
            "A preset names a permission the catalog does not declare.",
            "preset",
            entry,
            name,
          );
        }
        return parts;
      }),
    );
  }

  const resolved = new Map<string, ResolvedRole>();
  const visiting = new Set<string>();
  const walk: RoleWalk<string> = {
    open: (name) => {
      visiting.add(name);
      return parsed.get(name) ?? [];
    },
    refer: (reference, name) => {
      if (!parsed.has(reference)) {
        throw invalid(
          "A preset references a role that is not a preset.",
          "preset",
          reference,
          name,
        );
      }
      if (visiting.has(reference)) {
        throw invalid(
          "The catalog's presets reference each other in a cycle.",
          "cycle",
          reference,
          name,
        );
      }
      return resolved.get(reference) ?? { descend: reference };
    },
    close: (name, result) => {
      visiting.delete(name);
      if (isBreak(result)) {
        throw invalid("A preset does not resolve.", "preset", result.reference, name);
      }
      resolved.set(name, result);
    },
  };
  for (const name of parsed.keys()) if (!resolved.has(name)) walkRoles(catalog, name, walk);
  return resolved;
}

function invalid(
  message: string,
  reason: "token" | "preset" | "cycle",
  value: string,
  preset?: string,
) {
  return catalogInvalid(message, {
    reason,
    at: preset === undefined ? "presets" : `presets.${preset}`,
    value,
  });
}
