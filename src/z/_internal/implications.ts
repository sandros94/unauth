import { catalogInvalid } from "./errors.ts";

/** Both directions of the transitive closure of the implications, each permission left out of its own sets. */
export interface ImplicationClosure {
  implies: Map<string, Set<string>>;
  impliedBy: Map<string, Set<string>>;
}

/**
 * Closes the direct implications, declared and checked already, both ways. A cycle, a permission
 * implying itself included, is `ERR_AUTHZ_CATALOG_INVALID`: two permissions that imply each other
 * are one permission.
 */
export function closeImplications(
  direct: ReadonlyMap<string, ReadonlySet<string>>,
): ImplicationClosure {
  const implies = new Map<string, Set<string>>();
  const visiting = new Set<string>();
  const visit = (permission: string): Set<string> => {
    const known = implies.get(permission);
    if (known) return known;
    if (visiting.has(permission)) {
      throw catalogInvalid("The catalog's implications form a cycle.", {
        reason: "cycle",
        at: "implies",
        value: permission,
      });
    }
    visiting.add(permission);
    const closure = new Set<string>();
    for (const next of direct.get(permission) ?? []) {
      closure.add(next);
      for (const further of visit(next)) closure.add(further);
    }
    visiting.delete(permission);
    implies.set(permission, closure);
    return closure;
  };
  for (const permission of direct.keys()) visit(permission);

  const impliedBy = new Map<string, Set<string>>();
  for (const [above, below] of implies) {
    if (below.size === 0) implies.delete(above);
    for (const permission of below) {
      let set = impliedBy.get(permission);
      if (!set) impliedBy.set(permission, (set = new Set()));
      set.add(above);
    }
  }
  return { implies, impliedBy };
}
