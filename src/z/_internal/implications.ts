import { catalogInvalid } from "./errors.ts";

/** Both directions of the transitive closure of the implications, each permission left out of its own sets. */
export interface ImplicationClosure {
  implies: Map<string, Set<string>>;
  impliedBy: Map<string, Set<string>>;
}

/**
 * Closes the direct implications, declared and checked already, both ways, depth first on an
 * explicit stack, so no length of a chain exhausts the call stack. A cycle, a permission implying
 * itself included, is `ERR_AUTHZ_CATALOG_INVALID`: two permissions that imply each other are one
 * permission. The closure itself grows with the square of a chain's length.
 */
export function closeImplications(
  direct: ReadonlyMap<string, ReadonlySet<string>>,
): ImplicationClosure {
  const implies = new Map<string, Set<string>>();
  const visiting = new Set<string>();
  const frames: ClosureFrame[] = [];
  const open = (permission: string) => {
    visiting.add(permission);
    frames.push({
      permission,
      closure: new Set(),
      next: [...(direct.get(permission) ?? [])],
      index: 0,
    });
  };
  for (const start of direct.keys()) {
    if (!implies.has(start)) open(start);
    for (let frame = frames.at(-1); frame; frame = frames.at(-1)) {
      const next = frame.next[frame.index];
      if (next === undefined) {
        frames.pop();
        visiting.delete(frame.permission);
        implies.set(frame.permission, frame.closure);
        const parent = frames.at(-1);
        if (parent) for (const further of frame.closure) parent.closure.add(further);
        continue;
      }
      frame.index++;
      frame.closure.add(next);
      const known = implies.get(next);
      if (known) {
        for (const further of known) frame.closure.add(further);
        continue;
      }
      if (visiting.has(next)) {
        throw catalogInvalid("The catalog's implications form a cycle.", {
          reason: "cycle",
          at: "implies",
          value: next,
        });
      }
      open(next);
    }
  }

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

interface ClosureFrame {
  readonly permission: string;
  readonly closure: Set<string>;
  readonly next: readonly string[];
  index: number;
}
