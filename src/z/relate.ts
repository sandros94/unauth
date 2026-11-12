import { compiledOf } from "./_internal/compile.ts";
import { sortedUnique } from "./_internal/grammar.ts";
import {
  assertQuestionPermission,
  blocking,
  down,
  spellings,
  wanted,
} from "./_internal/permissions.ts";
import type { Catalog } from "./catalog.ts";

/** The values a stored statement, or an entry of grants, must carry to bear on a question about one permission. */
export interface RelatedValues {
  /** The values of an allow that can give it. */
  allow: string[];
  /** The values of a deny that can block it. */
  deny: string[];
  /** The values of an exclusion that can take it out. */
  exclude: string[];
  /** The presets whose assignment can give it. An assignment of a stored role always relates: only its definition tells. */
  presets: string[];
}

/**
 * Names what can change the answer to a question about `permission`, as plain values for the
 * application's own query. A read that returns only the allows, denies and exclusions carrying
 * them, the assignments of these presets and every assignment of a stored role, answers as the
 * whole would. The same names are the entries of grants a read looks up, with every stored role
 * of `sr`, except that grants holding `pm` name a permission by its position there. Under a
 * catalog other than the one of issue, a copy of a preset gives what it gave at issue, so every
 * copy of `ps` is looked up too.
 *
 * @throws what a question about `permission` throws: `ERR_AUTHZ_MALFORMED`,
 * `ERR_AUTHZ_QUESTION_INVALID` for a wildcard, `ERR_AUTHZ_PERMISSION_UNKNOWN`.
 *
 * @example
 * const { allow, deny, exclude, presets } = relatedValues(catalog, "report:write");
 * // WHERE (kind = 'allow' AND value IN (...allow)) OR (kind = 'deny' AND value IN (...deny)) OR ...
 */
export function relatedValues<TPermission extends string>(
  catalog: Catalog<TPermission>,
  permission: NoInfer<TPermission>,
): RelatedValues {
  const compiled = compiledOf(catalog);
  const asked = assertQuestionPermission(compiled, permission);
  const satisfying = wanted(compiled, asked);
  const presets: string[] = [];
  for (const [name, role] of compiled.presets) {
    for (const given of role.gives) {
      if (satisfying.has(given)) {
        presets.push(name);
        break;
      }
    }
  }
  return {
    allow: spelled(satisfying),
    deny: spelled(blocking(compiled, asked)),
    exclude: spelled(down(compiled, asked)),
    presets: sortedUnique(presets),
  };
}

function spelled(permissions: Iterable<string>): string[] {
  const values: string[] = [];
  for (const permission of permissions) values.push(...spellings(permission));
  return sortedUnique(values);
}
