/** Catalog data checked for shape: the members the model defines, lists of strings, nothing else. */
export interface PlainCatalogData {
  readonly permissions: readonly string[];
  readonly implies?: Readonly<Record<string, readonly string[]>>;
  readonly presets?: Readonly<Record<string, readonly string[]>>;
  readonly places?: false | Readonly<Record<string, readonly string[]>>;
}

/**
 * What a role resolves to: `gives`, the concrete permissions it gives (the model's `P`), and
 * `withholds`, what it still forbids to the roles that reference it (`E`). Only resolution reads
 * `withholds`: everything else reads `gives`.
 */
export interface ResolvedRole {
  readonly gives: ReadonlySet<string>;
  readonly withholds: ReadonlySet<string>;
}

/**
 * What a catalog says about places: `open`, nothing, so every canonical key fits; `none`, no
 * places, so only the root fits; `declared`, a structure, where `under` maps `"/"` or a level to
 * the levels that may sit directly under it and `anywhere` holds the levels that may sit under the
 * root and under every level.
 */
export type Structure =
  | { readonly kind: "open" }
  | { readonly kind: "none" }
  | {
      readonly kind: "declared";
      readonly levels: ReadonlySet<string>;
      readonly under: ReadonlyMap<string, ReadonlySet<string>>;
      readonly anywhere: ReadonlySet<string>;
    };

/**
 * A catalog checked and compiled: every lookup the engine makes, precomputed. Every set and map
 * is shared, never to be mutated.
 */
export interface CompiledCatalog {
  readonly fingerprint: string;
  /** Every declared permission. */
  readonly permissions: ReadonlySet<string>;
  /** The declared permissions by resource, for `resource:*`. */
  readonly byResource: ReadonlyMap<string, ReadonlySet<string>>;
  /** The declared permissions by action, for `*:action`. */
  readonly byAction: ReadonlyMap<string, ReadonlySet<string>>;
  /** For each declared permission that implies any, every permission it implies, transitively, itself left out. */
  readonly implies: ReadonlyMap<string, ReadonlySet<string>>;
  /** For each declared permission implied by any, every permission that implies it, transitively, itself left out. */
  readonly impliedBy: ReadonlyMap<string, ReadonlySet<string>>;
  /** Every preset, resolved. */
  readonly presets: ReadonlyMap<string, ResolvedRole>;
  readonly structure: Structure;
}
