export type MaybePromise<T> = T | Promise<T>;

export type MaybeArray<T> = T | T[];

export type ParseType<T> = {
  [K in keyof T]: T[K];
} & {};

export type ReadonlyDeep<T> = ParseType<{
  readonly [K in keyof T]: T[K] extends object ? ReadonlyDeep<T[K]> : T[K];
}>;

export type PartialDeep<T> = ParseType<{
  [K in keyof T]?: PartialDeep<T[K]>;
}>;

export type RequiredDeep<T> = ParseType<{
  [K in keyof T]-?: RequiredDeep<T[K]>;
}>;

export type DotPathKeys<T> =
  T extends Array<any>
    ? never
    : T extends object
      ? {
          [K in keyof T & string]: NonNullable<T[K]> extends Record<string, any>
            ? K | `${K}.${DotPathKeys<T[K]>}`
            : K;
        }[keyof T & string]
      : never;

export type DotPathValue<
  T,
  P extends DotPathKeys<T> | (string & {}),
> = P extends `${infer K}.${infer Rest}`
  ? K extends keyof T
    ? DotPathValue<NonNullable<T[K]>, Rest>
    : never
  : P extends keyof T
    ? T[P]
    : never;

type UnionToIntersection<U> = (U extends any ? (k: U) => void : never) extends (
  k: infer I,
) => void
  ? I
  : never;

type PathToObject<
  Path extends string,
  V,
  Optional extends boolean = false,
> = Path extends `${infer Head}.${infer Tail}`
  ? Optional extends true
    ? ParseType<{ [K in Head]?: PathToObject<Tail, V, Optional> }>
    : ParseType<{
        [K in Head]: Exclude<PathToObject<Tail, V, Optional>, undefined>;
      }>
  : Optional extends true
    ? { [K in Path]?: V }
    : { [K in Path]: Exclude<V, undefined> };

type RemoveAtPath<
  T extends object,
  P extends string,
> = P extends `${infer Head}.${infer Tail}`
  ? Head extends keyof T
    ? ParseType<{
        [K in keyof T]: K extends Head ? RemoveAtPath<T[K] & {}, Tail> : T[K];
      }>
    : T
  : P extends keyof T
    ? ParseType<Omit<T, P>>
    : T;

export type Require<T extends object, P extends DotPathKeys<T>> = ParseType<
  UnionToIntersection<PathToObject<P, DotPathValue<T, P>> & RemoveAtPath<T, P>>
>;

export type Optional<T extends object, P extends DotPathKeys<T>> = ParseType<
  UnionToIntersection<
    RemoveAtPath<T, P> & PathToObject<P, DotPathValue<T, P>, true>
  >
>;
