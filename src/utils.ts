import type { ReadonlyDeep } from "./types";

export {
  deriveJWKFromPassword,
  generateJWK,
  importJWKFromPEM,
} from "unjwt/jwk";

export function deepFreeze<T extends object>(object: T): ReadonlyDeep<T> {
  const propertyNames = Object.getOwnPropertyNames(object);
  for (const name of propertyNames) {
    const value = object[name as keyof T];
    if (value && typeof value === "object") {
      deepFreeze(value);
    }
  }
  return Object.freeze(object);
}
