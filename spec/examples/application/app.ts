import type { DatabaseSync } from "node:sqlite";
import { H3 } from "h3";
import { authzHttpError } from "./http.ts";
import type { GrantsOf } from "./session.ts";

export function createApp(db: DatabaseSync, grantsOf?: GrantsOf): H3 {
  return new H3({
    onRequest: (event) => {
      event.context.db = db;
      event.context.grantsOf = grantsOf;
    },
  }).use(async (_event, next) => {
    try {
      return await next();
    } catch (error) {
      throw authzHttpError(error);
    }
  });
}
