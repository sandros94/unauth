import { defineRelations } from "drizzle-orm";
import * as schema from "./schema";

export const relations = defineRelations(schema, (r) => ({
  users: {
    identities: r.many.identities(),
    credentials: r.one.credentials({ from: r.users.id, to: r.credentials.userId, optional: true }),
    sessions: r.many.sessions(),
  },
  identities: {
    user: r.one.users({ from: r.identities.userId, to: r.users.id, optional: false }),
  },
  credentials: {
    user: r.one.users({ from: r.credentials.userId, to: r.users.id, optional: false }),
  },
  sessions: {
    user: r.one.users({ from: r.sessions.userId, to: r.users.id, optional: false }),
  },
}));

export type Relations = typeof relations;
