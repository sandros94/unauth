import { bigint, index, jsonb, pgTable, primaryKey, text } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: text().primaryKey(),
  createdAt: bigint("created_at", { mode: "number" }).notNull(),
});

export const identities = pgTable(
  "identities",
  {
    provider: text().notNull(),
    subject: text().notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    name: text(),
    email: text(),
    linkedAt: bigint("linked_at", { mode: "number" }).notNull(),
  },
  (table) => [primaryKey({ columns: [table.provider, table.subject] })],
);

export const credentials = pgTable("credentials", {
  userId: text("user_id")
    .primaryKey()
    .references(() => users.id),
  passwordHash: text("password_hash").notNull(),
  updatedAt: bigint("updated_at", { mode: "number" }).notNull(),
});

export const sessions = pgTable(
  "sessions",
  {
    tokenHash: text("token_hash").primaryKey(),
    id: text().notNull().unique(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    data: jsonb().$type<SessionData>().notNull(),
    createdAt: bigint("created_at", { mode: "number" }).notNull(),
    updatedAt: bigint("updated_at", { mode: "number" }).notNull(),
    expiresAt: bigint("expires_at", { mode: "number" }),
  },
  (table) => [index("sessions_user_id").on(table.userId)],
);
