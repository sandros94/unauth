import { type RequestEvent, createError } from "nuxt/server";
import { and, eq } from "drizzle-orm";
import { argon2Hash, argon2NeedsRehash, argon2Verify } from "unauth/argon2";
import { credentials, identities, users } from "../db/schema";

export interface AccountIdentity {
  provider: string;
  subject: string;
  name?: string;
  email?: string;
}

export interface LinkedIdentity extends AccountIdentity {
  linkedAt: number;
}

export function findOrCreateUser(
  event: RequestEvent,
  identity: AccountIdentity,
): Promise<{ id: string }> {
  return useDB(event).transaction(async (tx) => {
    const owner = await ownerOf(tx, identity);
    if (owner !== undefined) return { id: owner };
    return createUser(tx, identity);
  });
}

export async function registerPassword(
  event: RequestEvent,
  username: string,
  password: string,
): Promise<{ id: string }> {
  const handle = useDB(event);
  const identity = { provider: "password", subject: username };
  if ((await ownerOf(handle, identity)) !== undefined) {
    throw createError({ statusCode: 409, message: "This user is already registered" });
  }
  const passwordHash = await argon2Hash(password);
  return handle.transaction(async (tx) => {
    const user = await createUser(tx, identity);
    await storePasswordHash(tx, user.id, passwordHash);
    return user;
  });
}

export async function verifyPassword(
  event: RequestEvent,
  username: string,
  password: string,
): Promise<{ id: string } | undefined> {
  const handle = useDB(event);
  const identity = await handle.query.identities.findFirst({
    where: { provider: "password", subject: username },
    columns: { userId: true },
    with: { user: { columns: {}, with: { credentials: { columns: { passwordHash: true } } } } },
  });
  const credential = identity?.user.credentials;
  if (!credential) {
    await argon2Verify(await dummyHash(), password);
    return undefined;
  }
  if (!(await argon2Verify(credential.passwordHash, password))) return undefined;
  if (argon2NeedsRehash(credential.passwordHash)) {
    await storePasswordHash(handle, identity.userId, await argon2Hash(password));
  }
  return { id: identity.userId };
}

export async function linkIdentity(
  event: RequestEvent,
  userId: string,
  identity: AccountIdentity,
): Promise<void> {
  const handle = useDB(event);
  const owner = await ownerOf(handle, identity);
  if (owner === userId) return;
  if (owner !== undefined) {
    throw createError({ statusCode: 409, message: "This account is linked to another user" });
  }
  await insertIdentity(handle, userId, identity, Date.now());
}

export async function unlinkIdentity(
  event: RequestEvent,
  sessionKey: string,
  identity: Pick<AccountIdentity, "provider" | "subject">,
): Promise<string> {
  const handle = useDB(event);
  const owned = await handle.query.identities.findFirst({
    where: {
      provider: identity.provider,
      subject: identity.subject,
      user: {
        sessions: {
          tokenHash: sessionKey,
          OR: [{ expiresAt: { gt: Date.now() } }, { expiresAt: { isNull: true } }],
        },
      },
    },
    columns: { userId: true },
    with: { user: { columns: {}, with: { identities: { columns: { provider: true } } } } },
  });
  if (!owned) {
    throw createError({ statusCode: 404, message: "This account is not linked to you" });
  }
  if (owned.user.identities.length <= 1) {
    throw createError({
      statusCode: 409,
      message: "This is the last account you can sign in with",
    });
  }
  await handle
    .delete(identities)
    .where(
      and(
        eq(identities.provider, identity.provider),
        eq(identities.subject, identity.subject),
        eq(identities.userId, owned.userId),
      ),
    );
  if (identity.provider === "password") {
    await handle.delete(credentials).where(eq(credentials.userId, owned.userId));
  }
  return owned.userId;
}

export async function deleteUser(event: RequestEvent, userId: string): Promise<void> {
  const handle = useDB(event);
  await handle.delete(credentials).where(eq(credentials.userId, userId));
  await handle.delete(identities).where(eq(identities.userId, userId));
  await handle.delete(users).where(eq(users.id, userId));
}

export async function listIdentities(
  event: RequestEvent,
  userId: string,
): Promise<LinkedIdentity[]> {
  const rows = await useDB(event).query.identities.findMany({
    where: { userId },
    columns: { provider: true, subject: true, name: true, email: true, linkedAt: true },
    orderBy: { linkedAt: "asc" },
  });
  return rows.map((row) => ({
    provider: row.provider,
    subject: row.subject,
    ...(row.name === null ? {} : { name: row.name }),
    ...(row.email === null ? {} : { email: row.email }),
    linkedAt: row.linkedAt,
  }));
}

let dummy: Promise<string> | undefined;

function dummyHash(): Promise<string> {
  return (dummy ??= argon2Hash(crypto.randomUUID()));
}

async function ownerOf(
  db: Db,
  identity: Pick<AccountIdentity, "provider" | "subject">,
): Promise<string | undefined> {
  const row = await db.query.identities.findFirst({
    where: { provider: identity.provider, subject: identity.subject },
    columns: { userId: true },
  });
  return row?.userId;
}

async function createUser(db: Db, identity: AccountIdentity): Promise<{ id: string }> {
  const id = crypto.randomUUID();
  const now = Date.now();
  await db.insert(users).values({ id, createdAt: now });
  await insertIdentity(db, id, identity, now);
  return { id };
}

async function storePasswordHash(db: Db, userId: string, passwordHash: string): Promise<void> {
  const updatedAt = Date.now();
  await db
    .insert(credentials)
    .values({ userId, passwordHash, updatedAt })
    .onConflictDoUpdate({ target: credentials.userId, set: { passwordHash, updatedAt } });
}

async function insertIdentity(
  db: Db,
  userId: string,
  identity: AccountIdentity,
  now: number,
): Promise<void> {
  await db.insert(identities).values({
    provider: identity.provider,
    subject: identity.subject,
    userId,
    name: identity.name ?? null,
    email: identity.email ?? null,
    linkedAt: now,
  });
}
