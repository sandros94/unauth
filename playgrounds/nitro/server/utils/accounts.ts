import { HTTPError } from "nitro";
import { useDatabase } from "nitro/database";
import { argon2Hash, argon2NeedsRehash, argon2Verify } from "unauth/argon2";

export interface AccountIdentity {
  provider: string;
  subject: string;
  name?: string;
  email?: string;
}

export interface LinkedIdentity extends AccountIdentity {
  linkedAt: number;
}

export async function findOrCreateUser(identity: AccountIdentity): Promise<{ id: string }> {
  // A real application runs this read-then-insert in a transaction.
  const owner = await ownerOf(identity);
  if (owner !== undefined) return { id: owner };
  return createUser(identity);
}

export async function registerPassword(
  username: string,
  password: string,
): Promise<{ id: string }> {
  const identity = { provider: "password", subject: username };
  if ((await ownerOf(identity)) !== undefined) {
    throw new HTTPError({ status: 409, message: "This user is already registered" });
  }
  const passwordHash = await argon2Hash(password);
  const user = await createUser(identity);
  await storePasswordHash(user.id, passwordHash);
  return user;
}

export async function verifyPassword(
  username: string,
  password: string,
): Promise<{ id: string } | undefined> {
  const db = await useAccounts();
  const { rows } = await db.sql<{
    rows: { user_id: string; password_hash: string }[];
  }>`SELECT credentials.user_id, credentials.password_hash FROM identities JOIN credentials ON credentials.user_id = identities.user_id WHERE identities.provider = 'password' AND identities.subject = ${username}`;
  const credential = rows[0];
  if (credential === undefined) {
    await argon2Verify(dummyHash, password);
    return undefined;
  }
  if (!(await argon2Verify(credential.password_hash, password))) return undefined;
  if (argon2NeedsRehash(credential.password_hash)) {
    await storePasswordHash(credential.user_id, await argon2Hash(password));
  }
  return { id: credential.user_id };
}

export async function linkIdentity(userId: string, identity: AccountIdentity): Promise<void> {
  const owner = await ownerOf(identity);
  if (owner === userId) return;
  if (owner !== undefined) {
    throw new HTTPError({ status: 409, message: "This account belongs to another user" });
  }
  await insertIdentity(userId, identity, Date.now());
}

export async function unlinkIdentity(
  userId: string,
  identity: Pick<AccountIdentity, "provider" | "subject">,
): Promise<void> {
  if ((await ownerOf(identity)) !== userId) {
    throw new HTTPError({ status: 404, message: "This account is not linked to you" });
  }
  const db = await useAccounts();
  const { rows } = await db.sql<{
    rows: { count: number }[];
  }>`SELECT COUNT(*) AS count FROM identities WHERE user_id = ${userId}`;
  if (rows[0].count <= 1) {
    throw new HTTPError({ status: 409, message: "This is the last account you can sign in with" });
  }
  await db.sql`DELETE FROM identities WHERE provider = ${identity.provider} AND subject = ${identity.subject} AND user_id = ${userId}`;
  if (identity.provider === "password") {
    await db.sql`DELETE FROM credentials WHERE user_id = ${userId}`;
  }
}

export async function deleteUser(userId: string): Promise<void> {
  const db = await useAccounts();
  await db.sql`DELETE FROM credentials WHERE user_id = ${userId}`;
  await db.sql`DELETE FROM identities WHERE user_id = ${userId}`;
  await db.sql`DELETE FROM users WHERE id = ${userId}`;
}

export async function listIdentities(userId: string): Promise<LinkedIdentity[]> {
  const db = await useAccounts();
  const { rows } = await db.sql<{
    rows: IdentityRow[];
  }>`SELECT provider, subject, name, email, linked_at FROM identities WHERE user_id = ${userId} ORDER BY linked_at`;
  return rows.map((row) => ({
    provider: row.provider,
    subject: row.subject,
    ...(row.name === null ? {} : { name: row.name }),
    ...(row.email === null ? {} : { email: row.email }),
    linkedAt: row.linked_at,
  }));
}

interface IdentityRow {
  provider: string;
  subject: string;
  name: string | null;
  email: string | null;
  linked_at: number;
}

let dummyHash = "";

let accounts: ReturnType<typeof setUp> | undefined;

function useAccounts(): ReturnType<typeof setUp> {
  return (accounts ??= setUp());
}

async function setUp() {
  const db = useDatabase();
  const [hash] = await Promise.all([
    argon2Hash(crypto.randomUUID()),
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS identities (
        provider TEXT NOT NULL,
        subject TEXT NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id),
        name TEXT,
        email TEXT,
        linked_at INTEGER NOT NULL,
        PRIMARY KEY (provider, subject)
      );
      CREATE TABLE IF NOT EXISTS credentials (
        user_id TEXT PRIMARY KEY REFERENCES users(id),
        password_hash TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `),
  ]);
  dummyHash = hash;
  return db;
}

async function ownerOf(identity: AccountIdentity): Promise<string | undefined> {
  const db = await useAccounts();
  const { rows } = await db.sql<{
    rows: { user_id: string }[];
  }>`SELECT user_id FROM identities WHERE provider = ${identity.provider} AND subject = ${identity.subject}`;
  return rows[0]?.user_id;
}

async function createUser(identity: AccountIdentity): Promise<{ id: string }> {
  const db = await useAccounts();
  const id = crypto.randomUUID();
  const now = Date.now();
  await db.sql`INSERT INTO users (id, created_at) VALUES (${id}, ${now})`;
  await insertIdentity(id, identity, now);
  return { id };
}

async function storePasswordHash(userId: string, passwordHash: string) {
  const db = await useAccounts();
  await db.sql`INSERT INTO credentials (user_id, password_hash, updated_at) VALUES (${userId}, ${passwordHash}, ${Date.now()}) ON CONFLICT (user_id) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at`;
}

async function insertIdentity(userId: string, identity: AccountIdentity, now: number) {
  const db = await useAccounts();
  await db.sql`INSERT INTO identities (provider, subject, user_id, name, email, linked_at) VALUES (${identity.provider}, ${identity.subject}, ${userId}, ${identity.name ?? null}, ${identity.email ?? null}, ${now})`;
}
