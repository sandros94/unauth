import type { DatabaseSync } from "node:sqlite";
import type { H3Event } from "h3";
import type { Authz, Question } from "unauth/z";
import { askInSql } from "../storage/ask.ts";
import { type Asker, readForQuestion } from "../storage/statements.ts";
import { useDB } from "./db.ts";
import { forbidden } from "./http.ts";
import { type SignedIn, requireAuthSession } from "./session.ts";

export interface AskOptions {
  identifiers?: string;
}

export function allowed<TPermission extends string>(
  event: H3Event,
  authz: Authz<TPermission>,
  session: SignedIn,
  question: Question<NoInfer<TPermission>>,
  options: AskOptions = {},
): boolean {
  if (session.grants !== undefined) {
    const answer = authz.could(session.grants, question);
    if (answer.covered) return answer.allowed;
  }
  return askNow(useDB(event), authz, { ...options, subject: session.subject }, question);
}

export async function authorize<TPermission extends string>(
  event: H3Event,
  authz: Authz<TPermission>,
  question: Question<NoInfer<TPermission>>,
  options: AskOptions = {},
): Promise<SignedIn> {
  const session = await requireAuthSession(event, authz);
  if (!allowed(event, authz, session, question, options)) throw forbidden();
  return session;
}

export function gate<TPermission extends string>(
  db: DatabaseSync,
  authz: Authz<TPermission>,
  session: SignedIn,
  question: Question<NoInfer<TPermission>>,
  options: AskOptions = {},
): void {
  if (!askNow(db, authz, { ...options, subject: session.subject }, question)) throw forbidden();
}

export function askNow(db: DatabaseSync, authz: Authz, asker: Asker, question: Question): boolean {
  const now = Date.now();
  const at = Math.floor(now / 1000);
  const answer = askInSql(db, authz, asker, question, at);
  if (answer !== undefined) return answer;
  const read = readForQuestion(db, authz, asker, question, at);
  return authz.ask(read, question, { now: () => now }).allowed;
}
