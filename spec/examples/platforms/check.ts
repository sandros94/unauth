import type { Question } from "unauth/z";
import type * as Store from "../storage/ask.ts";
import { readForQuestion } from "../storage/statements.ts";

interface Mismatch {
  subject: string;
  question: Question;
  sql: boolean | undefined;
  ask: boolean;
}

let questions = 0;
const mismatches: Mismatch[] = [];

export function againstAsk(store: typeof Store): typeof Store {
  return {
    ...store,
    askInSql: (db, authz, asker, question, at) => {
      const sql = store.askInSql(db, authz, asker, question, at);
      const read = readForQuestion(db, authz, asker, question, at);
      const { allowed } = authz.ask(read, question, { now: () => at * 1000 });
      questions += 1;
      if (sql !== allowed) mismatches.push({ subject: asker.subject, question, sql, ask: allowed });
      return sql;
    },
  };
}

export function sqlAgreed(): void {
  const found = mismatches.splice(0);
  if (found.length > 0) {
    throw new Error(`The SQL answered otherwise than ask: ${JSON.stringify(found)}`);
  }
}

export function sqlReached(): void {
  if (questions === 0) throw new Error("No question reached the SQL.");
}
