import { type RequestEvent, defineEventHandler } from "nuxt/server";

declare module "nuxt/schema" {
  interface RequestEventContext {
    transaction?: Transaction;
  }
}

export function withTransaction<T>(
  event: RequestEvent,
  fn: (tx: Transaction) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    event.context.transaction = tx;
    try {
      return await fn(tx);
    } finally {
      delete event.context.transaction;
    }
  });
}

export function defineTransactionalHandler<T>(
  handler: (event: RequestEvent, tx: Transaction) => Promise<T>,
): ReturnType<typeof defineEventHandler<Promise<T>>> {
  return defineEventHandler((event) => withTransaction(event, (tx) => handler(event, tx)));
}
