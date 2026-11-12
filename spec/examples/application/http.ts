import { type H3Event, HTTPError } from "h3";
import { isUnauthError } from "unauth/error";
import type { ValidationIssue } from "unauth/z";

export type Body = Readonly<Record<string, unknown>>;

export function param(event: H3Event, name: string): string {
  const value = event.context.params?.[name];
  if (value === undefined) throw new HTTPError({ status: 404, message: "Not found." });
  return value;
}

export async function readBody(event: H3Event): Promise<Body> {
  const body: unknown = await event.req.json().catch(() => undefined);
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new HTTPError({ status: 400, message: "The body is not a JSON object." });
  }
  return Object.fromEntries(Object.entries(body));
}

export function textOf(body: Body, name: string): string {
  const value = body[name];
  if (typeof value !== "string") {
    throw new HTTPError({ status: 400, message: `The body needs a text "${name}".` });
  }
  return value;
}

export function flagOf(body: Body, name: string): boolean {
  const value = body[name];
  if (typeof value !== "boolean") {
    throw new HTTPError({ status: 400, message: `The body needs a boolean "${name}".` });
  }
  return value;
}

export function forbidden(message = "Not allowed."): HTTPError {
  return new HTTPError({ status: 403, message });
}

export function invalid(issues: readonly ValidationIssue[], message = "Not valid."): HTTPError {
  return new HTTPError({ status: 400, message, data: { issues } });
}

export function authzHttpError(error: unknown): unknown {
  if (!isUnauthError(error) || !error.code.startsWith("ERR_AUTHZ_")) return error;
  return new HTTPError({
    status: error.status ?? 500,
    message: error.message,
    data: { code: error.code, cause: error.cause },
  });
}
