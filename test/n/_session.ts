/**
 * Web-request helpers for the `unauth/n` session suites: a request carrying the cookies a previous
 * response set, the way a browser would send them back.
 */

/** A request to `https://app.test/` whose `Cookie` header replays `from`'s live `Set-Cookie` lines. */
export function requestWith(from?: Headers): Request {
  const cookie = from ? cookieHeader(from) : "";
  return new Request("https://app.test/", cookie ? { headers: { cookie } } : undefined);
}

/** The `name=value` pairs of `headers`' `Set-Cookie` lines, dropping expired ones. */
export function cookieHeader(headers: Headers): string {
  return headers
    .getSetCookie()
    .filter((line) => !isExpired(line))
    .map((line) => line.split(";", 1)[0])
    .join("; ");
}

/** Whether a `Set-Cookie` line deletes its cookie. */
export function isExpired(line: string): boolean {
  const attrs = line.toLowerCase();
  if (/;\s*max-age=(0|-)/.test(attrs)) return true;
  const expires = /;\s*expires=([^;]+)/.exec(attrs)?.[1];
  return expires !== undefined && Date.parse(expires) <= Date.now();
}

/** The `Set-Cookie` line for cookie `name`, if the response wrote one. */
export function setCookieLine(headers: Headers, name: string): string | undefined {
  return headers.getSetCookie().find((line) => line.startsWith(`${name}=`));
}

/**
 * A form submitted on the application's own pages: a `POST` to `url` whose `Origin` is `url`'s,
 * the shape a start that links an account or names the account must have.
 */
export function formStart(url: string | URL, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  headers.set("origin", new URL(url).origin);
  return new Request(url, { ...init, method: "POST", headers });
}
