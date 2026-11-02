/**
 * In-memory cookie jar mirroring a browser across requests: apply each response's `Set-Cookie`
 * with `update()`, then read the joined `Cookie` header back with `toString()`. A `Max-Age=0`
 * (or negative) line deletes its cookie.
 */
export interface CookieJar {
  update: (headers: Headers) => void;
  toString: () => string;
}

export function cookieJar(): CookieJar {
  const jar: Record<string, string> = {};

  return {
    update(headers) {
      for (const line of headers.getSetCookie()) {
        const parts = line.split(";").map((part) => part.trim());
        const nameValue = parts[0]!;
        const eq = nameValue.indexOf("=");
        const name = nameValue.slice(0, eq).trim();
        const value = nameValue.slice(eq + 1);
        const expired = parts.some((part) => /^max-age=(0|-)/i.test(part));
        if (expired) delete jar[name];
        else jar[name] = value;
      }
    },
    toString() {
      return Object.entries(jar)
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    },
  };
}
