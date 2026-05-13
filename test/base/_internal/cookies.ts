/**
 * Framework-agnostic cookie helpers shared by every adapter test suite
 * under `test/base/<adapter>/`.
 */

/**
 * In-memory cookie jar that mirrors browser behavior for cross-request tests:
 * apply each response's `Set-Cookie` via `update()`, then read the joined
 * `Cookie` header back via `toString()`.
 *
 * Cookies with `Max-Age=0` (or negative) are treated as a delete instruction
 * and removed from the jar.
 */
export function cookieJar() {
  const jar: Record<string, string> = {};

  return {
    update(headers: Headers) {
      for (const sc of headers.getSetCookie()) {
        const parts = sc.split(";").map((p) => p.trim());
        const nameValue = parts[0]!;
        const eqIdx = nameValue.indexOf("=");
        const name = nameValue.slice(0, eqIdx).trim();
        const value = nameValue.slice(eqIdx + 1);

        const isExpired = parts.some(
          (p) => p.toLowerCase().startsWith("max-age=0") || p.toLowerCase().startsWith("max-age=-"),
        );

        if (isExpired) {
          delete jar[name];
        } else {
          jar[name] = value;
        }
      }
    },
    toString(): string {
      return Object.entries(jar)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");
    },
  };
}

/** Extracts a single cookie value by name from a `Set-Cookie` response header. */
export function parseCookie(headers: Headers, name: string): string | undefined {
  const setCookie = headers.get("set-cookie");

  const regex = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`);
  const match = setCookie?.match(regex);

  return match ? match[1] : undefined;
}
