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
