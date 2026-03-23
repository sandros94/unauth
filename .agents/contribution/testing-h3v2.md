# Testing with h3v2

Common patterns for testing h3v2 applications with vitest.

## Basics

h3v2 exposes `app.request(url, init?)` — a built-in test interface that accepts the standard Fetch API `RequestInit`. No external test servers or adapters needed.

```ts
import { H3 } from "h3v2";

const app = new H3();
app.get("/", () => ({ hello: "world" }));

const res = await app.request("/");
// res is a standard Response object
const body = await res.json();
```

## Test structure

Use `beforeEach` to create a fresh `H3` instance per test. Define routes inside each test (or inside a shared setup within a `describe` block) to keep tests isolated.

```ts
import { describe, it, expect, beforeEach } from "vitest";
import { H3 } from "h3v2";

describe("my feature", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("returns 200", async () => {
    app.get("/", () => "ok");
    const res = await app.request("/");
    expect(res.status).toBe(200);
  });
});
```

## Making requests

`app.request()` accepts the same signature as `fetch()`:

```ts
// GET (default)
await app.request("/path");

// POST with JSON body
await app.request("/path", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ key: "value" }),
});

// Custom headers
await app.request("/path", {
  headers: {
    Authorization: "Bearer token",
    Cookie: "session=abc123",
  },
});
```

## Reading responses

The response is a standard `Response` object:

```ts
const res = await app.request("/");

res.status; // HTTP status code
res.headers; // Headers object
await res.json(); // parse JSON body
await res.text(); // raw text body
```

## Cookies

### Parsing a single cookie from response

For simple cases (e.g., CSRF tokens), parse from the `set-cookie` header:

```ts
function parseCookie(headers: Headers, name: string): string | undefined {
  const setCookie = headers.get("set-cookie");
  const regex = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`);
  const match = setCookie?.match(regex);
  return match ? match[1] : undefined;
}

const res = await app.request("/");
const token = parseCookie(res.headers, "csrf");
```

### Tracking cookies across requests (cookie jar)

For stateful flows (sessions, auth), use a cookie jar that tracks `Set-Cookie` headers and replays them:

```ts
function cookieJar() {
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
```

Usage:

```ts
const jar = cookieJar();

// Request that sets a cookie
const res1 = await app.request("/login", { method: "POST" });
jar.update(res1.headers);

// Subsequent request carries the cookie
const res2 = await app.request("/me", {
  headers: { Cookie: jar.toString() },
});
jar.update(res2.headers); // always update after response

// After a clear/logout, the jar removes expired cookies
const res3 = await app.request("/logout", {
  method: "POST",
  headers: { Cookie: jar.toString() },
});
jar.update(res3.headers);
```

**Note:** `headers.getSetCookie()` is a standard Web API available in Node.js ≥20. It returns an array of individual `Set-Cookie` header values (unlike `headers.get("set-cookie")` which joins them).

### Cookie `Secure` flag in tests

h3v2's `app.request()` does not enforce HTTPS. However, cookie libraries may still set `Secure` on cookies. In test configs, override with `{ secure: false }` to ensure cookies are sent back through the jar.

## Middleware

Register per-route middleware via the `middleware` option:

```ts
app.get("/protected", (event) => ({ ok: true }), { middleware: [myMiddleware] });
```

Test that middleware blocks/allows correctly:

```ts
it("returns 401 without auth", async () => {
  app.get("/me", () => "ok", { middleware: [requireAuth] });
  const res = await app.request("/me");
  expect(res.status).toBe(401);
});
```

## Errors

h3v2 catches `HTTPError` thrown in handlers/middleware and returns the corresponding status code:

```ts
import { HTTPError } from "h3v2";

app.get("/fail", () => {
  throw new HTTPError("Not Found", { status: 404 });
});

const res = await app.request("/fail");
expect(res.status).toBe(404);
```

In tests, import `HTTPError` from `h3v2` directly (static import is fine in test files since h3v2 is a dev dependency).

## Fake timers

For time-sensitive features (JWT expiry, session refresh thresholds), use vitest's fake timers:

```ts
import { vi, afterEach } from "vitest";

afterEach(() => {
  vi.useRealTimers();
});

it("expires after maxAge", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

  // ... create session ...

  // Advance time past expiry
  vi.setSystemTime(new Date("2026-01-01T02:00:00Z"));

  // ... verify session is expired ...
});
```

**Important:** Always restore real timers in `afterEach` to avoid leaking fake timer state across tests.

When testing refresh/rotation that issues new cookies:

1. Set initial time, create the session, capture cookies
2. Advance time past the threshold
3. Make a request (triggers refresh), update the cookie jar
4. Optionally advance time slightly past the refresh point (avoid double-refresh)
5. Make another request with the refreshed cookies to verify new state

```ts
vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
// ... login, jar.update() ...

vi.setSystemTime(new Date("2026-01-01T00:31:00Z")); // past threshold
const refreshRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
jar.update(refreshRes.headers); // capture refreshed cookie

vi.setSystemTime(new Date("2026-01-01T00:31:01Z")); // tiny advance
const afterRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
// afterRes now reflects the refreshed session
```

## Spying on hooks

Use `vi.fn()` to verify hook invocations:

```ts
const onUpdate = vi.fn();

// Pass spy as hook
const useSession = defineSession({
  hooks: { onUpdate },
  // ...
});

// ... make requests ...

expect(onUpdate).toHaveBeenCalledTimes(1);
expect(onUpdate.mock.calls[0]![0]).toHaveProperty("session");
```

For hooks that should NOT fire, use `expect(...).not.toHaveBeenCalled()`.

To reset spy state mid-test (e.g., after a setup phase):

```ts
onRead.mockClear();
// subsequent assertions only count calls after this point
```
