import { describe, it, expect, beforeEach } from "vitest";
import { H3 } from "h3";

import { defineCsrf } from "../../src/base/h3/csrf.ts";

function parseCookie(headers: Headers, name: string): string | undefined {
  const setCookie = headers.get("set-cookie");

  const regex = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`);
  const match = setCookie?.match(regex);

  return match ? match[1] : undefined;
}

describe("defineCsrf", () => {
  let app: H3;
  const csrf = defineCsrf({
    secret: "test-secret",
    cookie: { secure: false },
  });

  beforeEach(() => {
    app = new H3();
  });

  it("sets CSRF cookie on safe methods", async () => {
    app.get("/", () => ({ ok: true }), { middleware: [csrf] });

    const res = await app.request("/");
    const token = parseCookie(res.headers, "csrf");
    expect(token).toBeTypeOf("string");
    expect(token!.length).toBeGreaterThan(0);
  });

  it("does not overwrite existing CSRF cookie", async () => {
    app.get("/", () => ({ ok: true }), { middleware: [csrf] });

    const res1 = await app.request("/");
    const token1 = parseCookie(res1.headers, "csrf");

    const res2 = await app.request("/", {
      headers: {
        Cookie: `csrf=${token1}`,
      },
    });
    const token2 = parseCookie(res2.headers, "csrf");

    // No new Set-Cookie when cookie already present
    expect(token2).toBeUndefined();
  });

  it("rejects POST without CSRF tokens", async () => {
    app.post("/", () => ({ ok: true }), { middleware: [csrf] });

    const res = await app.request("/", { method: "POST" });
    expect(res.status).toBe(403);
  });

  it("rejects POST with mismatched tokens", async () => {
    app.post("/", () => ({ ok: true }), { middleware: [csrf] });

    const res = await app.request("/", {
      method: "POST",
      headers: {
        Cookie: "csrf=real-token",
      },
    });
    expect(res.status).toBe(403);
  });

  it("accepts POST with matching tokens", async () => {
    app.get("/", () => ({ ok: true }), { middleware: [csrf] });
    app.post("/", () => ({ ok: true }), { middleware: [csrf] });

    // GET to obtain CSRF cookie
    const getRes = await app.request("/");
    const csrfToken = parseCookie(getRes.headers, "csrf")!;
    expect(csrfToken).toBeTypeOf("string");

    // POST with matching cookie + header
    const postRes = await app.request("/", {
      method: "POST",
      headers: {
        Cookie: `csrf=${csrfToken}`,
        "x-csrf-token": csrfToken,
      },
    });
    expect(postRes.status).toBe(200);
    const postBody = await postRes.json();
    expect(postBody.ok).toBe(true);
  });

  it("uses custom cookie and header names", async () => {
    const csrf = defineCsrf({
      secret: "test-secret",
      name: "my-csrf",
      headerName: "x-my-csrf",
      cookie: { secure: false },
    });

    app.get("/", () => ({ ok: true }), { middleware: [csrf] });
    app.post("/", () => ({ ok: true }), { middleware: [csrf] });

    const getRes = await app.request("/");
    const token = parseCookie(getRes.headers, "my-csrf")!;
    expect(token).toBeTypeOf("string");

    // Using the custom header name
    const postRes = await app.request("/", {
      method: "POST",
      headers: {
        Cookie: `my-csrf=${token}`,
        "x-my-csrf": token,
      },
    });
    expect(postRes.status).toBe(200);
    const postBody = await postRes.json();
    expect(postBody.ok).toBe(true);

    // Wrong header name fails
    const failRes = await app.request("/", {
      method: "POST",
      headers: {
        Cookie: `my-csrf=${token}`,
        "x-csrf-token": token,
      },
    });
    expect(failRes.status).toBe(403);
  });
});
