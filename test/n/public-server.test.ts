import { describe, expect, it } from "vitest";

import { isPublicServer } from "../../src/n/index.ts";

describe("isPublicServer", () => {
  it("refuses what a stranger could point a server at", () => {
    const refused = [
      "http://pds.test",
      "http://pds.host",
      "https://127.0.0.1",
      "https://10.1.2.3",
      "https://[::1]",
      "https://0x7f000001",
      "https://2130706433",
      "https://127.1",
      "https://localhost",
      "https://pds.localhost",
      "https://printer.local",
      "https://intranet",
      "https://user:pw@pds.host",
      "https://x.home.arpa",
      "https://pds.example.",
      "https://PDS.Example",
      "https://pds.onion",
      "ftp://pds.host",
      "not a url",
    ];
    for (const url of refused)
      expect({ url, allowed: isPublicServer(url) }).toEqual({ url, allowed: false });
  });

  it("accepts a public https server, as a string or a URL", () => {
    expect(isPublicServer("https://pds.bsky.network")).toBe(true);
    expect(isPublicServer("https://pds.host:8443/xrpc")).toBe(true);
    expect(isPublicServer("https://pds.test")).toBe(true);
    expect(isPublicServer("https://pds.host.")).toBe(true);
    expect(isPublicServer(new URL("https://bsky.social"))).toBe(true);
  });

  it("admits plain http with allow.http, still not on an IP literal", () => {
    expect(isPublicServer("http://pds.host", { allow: { http: true } })).toBe(true);
    expect(isPublicServer("http://10.0.0.1", { allow: { http: true } })).toBe(false);
    expect(isPublicServer("ws://pds.host", { allow: { http: true } })).toBe(false);
  });

  it("admits the suffixes allow.suffixes lists, keeping the rest of the list", () => {
    const allow = { suffixes: [".local"] };
    expect(isPublicServer("https://printer.local", { allow })).toBe(true);
    expect(isPublicServer("https://printer.LOCAL.", { allow })).toBe(true);
    expect(isPublicServer("https://printer.internal", { allow })).toBe(false);
    expect(isPublicServer("https://printer.local", { allow: { suffixes: ["local"] } })).toBe(true);
    expect(isPublicServer("https://nas.home.arpa", { allow: { suffixes: [".home.arpa"] } })).toBe(
      true,
    );
    expect(isPublicServer("https://1.in-addr.arpa", { allow: { suffixes: [".home.arpa"] } })).toBe(
      false,
    );
  });

  it("admits IP literals with allow.ipLiterals and single labels with allow.singleLabel", () => {
    expect(isPublicServer("https://10.1.2.3", { allow: { ipLiterals: true } })).toBe(true);
    expect(isPublicServer("https://[fd00::1]", { allow: { ipLiterals: true } })).toBe(true);
    expect(isPublicServer("https://intranet", { allow: { singleLabel: true } })).toBe(true);
    expect(isPublicServer("https://localhost", { allow: { singleLabel: true } })).toBe(false);
  });

  it("refuses credentials under every relaxation", () => {
    const allow = { http: true, ipLiterals: true, singleLabel: true, suffixes: [".local"] };
    for (const url of ["https://u:p@pds.host", "http://u@10.0.0.1", "https://:p@printer.local"]) {
      expect({ url, allowed: isPublicServer(url, { allow }) }).toEqual({ url, allowed: false });
    }
  });

  it("is tightened by wrapping it", () => {
    const onlyBsky = (url: URL) => isPublicServer(url) && url.hostname.endsWith(".bsky.network");
    expect(onlyBsky(new URL("https://morel.us-east.host.bsky.network"))).toBe(true);
    expect(onlyBsky(new URL("https://pds.host"))).toBe(false);
    expect(onlyBsky(new URL("http://pds.bsky.network"))).toBe(false);
  });
});
