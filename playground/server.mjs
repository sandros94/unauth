import { H3, HTTPError, serve } from "h3";

import {
  defineSession,
  defineTokenPair,
  defineCsrf,
  generateJWK,
  optionalAuth,
  requireAuth,
} from "unauth/base/h3";

// Pre-generate keys once per process. In production these come from secret storage.
const atKey = await generateJWK("ES256");
const rtKey = await generateJWK("A256GCMKW");
const sessionKey = await generateJWK("A256GCMKW");

// Single-cookie encrypted session — for traditional session-based auth.
const useSession = defineSession({
  key: sessionKey,
  maxAge: "7D",
  cookie: { secure: false }, // dev only — set secure: true behind HTTPS
  hooks: {
    async onRefresh({ session, refresh }) {
      // Hydrate latest claims from your store on sliding-window refresh.
      console.log("[session] sliding refresh for", session.data.userId);
      await refresh();
    },
  },
});

// Coordinated AT (JWS, short-lived) + RT (JWE, long-lived) — for SPA/mobile.
const useAuth = defineTokenPair({
  access: {
    key: atKey,
    maxAge: "15m",
    cookie: { secure: false },
  },
  refresh: {
    key: rtKey,
    maxAge: "30D",
    cookie: { secure: false },
  },
  hooks: {
    async onRefresh({ refresh, issue, revoke }) {
      // Look up the user from the RT and re-issue the AT.
      // Return without calling issue/revoke to leave tokens untouched.
      if (refresh.data.banned) {
        await revoke();
        return;
      }
      await issue({
        accessData: {
          sub: refresh.data.sub,
          permissions: refresh.data.permissions ?? ["read"],
        },
      });
    },
    onAfterRefresh({ access, previousRefresh, refresh }) {
      console.log(`[auth] rotated RT ${previousRefresh.id} -> ${refresh.id}, new AT ${access.id}`);
    },
  },
});

const csrf = defineCsrf({
  secret: "dev-csrf-secret",
  cookie: { secure: false },
});

const app = new H3();

// --- Session-based auth ---

app.post("/session/login", async (event) => {
  const body = await event.req.json();
  if (!body?.userId) {
    throw new HTTPError("userId is required", { status: 400 });
  }
  const session = await useSession(event);
  await session.update({ userId: body.userId, role: body.role ?? "user" });
  return { ok: true, id: session.id, data: session.data };
});

app.get("/session/me", async (event) => {
  const session = await useSession(event);
  return { id: session.id ?? null, data: session.data };
});

app.post("/session/logout", async (event) => {
  const session = await useSession(event);
  await session.clear();
  return { ok: true };
});

// --- Token pair (AT + RT) auth ---

app.post("/auth/login", async (event) => {
  const body = await event.req.json();
  if (!body?.username || !body?.password) {
    throw new HTTPError("username and password are required", { status: 400 });
  }
  // Validate credentials against your store here.
  const auth = await useAuth(event);
  await auth.issue({
    accessData: { sub: body.username, permissions: ["read"] },
    refreshData: { sub: body.username, family: crypto.randomUUID() },
  });
  return { ok: true, access: { id: auth.access.id }, refresh: { id: auth.refresh.id } };
});

app.get(
  "/auth/me",
  async (event) => {
    const { access } = await useAuth(event);
    return { sub: access.data.sub, permissions: access.data.permissions };
  },
  { middleware: [requireAuth(useAuth)] },
);

app.get(
  "/auth/feed",
  async (event) => {
    const { access } = await useAuth(event);
    return {
      authenticated: !!access.id,
      sub: access.data.sub ?? null,
    };
  },
  { middleware: [optionalAuth(useAuth)] },
);

app.post("/auth/logout", async (event) => {
  const auth = await useAuth(event);
  await auth.revoke();
  return { ok: true };
});

// --- CSRF demo (double-submit cookie) ---

app.get(
  "/csrf/form",
  () => ({ ok: true, hint: "Read the 'csrf' cookie and echo it as x-csrf-token" }),
  {
    middleware: [csrf],
  },
);

app.post("/csrf/submit", async (event) => ({ ok: true, body: await event.req.json() }), {
  middleware: [csrf],
});

// --- Landing ---

app.get("/", () => ({
  routes: {
    session: ["POST /session/login {userId,role?}", "GET /session/me", "POST /session/logout"],
    tokenPair: [
      "POST /auth/login {username,password}",
      "GET /auth/me (requires AT)",
      "GET /auth/feed (optional AT)",
      "POST /auth/logout",
    ],
    csrf: ["GET /csrf/form", "POST /csrf/submit (header: x-csrf-token)"],
  },
}));

serve(app);
