import { H3, type H3Event, HTTPError, serve } from "h3";
import { defineJWESession, deriveJWKFromPassword } from "unjwt/session";

import { defineSignInHandler } from "unauth/n";
import { defineAtprotoProvider } from "unauth/n/providers/atproto";
import { defineGitHubProvider } from "unauth/n/providers/github";

const password = process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";
const origin = process.env.ORIGIN ?? "http://localhost:3000";

interface SessionData {
  user: string;
  /** The provider the user signed in with; absent for a password login. */
  provider?: string;
}

/** One key seals the session cookie, another the sign-in flow cookie. */
const [sessionKey, flowKey] = await Promise.all(
  ["unauth-playground-h3:session", "unauth-playground-h3:flow"].map((salt) =>
    deriveJWKFromPassword(password, { alg: "PBES2-HS256+A128KW", salt, iterations: 600_000 }),
  ),
);

// The third generic narrows `use()` to the h3 event.
const definition = defineJWESession<SessionData, "1h", H3Event>({
  key: sessionKey,
  name: "unauth-playground",
  maxAge: "1h",
  rolling: "15m",
});

function useAuthSession(event: H3Event) {
  return definition.use(event);
}

async function requireAuthSession(event: H3Event) {
  const session = await useAuthSession(event);
  if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  return session;
}

const github = defineGitHubProvider({
  clientId: process.env.GITHUB_CLIENT_ID ?? "set GITHUB_CLIENT_ID",
  clientSecret: process.env.GITHUB_CLIENT_SECRET ?? "set GITHUB_CLIENT_SECRET",
});

// The app's identity is its client metadata document. In development that URL is on localhost,
// which no server can fetch, so the provider uses the spec's development client instead; its
// callback must be a loopback IP, which `devHosts` maps `localhost` to, moving a start on
// localhost there first.
const atproto = defineAtprotoProvider({
  redirectUri: `${origin}/auth/atproto`,
  devHosts: process.env.NODE_ENV === "production" ? undefined : ["localhost"],
  clientId: `${origin}/oauth-client-metadata.json`,
  clientName: "unauth playground",
  clientUri: origin,
});

// One route, both legs: `?login=<handle, DID or server>` starts, the callback completes.
const signInWithAtproto = defineSignInHandler(atproto, {
  key: flowKey,
  onStart: (event: H3Event) => ({
    login: new URL(event.req.url).searchParams.get("login") ?? undefined,
  }),
  onSuccess: async (event: H3Event, { identity }) => {
    const session = await useAuthSession(event);
    await session.update({ user: identity.name ?? identity.subject, provider: "atproto" });

    return new Response(null, { status: 302, headers: { location: "/" } });
  },
});

const app = new H3()
  .post("/login", async (event) => {
    const body: { user?: unknown } = await event.req.json();
    if (typeof body?.user !== "string")
      throw new HTTPError({ status: 400, message: "user required" });

    const session = await useAuthSession(event);
    await session.update({ user: body.user });

    return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
  })
  .get("/me", async (event) => {
    const session = await requireAuthSession(event);

    return { id: session.id, ...session.data, expiresAt: session.expiresAt };
  })
  .post("/logout", async (event) => {
    const session = await useAuthSession(event);
    await session.clear();

    return { ok: true };
  })
  .get("/throw-after-clear", async (event) => {
    const session = await requireAuthSession(event);
    await session.clear();

    throw new HTTPError({
      status: 401,
      message: "Session cleared; this response should drop the cookie",
    });
  })
  // One route, both legs: the redirect to GitHub, then the callback GitHub sends the browser to.
  .get(
    "/auth/github",
    defineSignInHandler(github, {
      key: flowKey,
      redirectUri: `${origin}/auth/github`,
      onSuccess: async (event: H3Event, { identity }) => {
        const session = await useAuthSession(event);
        await session.update({ user: identity.name ?? identity.subject, provider: "github" });

        return new Response(null, { status: 302, headers: { location: "/" } });
      },
    }),
  )
  .get("/auth/atproto", signInWithAtproto)
  .get("/oauth-client-metadata.json", () => atproto.client.metadata);

serve(app);
