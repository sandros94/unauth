import { H3, type H3Event, HTTPError, serve } from "h3";
import { deriveJWKFromPassword } from "unjwt/session";

import { defineAuthSession, defineSessionGuard, defineSignInHandler } from "unauth/n";
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

// The third generic narrows `use()` and every hook's `context` to the h3 event.
const auth = defineAuthSession<SessionData, H3Event>({
  key: sessionKey,
  maxAge: "1h",
  rolling: "15m",
  hooks: {
    onSignIn: ({ session }) => console.log(`[auth] ${session.data.user} signed in`),
    onSignOut: ({ oldSession, reason }) =>
      console.log(`[auth] ${oldSession.data.user} signed out (${reason})`),
  },
});

const github = defineGitHubProvider({
  clientId: process.env.GITHUB_CLIENT_ID ?? "set GITHUB_CLIENT_ID",
  clientSecret: process.env.GITHUB_CLIENT_SECRET ?? "set GITHUB_CLIENT_SECRET",
});

const app = new H3()
  .post("/login", async (event) => {
    const body: { user?: unknown } = await event.req.json();
    if (typeof body?.user !== "string")
      throw new HTTPError({ status: 400, message: "user required" });

    const session = await auth.use(event);
    await session.authenticate({ user: body.user });

    return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
  })
  .get(
    "/me",
    async (event) => {
      const session = await auth.require(event);

      return { id: session.id, ...session.data, expiresAt: session.expiresAt };
    },
    { middleware: [defineSessionGuard(auth)] },
  )
  .post("/logout", async (event) => {
    const session = await auth.use(event);
    await session.clear();

    return { ok: true };
  })
  .get("/throw-after-clear", async (event) => {
    const session = await auth.require(event);
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
        const session = await auth.use(event);
        await session.authenticate({ user: identity.name ?? identity.subject, provider: "github" });

        return new Response(null, { status: 302, headers: { location: "/" } });
      },
    }),
  );

serve(app);
