import { H3, type H3Event, HTTPError, serve } from "h3";
import { defineJWESession, deriveJWKFromPassword } from "unauth/session";

import { defineSignInHandler } from "unauth/n";
import { defineAtprotoProvider } from "unauth/n/providers/atproto";
import { defineGitHubProvider } from "unauth/n/providers/github";

const password = process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";
const origin = process.env.ORIGIN ?? "http://localhost:3000";

interface SessionData {
  user: string;
  provider?: string;
  signedInAt?: number;
}

const [sessionKey, flowKey] = await Promise.all(
  ["unauth-playground-h3:session", "unauth-playground-h3:flow"].map((salt) =>
    deriveJWKFromPassword(password, { alg: "PBES2-HS256+A128KW", salt, iterations: 600_000 }),
  ),
);

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

const atproto = defineAtprotoProvider({
  redirectUri: `${origin}/auth/atproto`,
  devHosts: process.env.NODE_ENV === "production" ? undefined : ["localhost"],
  clientId: `${origin}/oauth-client-metadata.json`,
  clientName: "unauth playground",
  clientUri: origin,
});

const signInWithAtproto = defineSignInHandler(atproto, {
  key: flowKey,
  onStart: (event: H3Event) => ({
    login: new URL(event.req.url).searchParams.get("login") ?? undefined,
  }),
  onSuccess: async (event, { identity }) => {
    const session = await useAuthSession(event);
    await session.clear();
    await session.update({
      user: identity.name ?? identity.subject,
      provider: identity.provider,
      signedInAt: Date.now(),
    });
  },
});

const app = new H3()
  .post("/login", async (event) => {
    const body: { user?: unknown } = await event.req.json();
    if (typeof body?.user !== "string")
      throw new HTTPError({ status: 400, message: "user required" });

    const session = await useAuthSession(event);
    await session.clear();
    await session.update({ user: body.user, signedInAt: Date.now() });

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
  .get(
    "/auth/github",
    defineSignInHandler(github, {
      key: flowKey,
      redirectUri: `${origin}/auth/github`,
      onSuccess: async (event: H3Event, { identity }) => {
        const session = await useAuthSession(event);
        await session.clear();
        await session.update({
          user: identity.name ?? identity.subject,
          provider: identity.provider,
          signedInAt: Date.now(),
        });
      },
    }),
  )
  .get("/auth/atproto", signInWithAtproto)
  .get("/oauth-client-metadata.json", () => atproto.client.metadata);

serve(app);
