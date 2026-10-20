import { useRuntimeConfig } from "nitro/runtime-config";
import { type SessionContext, deriveJWKFromPassword } from "unjwt/session";

import {
  type AuthSessionManager,
  type AuthenticatedSessionManager,
  defineAuthSession,
  defineSignInHandler,
} from "unauth/n";
import { defineGitHubProvider } from "unauth/n/providers/github";

export interface SessionData {
  user: string;
  /** The provider the user signed in with; absent for a password login. */
  provider?: string;
}

const password = process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";

/** One key seals the session cookie, another the sign-in flow cookie. */
const [sessionKey, flowKey] = await Promise.all(
  ["unauth-playground-nitro:session", "unauth-playground-nitro:flow"].map((salt) =>
    deriveJWKFromPassword(password, { alg: "PBES2-HS256+A128KW", salt, iterations: 600_000 }),
  ),
);

// Not narrowed to Nitro's `H3Event`: the WebSocket upgrade hands a request by its headers.
export const auth = defineAuthSession<SessionData>({
  key: sessionKey,
  maxAge: "1h",
  rolling: "15m",
  hooks: {
    onSignIn: ({ session }) => console.log(`[auth] ${session.data.user} signed in`),
    onSignOut: ({ oldSession, reason }) =>
      console.log(`[auth] ${oldSession.data.user} signed out (${reason})`),
  },
});

export function useAppSession(event: SessionContext): Promise<AuthSessionManager<SessionData>> {
  return auth.use(event);
}

/** The session once it authenticated; `ERR_AUTHN_UNAUTHENTICATED` (401) otherwise. */
export async function requireAppSession(
  event: SessionContext,
): Promise<AuthenticatedSessionManager<SessionData>> {
  return auth.require(event);
}

/** One route, both legs: the redirect to GitHub, then the callback GitHub sends the browser to. */
export const githubHandler = defineSignInHandler(
  defineGitHubProvider({
    clientId: useRuntimeConfig().github.clientId,
    clientSecret: useRuntimeConfig().github.clientSecret,
  }),
  {
    key: flowKey,
    redirectUri: `${useRuntimeConfig().public.origin}/auth/github`,
    onSuccess: async (event, { identity }) => {
      const session = await useAppSession(event);
      await session.authenticate({ user: identity.name ?? identity.subject, provider: "github" });

      return new Response(null, { status: 302, headers: { location: "/" } });
    },
  },
);
