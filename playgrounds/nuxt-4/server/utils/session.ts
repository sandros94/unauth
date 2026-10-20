import { deriveSecret, useRuntimeConfig } from "nuxt/server";
import type { SessionContext } from "unjwt/session";
import { base64UrlStringify } from "unjwt/utils";

import {
  type AuthSessionDefinition,
  type AuthSessionManager,
  type AuthenticatedSessionManager,
  type HandlerEvent,
  defineAuthSession,
  defineSignInHandler,
} from "unauth/n";
import { defineGitHubProvider } from "unauth/n/providers/github";

type Definition = AuthSessionDefinition<SessionData>;
type GitHubHandler = (event: HandlerEvent) => Promise<unknown>;

let app: Promise<{ auth: Definition; github: GitHubHandler }> | undefined;

/**
 * `deriveSecret` needs the Nuxt runtime config, so the definitions are created on first use, not
 * at import time. Each purpose's 32 HKDF bytes are an A256GCM key as an `oct` JWK: one seals the
 * session cookie, another the sign-in flow cookie.
 */
async function define(): Promise<{ auth: Definition; github: GitHubHandler }> {
  const [sessionKey, flowKey] = await Promise.all(
    ["unauth:session", "unauth:flow"].map(async (purpose) => {
      const secret = await deriveSecret(purpose);
      const bytes = Uint8Array.from(secret.match(/../g)!, (pair) => Number.parseInt(pair, 16));
      return { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" } as const;
    }),
  );
  const config = useRuntimeConfig();

  // Not narrowed to Nuxt's `RequestEvent`: the WebSocket upgrade hands a request by its headers.
  const auth = defineAuthSession<SessionData>({
    key: sessionKey!,
    maxAge: "1h",
    rolling: "15m",
    hooks: {
      onSignIn: ({ session }) => console.log(`[auth] ${session.data.user} signed in`),
      onSignOut: ({ oldSession, reason }) =>
        console.log(`[auth] ${oldSession.data.user} signed out (${reason})`),
    },
  });

  // One route, both legs: the redirect to GitHub, then the callback GitHub sends the browser to.
  const github = defineSignInHandler(
    defineGitHubProvider({
      clientId: config.github.clientId || "set NUXT_GITHUB_CLIENT_ID",
      clientSecret: config.github.clientSecret || "set NUXT_GITHUB_CLIENT_SECRET",
    }),
    {
      key: flowKey!,
      redirectUri: `${config.public.origin}/auth/github`,
      onSuccess: async (event, { identity }) => {
        const session = await auth.use(event);
        await session.authenticate({ user: identity.name ?? identity.subject, provider: "github" });

        return new Response(null, { status: 302, headers: { location: "/" } });
      },
    },
  );

  return { auth, github };
}

export async function useAppSession(
  event: SessionContext,
): Promise<AuthSessionManager<SessionData>> {
  return (app ??= define()).then(({ auth }) => auth.use(event));
}

/** The session once it authenticated; `ERR_AUTHN_UNAUTHENTICATED` (401) otherwise. */
export async function requireAppSession(
  event: SessionContext,
): Promise<AuthenticatedSessionManager<SessionData>> {
  return (app ??= define()).then(({ auth }) => auth.require(event));
}

export async function useGitHubSignIn(event: HandlerEvent): Promise<unknown> {
  return (app ??= define()).then(({ github }) => github(event));
}
