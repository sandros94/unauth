import { createApp, createRouter, defineEventHandler, getQuery } from "h3";
import { generateJWK, useOIDCProvider } from "unauth/h3";

// Create an app instance
export const app = createApp();

// Create a new router and register it in app
const router = createRouter();
app.use(router);

const [atJwk, idJwk] = await Promise.all([
  generateJWK("RS256", { kid: "at-rsa-1" }),
  generateJWK("RS256", { kid: "id-rsa-1" }),
]);
const provider = useOIDCProvider({
  issuer: "http://localhost:3000",
  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: atJwk,
  idTokenOptions: idJwk,
});

// OpenID Provider Configuration (Discovery)
router.get(
  "/.well-known/openid-configuration",
  defineEventHandler(() => {
    return provider.discovery();
  }),
);

// JWKS (public keys)
router.get(
  "/.well-known/jwks.json",
  defineEventHandler(() => provider.jwkSet),
);

// Simple callback endpoint for manual testing; not used by the scripted test (which intercepts the Location header)
router.get(
  "/callback",
  defineEventHandler((event) => {
    const q = getQuery<{ code?: string; state?: string }>(event);
    return `Callback received. code=${q.code ?? "<none>"} state=${q.state ?? "<none>"}`;
  }),
);

router.get(
  "/authorize",
  defineEventHandler(async (event) => {
    return provider.authorize(event, async (input, validateRedirectUri) => {
      const redirect_uri = validateRedirectUri(input.redirect_uri, [
        "http://localhost:3000/callback", // this is the one requested
        "http://localhost:3000/alt-callback",
      ]);

      return {
        subject: "user-123", // in a real app, you'd determine this from the user's session
        redirect_uri,
      };
    });
  }),
);

router.post(
  "/token",
  defineEventHandler(async (event) => {
    return provider.token(event);
  }),
);

router.get(
  "/userinfo",
  defineEventHandler(async (event) => {
    return provider.userInfo(event);
  }),
);
