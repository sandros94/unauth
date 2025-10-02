import {
  createApp,
  createRouter,
  defineEventHandler,
  getQuery,
  useBase,
} from "h3";
import { createOIDCRouter, validateRedirectUri } from "unauth/h3/oidc";
import { generateJWK } from "unauth";

const [atJwk, idJwk] = await Promise.all([
  generateJWK("RS256", { kid: "at-rsa-1" }),
  generateJWK("RS256", { kid: "id-rsa-1" }),
]);

// If the first argument is a string, it will return a handler with a base
const oidcRouter = createOIDCRouter({
  issuer: "http://localhost:3000",
  discovery: {
    // the base path where the OIDC endpoints will be served
    // (e.g. /oidc/v1/.well-known/openid-configuration)
    base: "/oidc/v1",
    // you can also override individual endpoints here, e.g.:
    // authorization_endpoint: "/oidc/v1/authorize",
  },

  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: atJwk, // we can directly pass keys and use default options
  idTokenOptions: idJwk, // same as accessTokenOptions

  // Hook that is called when the /authorize endpoint is hit
  authorize: async (input) => {
    if (input.client_id !== "test-client") {
      return {
        error: "invalid_client",
        error_description: "Unknown client",
      };
    }

    const validRedirectUri = validateRedirectUri(input.redirect_uri, [
      "http://localhost:3000/callback", // this is the one requested
      "http://localhost:3000/alt-callback",
    ]);

    if (!validRedirectUri.success) {
      return validRedirectUri.error;
    }

    // in a real app, you'd determine this from the user's login session
    const subject = "user-123";

    return {
      subject,
      redirect_uri: validRedirectUri.value,
    };
  },
});

// Create an H3 app instance
export const app = createApp();
const router = createRouter();

// Simple callback endpoint for manual testing; used by the scripted test (which intercepts the Location header)
router.get(
  "/callback",
  defineEventHandler((event) => {
    const q = getQuery<{ code?: string; state?: string }>(event);
    return `Callback received. code=${q.code ?? "<none>"} state=${q.state ?? "<none>"}`;
  }),
);

// Use the same base as used in `createOIDCRouter`
router.use("/oidc/v1/**", useBase("/oidc/v1", oidcRouter.handler));

app.use(router);
