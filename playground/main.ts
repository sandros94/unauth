import { H3, serve } from "h3";
import { OIDCProvider } from "unauth";
import { generateKey } from "unjwt/jwk";

const keys = await generateKey("Ed25519", { toJWK: true });

const app = new H3();
const provider = new OIDCProvider({
  issuer: "http://localhost:3000",
  privateKeys: [keys.privateKey],
  publicKeys: [keys.publicKey],
});

app.get("/", () => {
  return "Hello World!";
});

app.get("/.well-known/jwks.json", () => {
  return provider.jwks;
});

serve(app);
