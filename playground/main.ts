import { H3, serve } from "h3v2";

const app = new H3();

app.get("/", () => "Hello World!");

serve(app);
