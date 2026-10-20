import { defineHandler } from "nitro";

import { githubHandler } from "../../utils/session.ts";

export default defineHandler(githubHandler);
