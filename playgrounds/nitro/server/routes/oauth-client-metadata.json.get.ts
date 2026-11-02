import { defineHandler } from "nitro";

import { atproto } from "../utils/atproto.ts";

export default defineHandler(() => atproto.client.metadata);
