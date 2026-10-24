import { defineWebSocketHandler } from "h3";
import type { SessionManager } from "unauth/session";

export default defineWebSocketHandler({
  async upgrade(request) {
    // Named, not spread: on Nitro 3 the request is a `Request`, and a spread loses its `headers`.
    const headers = new Headers();
    const session = await useAuthSession({
      headers: request.headers,
      context: request.context,
      res: { headers },
    });
    if (!session.id) throw new Response("Sign in first", { status: 401 });

    // `headers` ride on the 101 upgrade (a roll or a drop made during the read); `request.context`
    // is what every later hook gets as `peer.context`: a snapshot of the session, read once here.
    setContext(request, session);
    return { headers };
  },

  open(peer) {
    const { data } = getContext(peer);
    peer.send(`hello ${data.name ?? data.subject}`);
  },

  message(peer, message) {
    const { expiresAt } = getContext(peer);
    if (expiresAt < Date.now()) {
      peer.close(4401, "Session expired");
      return;
    }
    peer.send(`echo: ${message.text()}`);
  },

  close(peer, details) {
    const { data } = getContext(peer);
    console.log(`[ws] ${data.subject} left (${details.code ?? "no code"})`);
  },
});

function setContext(
  request: { context: Record<string, unknown> },
  session: SessionManager<SessionData, "1h">,
) {
  Object.assign(request.context, session);
}
function getContext(peer: { context: Record<string, unknown> }): SessionManager<SessionData, "1h"> {
  // oxlint-disable-next-line typescript/no-explicit-any
  return peer.context as any;
}
