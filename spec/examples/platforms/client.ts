import type { H3 } from "h3";

export interface Reply {
  status: number;
  body: unknown;
}

export interface Caller {
  get(path: string): Promise<Reply>;
  post(path: string, body: object): Promise<Reply>;
  put(path: string, body?: object): Promise<Reply>;
  delete(path: string): Promise<Reply>;
}

export function visitor(app: H3): Caller {
  return caller(app, undefined);
}

export async function signedIn(app: H3, user: string): Promise<Caller> {
  const response = await app.request("/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user }),
  });
  if (response.status !== 200) throw new Error(`${user} could not sign in: ${response.status}.`);
  const cookie = response.headers.getSetCookie().at(-1)?.split(";")[0];
  return caller(app, cookie);
}

function caller(app: H3, cookie: string | undefined): Caller {
  const send = async (method: string, path: string, body?: object): Promise<Reply> => {
    const headers = new Headers({ "content-type": "application/json" });
    if (cookie !== undefined) headers.set("cookie", cookie);
    const init = { method, headers, body: body === undefined ? undefined : JSON.stringify(body) };
    const response = await app.request(path, init);
    const text = await response.text();
    return { status: response.status, body: text === "" ? undefined : JSON.parse(text) };
  };
  return {
    get: (path) => send("GET", path),
    post: (path, body) => send("POST", path, body),
    put: (path, body) => send("PUT", path, body ?? {}),
    delete: (path) => send("DELETE", path),
  };
}
