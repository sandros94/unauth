import supertest from "supertest";
import { createApp, createRouter, toNodeListener, type App, type Router } from "h3v1";

/**
 * h3 v1 doesn't ship a Fetch-style request method like h3 v2's `app.request()`,
 * so this helper wraps the app with supertest + an Express-style listener and
 * exposes a `request(url, init)` method returning a real `Response`. Keeps the
 * test bodies close to the h3v2 suite — only the setup differs.
 */
export interface H3v1Harness {
  app: App;
  router: Router;
  request(url: string, init?: RequestInit): Promise<Response>;
}

export function createH3v1Harness(): H3v1Harness {
  const router = createRouter({ preemptive: true });
  const app = createApp({ debug: true }).use(router);
  const agent = supertest(toNodeListener(app));

  return {
    app,
    router,
    request(url, init = {}) {
      const method = (init.method ?? "GET").toLowerCase() as
        | "get"
        | "post"
        | "put"
        | "delete"
        | "patch"
        | "head"
        | "options";

      let req = agent[method](url);

      if (init.headers) {
        const h = init.headers instanceof Headers ? Object.fromEntries(init.headers) : init.headers;
        for (const [k, v] of Object.entries(h)) {
          req = req.set(k, v as string);
        }
      }

      const bodyPromise: Promise<void> = (async () => {
        if (init.body !== undefined && init.body !== null) {
          const body =
            typeof init.body === "string" ? init.body : await new Response(init.body).text();
          req = req.send(body);
        }
      })();

      return bodyPromise.then(
        () =>
          new Promise<Response>((resolve, reject) => {
            req.end((err, res) => {
              if (err) {
                reject(err);
                return;
              }

              const headers = new Headers();
              for (const [key, value] of Object.entries(res.headers)) {
                if (key === "set-cookie" && Array.isArray(value)) {
                  for (const v of value) headers.append("set-cookie", v);
                } else if (Array.isArray(value)) {
                  headers.set(key, value.join(", "));
                } else if (value !== undefined) {
                  headers.set(key, String(value));
                }
              }

              const text =
                typeof res.text === "string" && res.text.length > 0
                  ? res.text
                  : res.body && typeof res.body === "object"
                    ? JSON.stringify(res.body)
                    : "";

              resolve(new Response(text || null, { status: res.status, headers }));
            });
          })
      );
    },
  };
}
