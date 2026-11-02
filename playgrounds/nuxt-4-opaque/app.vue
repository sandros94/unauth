<script setup lang="ts">
const log = ref<string[]>([]);
const user = ref("");
const password = ref("");
const say = (line: string) => log.value.unshift(line);

const { data: session, refresh } = await useFetch("/me", { default: () => null });

async function call(path: string, method: "GET" | "POST" = "GET", body?: Record<string, unknown>) {
  try {
    const result = await $fetch(path, { method, body });
    say(`${method} ${path} → ${JSON.stringify(result)}`);
  } catch (error) {
    const failure = error as { statusCode?: number; data?: { message?: string }; message?: string };
    say(
      `${method} ${path} → ${failure.statusCode ?? "?"} ${failure.data?.message ?? failure.message}`,
    );
  }
  await refresh();
}
</script>

<template>
  <main style="font-family: system-ui; max-width: 40rem; margin: 2rem auto">
    <h1>unauth on Nuxt 4, opaque sessions</h1>
    <template v-if="session">
      <p>
        Signed in as <strong>{{ session.userId }}</strong
        >.
      </p>
      <p>Connected accounts:</p>
      <ul>
        <li v-for="entry in session.identities" :key="`${entry.provider}:${entry.subject}`">
          {{ entry.provider }}: {{ entry.name ?? entry.subject }}
          <button
            v-if="session.identities.length > 1"
            @click="call('/unlink', 'POST', { provider: entry.provider, subject: entry.subject })"
          >
            unlink
          </button>
          <button v-else @click="call('/delete', 'POST')">delete account</button>
        </li>
      </ul>
      <form action="/auth/github" method="post"><button type="submit">connect GitHub</button></form>
      <p>
        <button @click="call('/me')">me</button>
        <button @click="call('/logout', 'POST')">logout</button>
      </p>
    </template>
    <template v-else>
      <form>
        <input v-model="user" name="user" placeholder="alice" autocomplete="username" />
        <input v-model="password" name="password" type="password" autocomplete="current-password" />
        <button type="button" @click="call('/register', 'POST', { user, password })">
          register
        </button>
        <button type="button" @click="call('/login', 'POST', { user, password })">login</button>
      </form>
      <p><a href="/auth/github">sign in with GitHub</a></p>
    </template>
    <pre v-for="(line, i) in log" :key="i">{{ line }}</pre>
  </main>
</template>
