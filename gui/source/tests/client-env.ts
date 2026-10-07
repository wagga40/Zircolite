import type { Environment } from 'vitest/runtime';

// Plain node globals, but modules go through the client transform so Svelte
// compiles runes and effects for the browser instead of the server.
export default <Environment>{
  name: 'node-client',
  viteEnvironment: 'client',
  setup() {
    return { teardown() {} };
  },
};
