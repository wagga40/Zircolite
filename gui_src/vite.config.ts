/// <reference types="vitest/config" />
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

// One classic script rather than ES modules: a page opened from file:// may
// run <script src> beside it, but module scripts load under CORS and fail.
export default defineConfig({
  plugins: [svelte()],
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    outDir: '../gui/viewer',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    lib: {
      entry: 'src/main.ts',
      name: 'ZircoliteViewer',
      formats: ['iife'],
      fileName: () => 'app.js',
      cssFileName: 'app',
    },
  },
  // Tests run Svelte's browser build (client-env.ts picks the client transform), so effects and flushSync work.
  resolve: process.env.VITEST ? { conditions: ['browser'] } : undefined,
  test: { environment: './tests/client-env.ts', include: ['tests/**/*.test.ts'] },
});
