import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'node:path';
export default defineConfig({
  root: resolve('tests/compat/browser'),
  envDir: false,
  plugins: [svelte(), tailwindcss()],
  resolve: {
    alias: {
      '@': resolve('src'),
      '@client': resolve('src/client'),
      '@shared': resolve('src/shared'),
    },
  },
  server: { host: '127.0.0.1', port: 4178, strictPort: true, fs: { allow: [resolve('.')] } },
});
