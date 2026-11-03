import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'node:path';
import { capPakoAlias } from '../../../scripts/cap-pako-alias.mjs';
export default defineConfig({
  root: resolve('tests/compat/browser'),
  envDir: false,
  plugins: [svelte(), tailwindcss()],
  resolve: {
    alias: [
      { find: '@', replacement: resolve('src') },
      { find: '@client', replacement: resolve('src/client') },
      { find: '@shared', replacement: resolve('src/shared') },
      capPakoAlias,
    ],
  },
  optimizeDeps: { exclude: ['pako/browser/inflate?url'] },
  server: { host: '127.0.0.1', port: 4178, strictPort: true, fs: { allow: [resolve('.')] } },
});
