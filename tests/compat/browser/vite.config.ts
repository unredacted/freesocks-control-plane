import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'node:path';
import { capPakoAlias } from '../../../scripts/cap-pako-alias.mjs';
import { reportKeys } from './reportKeys';

const { publicPin, kid } = await reportKeys();
export default defineConfig({
  define: {
    'import.meta.env.VITE_FS_SERVER_HPKE_PK': JSON.stringify(publicPin),
    'import.meta.env.VITE_FS_SERVER_HPKE_KID': JSON.stringify(kid),
  },
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
