import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { resolve } from 'node:path';
import { capPakoAlias } from '../../scripts/cap-pako-alias.mjs';

export default defineConfig({
  root: resolve('tests/cap/browser'),
  envDir: false,
  plugins: [svelte()],
  resolve: { alias: [{ find: '@', replacement: resolve('src') }, capPakoAlias] },
  build: { outDir: resolve('tests/cap/dist'), emptyOutDir: true },
});
