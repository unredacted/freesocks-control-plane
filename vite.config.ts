import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

// Post-Convex-migration (P10): the backend is the self-hosted convex-backend,
// not a Cloudflare Worker. Dev = plain Vite serving the SPA + a proxy that
// forwards the API surface to the Convex HTTP-actions port (:3211 by default),
// so the SPA's same-origin `/api/*` fetches (credentials:'include') reach the
// httpRouter in convex/http.ts. In production a reverse proxy serves the built
// SPA and routes /api → the Convex HTTP-actions origin (see docs).
const CONVEX_SITE = process.env.VITE_CONVEX_SITE_URL ?? 'http://127.0.0.1:3211';

export default defineConfig(() => ({
  plugins: [svelte(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@client': path.resolve(__dirname, './src/client'),
      '@shared': path.resolve(__dirname, './src/shared'),
    },
  },
  esbuild: { target: 'esnext' },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    target: 'esnext',
    rollupOptions: { input: path.resolve(__dirname, 'index.html') },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: CONVEX_SITE, changeOrigin: true },
      '/healthz': { target: CONVEX_SITE, changeOrigin: true },
    },
  },
}));
