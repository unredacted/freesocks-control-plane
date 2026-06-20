import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

/**
 * Subresource Integrity (CDN-blinding Phase 3): stamp sha384 `integrity` on the
 * built entry script/style + the external theme script. Hand-rolled (no new
 * build dependency) to keep the reproducible-build input set small. The hash is
 * computed from the exact emitted bytes, so a CDN that alters a cached
 * subresource while index.html stays fresh is caught by the browser. This is the
 * prerequisite for enforcing the `Integrity-Policy` header (staged in the
 * Caddyfile, see docs/convex-self-hosting.md). Build-only; dev serve is
 * untouched.
 */
function sriPlugin(): Plugin {
  return {
    name: 'fcp-sri',
    apply: 'build',
    closeBundle() {
      const dist = path.resolve(__dirname, 'dist');
      const indexPath = path.join(dist, 'index.html');
      if (!existsSync(indexPath)) return;
      const html = readFileSync(indexPath, 'utf8').replace(
        /<(script|link)\b([^>]*?)\s(src|href)="(\/[^"]+\.(?:js|css))"([^>]*)>/g,
        (m, tag: string, pre: string, attr: string, url: string, post: string) => {
          if (/\sintegrity=/.test(m)) return m;
          const file = path.join(dist, url);
          if (!existsSync(file)) return m;
          const hash = createHash('sha384').update(readFileSync(file)).digest('base64');
          return `<${tag}${pre} ${attr}="${url}" integrity="sha384-${hash}"${post}>`;
        },
      );
      writeFileSync(indexPath, html);
    },
  };
}

// Post-Convex-migration (P10): the backend is the self-hosted convex-backend,
// not a Cloudflare Worker. Dev = plain Vite serving the SPA + a proxy that
// forwards the API surface to the Convex HTTP-actions port (:3211 by default),
// so the SPA's same-origin `/api/*` fetches (credentials:'include') reach the
// httpRouter in convex/http.ts. In production a reverse proxy serves the built
// SPA and routes /api → the Convex HTTP-actions origin (see docs).
const CONVEX_SITE = process.env.VITE_CONVEX_SITE_URL ?? 'http://127.0.0.1:3211';

export default defineConfig(() => ({
  plugins: [
    // i18n: compile messages/*.json (inlang message-format) → tree-shaken JS in
    // src/lib/paraglide on dev + build. The output is gitignored + recompiled;
    // `bun run i18n:translate` machine-fills the non-base locales.
    paraglideVitePlugin({ project: './project.inlang', outdir: './src/lib/paraglide' }),
    svelte(),
    tailwindcss(),
    sriPlugin(),
  ],
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
    // P1-17: do NOT ship a sourcemap to the public web root. The 3+ MB .map was
    // publicly fetchable and disclosed full readable source — a needless leak
    // for a censorship-resistance tool. Caddy also blocks *.map as defense in
    // depth. (Re-enable as 'hidden' + upload to an error tracker if/when one
    // exists, so maps stay private.)
    sourcemap: false,
    target: 'esnext',
    rollupOptions: { input: path.resolve(__dirname, 'index.html') },
  },
  server: {
    port: 5173,
    // `xfwd` adds X-Forwarded-For so the backend can resolve the client IP in
    // dev the same way it does behind the prod reverse proxy. The backend only
    // trusts it when TRUSTED_PROXY=true (set that on the dev deployment); without
    // it the anonymous get-account flow fails closed with `freetier.ip_unresolved`.
    proxy: {
      '/api': { target: CONVEX_SITE, changeOrigin: true, xfwd: true },
      '/healthz': { target: CONVEX_SITE, changeOrigin: true, xfwd: true },
    },
  },
}));
