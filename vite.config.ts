import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';

/**
 * Subresource Integrity (CDN-blinding Phase 3). Two outputs, both from the exact
 * emitted bytes, so a CDN that alters a cached subresource while index.html stays
 * fresh is caught by the browser:
 *
 *  1. Stamp sha384 `integrity` on the static refs in index.html (the entry
 *     script + css + the external theme-init script + any modulepreloads).
 *  2. Inject ONE import map with an `integrity` section covering EVERY emitted
 *     JS chunk, so the runtime code-split / dynamic-import chunks (the lazy admin
 *     CMS, the e2ee crypto) are integrity-checked too — index.html only
 *     references the entry, so without this they carried no SRI. Also emit the
 *     same map as `dist/sri-manifest.json` for the OOB / reproducible-build
 *     verifier (Phase 4).
 *
 * The import map is BACKWARDS-SAFE: a browser without import-map (or import-map
 * `integrity`) support ignores it and loads normally; a supporting browser
 * verifies and only blocks a genuinely-altered chunk (the hashes match the
 * emitted bytes, so a legit chunk never blocks).
 *
 * The enforcing `Integrity-Policy: blocked-destinations=(script)` header stays
 * DEFERRED (see the Caddyfile) — NOT for lack of chunk SRI (this closes that),
 * but because a module WORKER realm does not inherit the document import map, so
 * the PoP signing worker's module imports would have no integrity source and the
 * enforcing header would block them (breaking auth). That needs dedicated
 * in-browser verification (and likely per-worker integrity) before it can flip.
 * Build-only; dev serve is untouched.
 */
function sriPlugin(): Plugin {
  return {
    name: 'fcp-sri',
    apply: 'build',
    closeBundle() {
      const dist = path.resolve(__dirname, 'dist');
      const indexPath = path.join(dist, 'index.html');
      if (!existsSync(indexPath)) return;

      // (1) Integrity for every emitted JS chunk → an import map + a sidecar
      // manifest. Covers the dynamic-import chunks that index.html never names.
      const assetsDir = path.join(dist, 'assets');
      const chunkIntegrity: Record<string, string> = {};
      if (existsSync(assetsDir)) {
        for (const f of readdirSync(assetsDir)) {
          if (!f.endsWith('.js')) continue;
          const hash = createHash('sha384')
            .update(readFileSync(path.join(assetsDir, f)))
            .digest('base64');
          chunkIntegrity[`/assets/${f}`] = `sha384-${hash}`;
        }
      }
      writeFileSync(
        path.join(dist, 'sri-manifest.json'),
        `${JSON.stringify({ integrity: chunkIntegrity }, null, 2)}\n`,
      );

      // (2) Stamp integrity on the static refs already in index.html.
      let html = readFileSync(indexPath, 'utf8').replace(
        /<(script|link)\b([^>]*?)\s(src|href)="(\/[^"]+\.(?:js|css))"([^>]*)>/g,
        (m, tag: string, pre: string, attr: string, url: string, post: string) => {
          if (/\sintegrity=/.test(m)) return m;
          const file = path.join(dist, url);
          if (!existsSync(file)) return m;
          const hash = createHash('sha384').update(readFileSync(file)).digest('base64');
          return `<${tag}${pre} ${attr}="${url}" integrity="sha384-${hash}"${post}>`;
        },
      );

      // (3) Inject the import map BEFORE the first module script (an import map
      // must precede any module load). A single map; only the `integrity` key.
      if (!html.includes('type="importmap"') && Object.keys(chunkIntegrity).length > 0) {
        const tag = `<script type="importmap">${JSON.stringify({ integrity: chunkIntegrity })}</script>`;
        html = html.replace(/(^[ \t]*)(<script type="module")/m, `$1${tag}\n$1$2`);
      }
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
