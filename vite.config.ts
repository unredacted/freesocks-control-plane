import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { cloudflare } from '@cloudflare/vite-plugin';
import path from 'node:path';

// The Cloudflare Vite plugin embeds the chosen wrangler config into the build
// output (dist/ssr/wrangler.json), which is what `wrangler deploy`
// ultimately ships. We need to point it at the right config per env:
//
//   vite dev                         → wrangler.dev.toml (Miniflare placeholders)
//   DEPLOY_ENV=beta vite build       → wrangler.beta.toml (beta.freesocks.org)
//   vite build (no DEPLOY_ENV)       → wrangler.toml      (production, app.freesocks.org)
//
// Without this, production deploys would carry whichever config was wired,
// regardless of the wrangler --config flag (since the plugin's emitted
// dist/client/ssr/wrangler.json overrides anything wrangler reads on its own).
function configPathForBuild(): string {
  const env = process.env.DEPLOY_ENV;
  switch (env) {
    case 'beta':
      return './wrangler.beta.toml';
    case 'production':
    case undefined:
    case '':
      return './wrangler.toml';
    default:
      throw new Error(
        `Unknown DEPLOY_ENV=${env}. Expected one of: production, beta, or unset (defaults to production).`,
      );
  }
}

export default defineConfig(({ command }) => ({
  plugins: [
    svelte(),
    tailwindcss(),
    cloudflare({
      configPath: command === 'build' ? configPathForBuild() : './wrangler.dev.toml',
      viteEnvironment: { name: 'ssr' },
    }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@client': path.resolve(__dirname, './src/client'),
      '@server': path.resolve(__dirname, './src/server'),
      '@shared': path.resolve(__dirname, './src/shared'),
    },
  },
  esbuild: {
    target: 'esnext',
  },
  build: {
    // outDir is `dist`, not `dist/client`. The Cloudflare Vite plugin appends
    // each environment's name as a subdir under outDir:
    //   - SPA   → dist/client/
    //   - worker → dist/ssr/
    // With outDir='dist/client' the SPA would nest as dist/client/client/,
    // and the wrangler `[assets].directory = "./dist/client"` would look one
    // level above the SPA, finding both client/ and ssr/ siblings — wrangler
    // then uploads nothing useful and / returns 404 from env.ASSETS.fetch().
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    target: 'esnext',
    rollupOptions: {
      input: path.resolve(__dirname, 'index.html'),
    },
  },
  server: {
    port: 5173,
  },
}));
