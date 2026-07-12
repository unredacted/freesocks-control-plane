import { mount } from 'svelte';
import App from './App.svelte';
import './styles/globals.css';
import { initI18n } from './lib/i18n/index.svelte';

/*
 * Bundled web fonts. NEVER load fonts from a third-party CDN: every font
 * weight here is shipped as a hashed WOFF2 asset in our own dist/ bundle so
 * the SPA renders without contacting Google Fonts (or any other host) on
 * behalf of the user.
 *
 * Two reasons this matters:
 *   1. Privacy. Loading Google Fonts leaks every visitor's IP + UA to
 *      Google. The audience we serve (users in heavily-censored regions)
 *      are exactly the people who can least afford that data leak.
 *   2. Reliability. fonts.gstatic.com is blocked in some regions we care
 *      about. The SPA must render with our brand typography even if the
 *      visitor can't reach any Google domain.
 *
 * Weights mirror what the previous Google-Fonts URL requested. If new
 * weights are needed, add them here, not via an external stylesheet.
 *   - Inter (body, UI):       400, 500, 600, 700
 *   - Inter Tight (display):  600, 700, 800
 *   - JetBrains Mono (code):  400, 500
 *
 * The fontsource packages ship per-subset @font-face declarations with
 * unicode-range, so the browser only downloads the subset(s) it actually
 * needs, so adding cyrillic/greek/vietnamese support costs nothing on a
 * latin-only page.
 */
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/inter-tight/600.css';
import '@fontsource/inter-tight/700.css';
import '@fontsource/inter-tight/800.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';

// Hand the per-request CSP nonce to the Cap widget. Caddy puts the same UUID in
// the response's `script-src 'nonce-…'` header and in the <meta name="csp-nonce">
// tag (templates), so the widget can stamp it on its instrumentation challenge
// (a server-supplied inline script in a sandboxed <iframe srcdoc>) and have it
// run under our strict no-inline-script CSP. Outside Caddy (vite dev/preview)
// the meta is the literal "{{…}}" placeholder - ignore it (dev has no
// enforcing CSP, and a bogus nonce would just make instrumentation no-op).
const cspNonce = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content');
if (cspNonce && !cspNonce.includes('{{')) {
  window.CAP_SCRIPT_NONCE = cspNonce;
}

// Apply the saved/detected locale's <html lang/dir> before first paint.
initI18n();

const target = document.getElementById('app');
if (!target) throw new Error('#app element not found');

mount(App, { target });
