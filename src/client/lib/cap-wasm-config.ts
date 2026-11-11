/**
 * Point the Cap widget's proof-of-work WASM + pako loader at SAME-ORIGIN bundled
 * assets instead of its built-in `cdn.jsdelivr.net` defaults. Without this the
 * captcha fetches from a third-party CDN - which would reintroduce a third-party
 * runtime dependency AND break in regions where jsdelivr is blocked, defeating
 * the entire point of self-hosting Cap (W1).
 *
 * Vite emits these as hashed assets under /assets (served same-origin by Caddy).
 * Versions are pinned to match what the widget expects (@cap.js/widget@0.1.62
 * names @cap.js/wasm@0.0.8, both pinned exactly). Pako's public browser entry
 * is resolved to its classic UMD build for the widget's script loader. Two solvers:
 * `cap_wasm_bg.wasm` for `sha256-pow` keys and `hashwx.wasm` for `hashwx` keys
 * (what a self-hosted Cap creates by default). Imported for its side effect
 * BEFORE `@cap.js/widget` so the globals are set before the lazy loader reads them.
 */
import wasmUrl from '@cap.js/wasm/browser/cap_wasm_bg.wasm?url';
import hashwxUrl from '@cap.js/wasm/browser/hashwx.wasm?url';
import pakoUrl from 'pako/browser/inflate?url';

declare global {
  interface Window {
    CAP_CUSTOM_WASM_URL?: string;
    CAP_CUSTOM_HASHWX_URL?: string;
    CAP_PAKO_URL?: string;
    CAP_ISOLATE?: boolean;
    CAP_DISABLE_WIDGET_REF?: boolean;
    // Per-request CSP nonce (set in main.ts from the <meta name="csp-nonce">
    // Caddy templates). The widget stamps it on its instrumentation srcdoc
    // script so it runs under our strict no-inline-script CSP.
    CAP_SCRIPT_NONCE?: string;
  }
}

if (typeof window !== 'undefined') {
  window.CAP_CUSTOM_WASM_URL = wasmUrl;
  window.CAP_CUSTOM_HASHWX_URL = hashwxUrl;
  window.CAP_PAKO_URL = pakoUrl;
  // The server's instrumentation must not inherit the member page's origin or
  // inspect its interactions, cookies or storage. Keep behavior/agent blocking
  // off on the site key: those modes require access to the parent page.
  window.CAP_ISOLATE = true;
  window.CAP_DISABLE_WIDGET_REF = true;
}
