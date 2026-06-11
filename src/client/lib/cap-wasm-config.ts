/**
 * Point the Cap widget's proof-of-work WASM + pako loader at SAME-ORIGIN bundled
 * assets instead of its built-in `cdn.jsdelivr.net` defaults. Without this the
 * captcha fetches from a third-party CDN — which would reintroduce a third-party
 * runtime dependency AND break in regions where jsdelivr is blocked, defeating
 * the entire point of self-hosting Cap (W1).
 *
 * Vite emits these as hashed assets under /assets (served same-origin by Caddy).
 * Versions are pinned to match what the widget expects (@cap.js/wasm@0.0.7 — its
 * WASM hash is checked — and pako@2.1.0). Imported for its side effect BEFORE
 * `@cap.js/widget` so the globals are set before the lazy loader reads them.
 */
import wasmUrl from '@cap.js/wasm/browser/cap_wasm_bg.wasm?url';
import pakoUrl from 'pako/dist/pako_inflate.min.js?url';

declare global {
  interface Window {
    CAP_CUSTOM_WASM_URL?: string;
    CAP_PAKO_URL?: string;
  }
}

if (typeof window !== 'undefined') {
  window.CAP_CUSTOM_WASM_URL = wasmUrl;
  window.CAP_PAKO_URL = pakoUrl;
}
