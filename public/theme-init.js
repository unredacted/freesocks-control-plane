// FOUC-prevention theme script. Extracted from an inline <script> in index.html
// so a strict Content-Security-Policy (script-src 'self', no 'unsafe-inline')
// can be enforced. Served same-origin at /theme-init.js, it runs synchronously
// before paint. Logic mirrors mode-watcher's setInitialMode; keep the storage
// key (mode-watcher-mode) and class name (dark) in sync with App.svelte.
(function () {
  try {
    const stored = localStorage.getItem('mode-watcher-mode');
    const mode = stored || 'dark';
    const prefersDark =
      window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const dark = mode === 'dark' || (mode === 'system' && prefersDark);
    const root = document.documentElement;
    if (dark) root.classList.add('dark');
    else root.classList.remove('dark');
    root.style.colorScheme = dark ? 'dark' : 'light';
  } catch (_) {
    // localStorage / matchMedia unavailable (restrictive privacy settings).
    // Fall through to dark by default.
    document.documentElement.classList.add('dark');
  }
})();

// Brand-theme FOUC replay (W3-3): re-inject the admin-selected palette the SPA
// cached on its last run, so a reload doesn't flash the baked default before the
// public-config query resolves. The cached value is the full :root/.dark
// override string built by src/client/lib/theme.ts — we just replay it here (no
// preset logic duplicated). First-ever visit has no cache → the baked default
// shows until the SPA applies the configured theme.
(function () {
  try {
    const css = localStorage.getItem('fs_theme_css');
    if (css) {
      const el = document.createElement('style');
      el.id = 'fs-theme';
      el.textContent = css;
      document.head.appendChild(el);
    }
  } catch (_) {
    /* no cached theme / storage blocked → the baked default shows */
  }
})();
