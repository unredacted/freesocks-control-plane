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
