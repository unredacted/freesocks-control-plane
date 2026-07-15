/**
 * Scroll-triggered reveal action. Svelte `in:` transitions run at mount, so
 * below-the-fold sections used to play their entrance while invisible; this
 * action defers the entrance (pure CSS, see `[data-reveal]` in globals.css)
 * until the element actually scrolls into view.
 *
 * Fail-open by design: content must never stay hidden. Reduced motion, a
 * missing IntersectionObserver, or any other bail-out path reveals immediately.
 */
export interface RevealOptions {
  /** Fires once, when the element reveals (drives e.g. the impact count-up). */
  onReveal?: () => void;
}

export function reveal(node: HTMLElement, opts: RevealOptions = {}) {
  let fired = false;
  const show = () => {
    if (fired) return;
    fired = true;
    node.setAttribute('data-revealed', '');
    opts.onReveal?.();
  };

  if (
    typeof IntersectionObserver === 'undefined' ||
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  ) {
    show();
    return {};
  }

  // Only now opt the element into the hidden initial state: if the observer
  // can't run, the attribute never lands and the content renders normally.
  node.setAttribute('data-reveal', '');
  let gotCallback = false;
  const io = new IntersectionObserver(
    (entries) => {
      gotCallback = true;
      if (entries.some((e) => e.isIntersecting)) {
        io.disconnect();
        show();
      }
    },
    { threshold: 0.2 },
  );
  io.observe(node);
  // Inertness probe: a working IntersectionObserver ALWAYS delivers an initial
  // callback shortly after observe (intersecting or not). If none arrives, the
  // observer isn't ticking (e.g. a non-painting/embedded renderer) - reveal
  // rather than leave content at opacity 0 forever.
  const failsafe = setTimeout(() => {
    if (!gotCallback) {
      io.disconnect();
      show();
    }
  }, 1500);
  return {
    destroy() {
      clearTimeout(failsafe);
      io.disconnect();
    },
  };
}
