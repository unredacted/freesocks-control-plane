/**
 * Links into the home page's sections (How it works, Membership, FAQ, the
 * threat-model tab) from the header and footer on any page. The router keeps
 * its own scroll positions and resets to the top on popstate, so these never
 * change the URL hash: they navigate to "/" when needed and scroll in JS.
 */
import { tick } from 'svelte';
import { router } from '../stores/router.svelte';

export type FaqTab = 'general' | 'threat';

/** The FAQ section's open tab, shared so a "What we protect you from" link
 *  can open the threat-model tab from anywhere. */
export const homeFaq = $state<{ tab: FaqTab }>({ tab: 'general' });

export const THREAT_MODEL_ID = 'threat-model';
export const FAQ_ID = 'faq';

function scrollToSection(id: string) {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.getElementById(id)?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' });
}

/** Click handler for an `<a href="/#id">`: modified clicks keep the browser's
 *  own behavior (new tab, and so on). */
export async function goToSection(e: MouseEvent, id: string): Promise<void> {
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
  e.preventDefault();
  // The threat-model link opens that tab; a plain FAQ link opens the general
  // one, so it never lands on whichever tab an earlier link left open.
  if (id === THREAT_MODEL_ID) homeFaq.tab = 'threat';
  else if (id === FAQ_ID) homeFaq.tab = 'general';
  if (router.pathname === '/') {
    scrollToSection(id);
    return;
  }
  router.navigate('/');
  await tick();
  // Double rAF: the home route remounts on the next flush.
  requestAnimationFrame(() => requestAnimationFrame(() => scrollToSection(id)));
}
