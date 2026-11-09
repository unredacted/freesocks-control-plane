/**
 * The section state of a node's page (nodeSections.ts has the pure rules):
 * which section the URL names, whether the Technical details fold is open,
 * and scrolling to a section. Call from a page's script (it sets up effects).
 *
 *   const nav = nodeSectionState(() => ready);
 *   nav.section          the section `?section=` names, or null
 *   nav.detailsOpen      the fold (opens with `?section=details` or any origin page param)
 *   nav.pick(id)         section bar: names it in the URL and scrolls there
 *   nav.toggleDetails()  the fold's own button
 *   sectionId(id)        the element id of a section
 */
import { router } from '@client/stores/router.svelte';
import { setSearchParams } from '@client/lib/urlState.svelte';
import { detailsOpenFor, parseSection, type NodeSection } from './nodeSections';

export const sectionId = (id: NodeSection) => `node-${id}`;

function scrollTo(id: NodeSection): void {
  requestAnimationFrame(() =>
    document.getElementById(sectionId(id))?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
  );
}

export function nodeSectionState(ready: () => boolean) {
  let detailsOpen = $state(detailsOpenFor(router.search));
  // A link that names a tab, an edge or a rotation opens the fold.
  $effect(() => {
    if (detailsOpenFor(router.search)) detailsOpen = true;
  });
  // Once the page has drawn, go to the section the address names (once).
  let scrolled = false;
  $effect(() => {
    if (scrolled || !ready()) return;
    const s = parseSection(router.searchParams.get('section'));
    scrolled = true;
    if (s && s !== 'summary') scrollTo(s);
  });

  return {
    get section(): NodeSection | null {
      return parseSection(router.searchParams.get('section'));
    },
    get detailsOpen(): boolean {
      return detailsOpen;
    },
    pick(id: NodeSection): void {
      setSearchParams({ section: id === 'summary' ? null : id });
      if (id === 'details') detailsOpen = true;
      scrollTo(id);
    },
    toggleDetails(): void {
      if (detailsOpen) {
        detailsOpen = false;
        // Closing drops what would open it again.
        const patch: Record<string, null> = {
          tab: null,
          edge: null,
          rotation: null,
          listener: null,
        };
        if (router.searchParams.get('section') === 'details') patch.section = null;
        setSearchParams(patch);
      } else {
        detailsOpen = true;
        setSearchParams({ section: 'details' });
      }
    },
  };
}
