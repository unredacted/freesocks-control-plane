/**
 * The onboarding mirror suggestion (/get-account step 3, MirrorSuggestion):
 * when it shows, and which link the member's app gets once there is a choice.
 * Also what it shares with MirrorHelp: one pending mirror request at a time,
 * and the account-cache writes that keep the key's mirror list current.
 */

/**
 * The mutation key both mirror buttons (MirrorSuggestion, MirrorHelp) request
 * under: each disables while ANY request for the key is in flight, so two can't
 * race to the same provider from one page.
 */
export const MIRROR_REQUEST_KEY = ['mirror', 'request'] as const;

/**
 * The country the onboarding suggestion speaks about: the member's own stored
 * answer when they gave one (the opt-out means none: their answer wins over
 * this request's country), else THIS request's country when the server says it
 * is on the censored-country list (`geoCountryCensored`).
 */
export function suggestionCountry(o: {
  geoCountry?: string | null;
  geoCountryCensored?: boolean;
  /** The key's stored answer (a listed country or `ZZ`), from the sealed view. */
  storedChoice?: string | null;
}): string | null {
  if (o.storedChoice === 'ZZ') return null;
  if (o.storedChoice) return o.storedChoice;
  return o.geoCountry && o.geoCountryCensored === true ? o.geoCountry : null;
}

/**
 * Whether onboarding suggests a mirror link: there is a country to speak about
 * (`suggestionCountry`), the deployment has mirrors, and the mode delivers a
 * link (rawConfig modes get no public mirrors). No country, no suggestion,
 * whatever the flag says.
 */
export function mirrorSuggested(o: {
  geoCountry?: string | null;
  geoCountryCensored?: boolean;
  storedChoice?: string | null;
  mirrorsEnabled?: boolean;
  rawConfig: boolean;
}): boolean {
  return o.mirrorsEnabled === true && !o.rawConfig && suggestionCountry(o) !== null;
}

/** The key's mirror links, in the server's order, without the main link or repeats. */
export function mirrorLinks(
  mirrors: readonly { publicUrl: string }[],
  subscriptionUrl: string,
): string[] {
  const out: string[] = [];
  for (const m of mirrors)
    if (m.publicUrl && m.publicUrl !== subscriptionUrl && !out.includes(m.publicUrl))
      out.push(m.publicUrl);
  return out;
}

/**
 * The link the member's app gets (the pass's copy, download and QR, and the
 * app list's import buttons): their pick while it is still on offer, else the
 * first mirror (the recommendation), else the main link.
 */
export function chosenLink(
  subscriptionUrl: string,
  mirrors: readonly string[],
  picked: string | null,
): string {
  if (picked && (picked === subscriptionUrl || mirrors.includes(picked))) return picked;
  return mirrors[0] ?? subscriptionUrl;
}

/**
 * The account view with a mirror just added: the suggestion writes it into the
 * cached view at once, so the pass, the choice and MirrorHelp all see it before
 * the refetch lands (and a failed refetch can't bring the create button back
 * for a second, unwanted mirror). The refetch then replaces it with the server's.
 */
export function withMirror<
  V extends { subscription: { mirrors: { provider: string; publicUrl: string }[] } | null },
>(view: V | undefined, mirror: { provider: string; publicUrl: string }): V | undefined {
  if (!view?.subscription) return view;
  if (view.subscription.mirrors.some((m) => m.publicUrl === mirror.publicUrl)) return view;
  return {
    ...view,
    subscription: { ...view.subscription, mirrors: [...view.subscription.mirrors, mirror] },
  };
}

/**
 * The account view with no mirrors: "Remove all mirrors" clears the cached view
 * at once, so a link picked from the removed mirrors stops reaching the pass and
 * the app buttons even if the refetch fails.
 */
export function withoutMirrors<
  V extends { subscription: { mirrors: { provider: string; publicUrl: string }[] } | null },
>(view: V | undefined): V | undefined {
  if (!view?.subscription || view.subscription.mirrors.length === 0) return view;
  return { ...view, subscription: { ...view.subscription, mirrors: [] } };
}
