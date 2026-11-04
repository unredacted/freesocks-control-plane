/**
 * Words for where members are told a location is (docs/edges.md "Names in
 * apps"): the line under a location and the preview in its dialog, built by
 * the renderer's own naming function (src/shared/entryNames.ts), so what an
 * admin reads here is what members read in their apps. Pure, so the sentences
 * are tested.
 */
import {
  MAX_PLACE_NAME,
  cleanNamePart,
  entryBase,
  placeCountry,
} from '../../../../../shared/entryNames';

/** The line under a location (or the dialog's preview) for a place as stored or typed. */
export function memberPlaceLine(place: { name: string | null; country: string | null }): string {
  const p = {
    name: cleanNamePart(place.name ?? '', MAX_PLACE_NAME) || null,
    country: placeCountry(place.country),
  };
  if (!p.name)
    return `In members' apps: "${entryBase({ kind: 'relay', place: p, letter: 'A' })}". No place name yet, so no flag either.`;
  const one = entryBase({ kind: 'relay', place: p, letter: null });
  const a = entryBase({ kind: 'relay', place: p, letter: 'A' });
  return `In members' apps: "${one}" ("${a}", "B" for a member with two addresses here).`;
}

/** The line under a CDN zone: its fronts never carry a place. */
export const CDN_PLACE_LINE = `In members' apps: "${entryBase({ kind: 'cdn', n: 1 })}", "2" and so on, numbered in each member's app, never named after a place or the CDN.`;
