/**
 * Words for where members are told a location is (docs/edges.md "Names in
 * apps"): the line under a location and the preview in its dialog, built by
 * the renderer's own naming function (src/shared/entryNames.ts), so what an
 * admin reads here is what members read in their apps. A name leads with the
 * node's own place (`🇨🇦 Example City via …`), which differs per node, so the
 * words show it as "…". Pure, so the sentences are tested.
 */
import {
  MAX_PLACE_NAME,
  cleanNamePart,
  entryBase,
  placeCountry,
  type MemberPlace,
} from '../../../../../shared/entryNames';

/** Stands for the node's own place (its location label and flag) in these words. */
const NODE_PLACE: MemberPlace = { name: '…', country: null };

/** The line under a location (or the dialog's preview) for a place as stored or typed. */
export function memberPlaceLine(place: { name: string | null; country: string | null }): string {
  const p = {
    name: cleanNamePart(place.name ?? '', MAX_PLACE_NAME) || null,
    country: placeCountry(place.country),
  };
  const lead = `In members' apps, after the node's own place:`;
  if (!p.name)
    return `${lead} "${entryBase({ kind: 'relay', place: p, letter: 'A', exit: NODE_PLACE })}". No place name yet.`;
  const one = entryBase({ kind: 'relay', place: p, letter: null, exit: NODE_PLACE });
  const a = entryBase({ kind: 'relay', place: p, letter: 'A', exit: NODE_PLACE });
  const flag = p.country
    ? ` The country's flag shows only for a node with no place of its own ("${entryBase({ kind: 'relay', place: p, letter: null })}").`
    : '';
  return `${lead} "${one}" ("${a}", "B" for a member with two addresses here).${flag}`;
}

/** The line under a CDN zone: its fronts never carry a place. */
export const CDN_PLACE_LINE = `In members' apps, after the node's own place: "${entryBase({ kind: 'cdn', n: 1, exit: NODE_PLACE })}", "2" and so on, numbered in each member's app, never named after a place or the CDN.`;
