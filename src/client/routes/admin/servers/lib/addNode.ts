/**
 * "Add a node" by hand (pure; unit-tested): the form's checks and the
 * placement check it shows BEFORE anything is sent. A node is only useful to
 * members when a mode group lists one of its transports and a connection mode
 * issues keys into that group (its pool). The node role is the normal way a
 * node arrives; this is for a machine the role does not run.
 *
 * Exports:
 *   nodeFormProblems(form)                     what keeps the form from being sent, in words
 *   placementCheck(transports, groups, pools)  per transport: the mode groups that list it;
 *                                              per pool: what the backend says about it
 *   placementLines(check)                      the check as plain lines (ok / warn)
 */
import type { PlacementValidation, ServerTree } from '../../../../../shared/contracts/servers';

export interface NodeForm {
  name: string;
  address: string;
  port: string;
  countryCode: string;
  profileUuid: string;
  transportUuids: string[];
}

/** Node names are how a lost create is found again: one plain label, like the role sends. */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

export function nodeFormProblems(f: NodeForm, takenNames: readonly string[] = []): string[] {
  const out: string[] = [];
  const name = f.name.trim();
  if (!name) out.push('Give the node a name.');
  else if (!NAME_RE.test(name))
    out.push('Use letters, digits, dots, dashes or underscores in the name (up to 63).');
  else if (takenNames.some((n) => n.toLowerCase() === name.toLowerCase()))
    out.push('Another node already has this name.');
  if (!f.address.trim()) out.push('Say where the backend reaches the node.');
  if (f.port.trim() !== '') {
    const port = Number(f.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      out.push('The port is a whole number from 1 to 65535.');
  }
  if (f.countryCode.trim() !== '' && !/^[A-Za-z]{2}$/.test(f.countryCode.trim()))
    out.push('The country code is two letters.');
  if (!f.profileUuid) out.push('Pick the profile it runs.');
  else if (f.transportUuids.length === 0) out.push('Pick at least one transport it serves.');
  return out;
}

type Group = ServerTree['modeGroups'][number];

export interface PlacementCheck {
  transports: Array<{ transportUuid: string; tag: string; groups: string[] }>;
  pools: PlacementValidation['modes'];
}

export function placementCheck(
  transports: ReadonlyArray<{ transportUuid: string; tag: string }>,
  groups: readonly Group[],
  pools: PlacementValidation | null,
): PlacementCheck {
  return {
    transports: transports.map((t) => ({
      transportUuid: t.transportUuid,
      tag: t.tag,
      groups: groups
        .filter((g) => g.transportUuids.includes(t.transportUuid))
        .map((g) => g.name)
        .sort((a, b) => a.localeCompare(b)),
    })),
    pools: pools?.modes ?? [],
  };
}

export interface PlacementLine {
  ok: boolean;
  text: string;
}

const list = (xs: readonly string[]) =>
  xs.length <= 1 ? (xs[0] ?? '') : `${xs.slice(0, -1).join(', ')} and ${xs.at(-1)}`;

export function placementLines(c: PlacementCheck): PlacementLine[] {
  const out: PlacementLine[] = [];
  for (const t of c.transports) {
    out.push(
      t.groups.length > 0
        ? {
            ok: true,
            text: `${t.tag} is in the mode group${t.groups.length === 1 ? '' : 's'} ${list(t.groups)}.`,
          }
        : {
            ok: false,
            text: `${t.tag} is in no mode group, so no member can reach it through this node yet.`,
          },
    );
  }
  for (const p of c.pools) {
    if (p.modeGroups === 0) {
      out.push({
        ok: false,
        text: `The ${p.modeSlug} pool is empty: that mode issues no keys here.`,
      });
      continue;
    }
    if (p.unknownHere > 0)
      out.push({
        ok: false,
        text: `The ${p.modeSlug} pool names ${p.unknownHere} mode group${p.unknownHere === 1 ? '' : 's'} this backend does not have (it may be on another backend).`,
      });
    if (p.withoutTransports.length > 0)
      out.push({
        ok: false,
        text: `In the ${p.modeSlug} pool, ${list(p.withoutTransports)} ${p.withoutTransports.length === 1 ? 'lists' : 'list'} no transport.`,
      });
    if (p.unknownHere === 0 && p.withoutTransports.length === 0)
      out.push({
        ok: true,
        text: `The ${p.modeSlug} pool has ${p.modeGroups} mode group${p.modeGroups === 1 ? '' : 's'}.`,
      });
  }
  return out;
}
