/**
 * Changing a backend's setup (docs/servers.md "Changing a backend's setup"),
 * pure and unit-tested: the sheet's input filled in from the current setup,
 * and what a change does, in words, before it runs. On a backend FCP writes,
 * the profile and every mode already set up stay exactly as they are (the
 * server refuses anything else): the zone for origin names changes in place,
 * and an added mode runs the setup again. A zone is known by its id: another
 * account holding the same zone id is the same zone. No em-dashes.
 */
import type { EdgeLocationAdmin } from '../../../../../shared/contracts/edges';
import type {
  BackendSetupInput,
  BackendSetupView,
  ModeSetupInput,
} from '../../../../../shared/contracts/servers';
import { shapeWords } from './words';

/**
 * A DNS account whose zones can hold origin names: the sheet lists its zones
 * from its catalog and its own locations (../../edges/forms/zones.ts).
 */
export interface OriginAccount {
  id: string;
  name: string;
  enabled: boolean;
  locations: readonly Pick<EdgeLocationAdmin, 'placement'>[];
}

/** The account and zone the sheet asks for; an empty `zoneId` is a zone not picked yet. */
export interface OriginPick {
  accountId: string;
  zoneId: string;
}

/** A zone the sheet knows by id and name. */
export interface OriginZone {
  id: string;
  name: string;
}

/** One mode as the sheet sends it, exactly as it was asked for. */
export function modeInputOf(m: BackendSetupView['modes'][number]): ModeSetupInput {
  return {
    slug: m.slug,
    name: m.name,
    shape: { ...m.shape },
    ...(m.familySlug ? { familySlug: m.familySlug } : {}),
    acceptProxyProtocol: m.acceptProxyProtocol,
    ...(m.ws ? { ws: { ...m.ws } } : {}),
  };
}

/** The sheet's starting point: the current setup, or null when there is none to start from. */
export function setupInputOf(
  view: BackendSetupView | null,
): Pick<BackendSetupInput, 'profileName' | 'modes' | 'originDns'> | null {
  if (!view?.exists || !view.profile || view.modes.length === 0) return null;
  return {
    profileName: view.profile.name,
    modes: view.modes.map(modeInputOf),
    originDns: view.originDns
      ? { accountId: view.originDns.accountId, zoneId: view.originDns.zoneId }
      : null,
  };
}

/**
 * The modes that are set up (their transport and group found): these stay as
 * they are. A mode a stopped run never got that far with may be changed or
 * taken out again.
 */
export function setUpSlugs(view: BackendSetupView | null): Set<string> {
  return new Set((view?.modes ?? []).filter((m) => m.transport && m.group.uuid).map((m) => m.slug));
}

/** The name of a zone, as far as the sheet knows it. */
function zoneOf(view: BackendSetupView, zoneId: string, zones: readonly OriginZone[]): string {
  const known = zones.find((z) => z.id === zoneId)?.name;
  if (known) return known;
  return view.originDns?.zoneId === zoneId ? view.originDns.zoneName : 'another zone';
}

export interface ChangeWords {
  /** Whether the change changes anything at all. */
  changed: boolean;
  /** What changes, one sentence each. */
  lines: string[];
  /** What sending it does, and what it leaves alone. */
  effect: string;
  /** The toast once it is sent. */
  done: string;
}

/**
 * What changing a set-up backend's setup to `next` does: the origin names
 * (recorded at once, nothing on the backend or a node moves) and the modes
 * added (the setup runs again; what is set up is found as it is). `zones` are
 * the zones the sheet lists, for their names. An account whose zone is not
 * picked yet changes nothing: the sheet asks for the zone before sending.
 */
export function setupChangeWords(
  view: BackendSetupView,
  next: { modes: readonly ModeSetupInput[]; origin: OriginPick | null },
  zones: readonly OriginZone[],
): ChangeWords {
  const generation = view.generation + 1;
  const setUp = setUpSlugs(view);
  const added = next.modes.filter((m) => !setUp.has(m.slug));
  const dropped = view.modes.filter(
    (v) => !setUp.has(v.slug) && !next.modes.some((m) => m.slug === v.slug),
  );
  const from = view.originDns ?? null;
  const pending = next.origin !== null && !next.origin.zoneId;
  const to = pending ? null : next.origin;
  const key = (o: OriginPick | null) => (o ? `${o.accountId}|${o.zoneId}` : '');
  const originMoved = !pending && key(from) !== key(to);
  const toName = to ? zoneOf(view, to.zoneId, zones) : null;
  const lines: string[] = [];
  if (originMoved) {
    if (!from) lines.push(`WebSocket nodes get their origin names under ${toName}.`);
    else if (!to)
      lines.push(
        `No zone for origin names any more: each WebSocket node enrolled from now on needs a hostname set by hand.`,
      );
    else if (from.zoneId === to.zoneId)
      lines.push(`Origin names stay under ${from.zoneName}, through another account.`);
    else lines.push(`Origin names move from ${from.zoneName} to ${toName}.`);
  }
  for (const m of added)
    lines.push(`Adds the mode ${m.name || m.slug || 'without a name'} (${shapeWords(m.shape)}).`);
  for (const m of dropped) lines.push(`Takes out the mode ${m.name}, which was never set up.`);
  if (added.length > 0 || dropped.length > 0)
    return {
      changed: true,
      lines,
      effect:
        `The setup runs again as generation ${generation}. The modes already set up are only ` +
        `looked at: their transports, groups and placements are not written, and the run stops ` +
        `if one of them changed on the backend` +
        (added.length === 0
          ? '. '
          : `, and ${
              added.length === 1 ? 'the new mode gets its' : 'the new modes get their'
            } group and placement. Its transport has to be in the profile already (Add a transport, on a node's page). `) +
        `Until the run is done no node can enroll or be approved; members are not affected.`,
      done: 'The setup runs again.',
    };
  if (originMoved)
    return {
      changed: true,
      lines,
      effect:
        `Recorded at once as generation ${generation}. Nothing on the backend changes, and no ` +
        `node that has a name or serves members is touched.` +
        (toName
          ? ` A WebSocket node still waiting for a name gets one under ${toName}: a new machine ` +
            `revision, which the node role applies on its next run.`
          : ''),
      done: 'Origin names changed. Nothing on the backend moved.',
    };
  return { changed: false, lines, effect: 'Nothing is changed yet.', done: '' };
}

/** One line on the Servers home about how the backend is set up. */
export function setupSummary(view: BackendSetupView): string {
  const n = view.modes.length;
  const head = `${view.adopted ? 'Adopted and set up' : 'Set up'} for ${n} mode${
    n === 1 ? '' : 's'
  } (generation ${view.generation}).`;
  if (view.originDns) return `${head} Origin names under ${view.originDns.zoneName}.`;
  return view.modes.some((m) => m.shape.transport === 'ws')
    ? `${head} No zone for origin names, so each WebSocket node needs a hostname set by hand.`
    : `${head} No zone for origin names.`;
}
