/**
 * Changing a backend's setup (docs/servers.md "Changing a backend's setup"),
 * pure and unit-tested: the sheet's input filled in from the current setup,
 * and what a change does, in words, before it runs. On a backend FCP writes,
 * the profile and every mode already set up stay exactly as they are (the
 * server refuses anything else): the zone for origin names changes in place,
 * and an added mode runs the setup again. No em-dashes.
 */
import type {
  BackendSetupInput,
  BackendSetupView,
  ModeSetupInput,
} from '../../../../../shared/contracts/servers';
import { shapeWords } from './words';

/** A Cloudflare account whose zone can hold origin names. */
export interface OriginAccount {
  id: string;
  name: string;
  zoneName: string;
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
    originDns: view.originDns ? { accountId: view.originDns.accountId } : null,
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

/** The zone an account holds, as far as the sheet knows it. */
function zoneOf(
  view: BackendSetupView,
  accountId: string,
  accounts: readonly OriginAccount[],
): string | null {
  if (!accountId) return null;
  const known = accounts.find((a) => a.id === accountId)?.zoneName;
  if (known) return known;
  return view.originDns?.accountId === accountId ? view.originDns.zoneName : 'another zone';
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
 * added (the setup runs again; what is set up is found as it is).
 */
export function setupChangeWords(
  view: BackendSetupView,
  next: { modes: readonly ModeSetupInput[]; originAccountId: string },
  accounts: readonly OriginAccount[],
): ChangeWords {
  const generation = view.generation + 1;
  const setUp = setUpSlugs(view);
  const added = next.modes.filter((m) => !setUp.has(m.slug));
  const dropped = view.modes.filter(
    (v) => !setUp.has(v.slug) && !next.modes.some((m) => m.slug === v.slug),
  );
  const from = view.originDns?.zoneName ?? null;
  const to = zoneOf(view, next.originAccountId, accounts);
  const originMoved = (view.originDns?.accountId ?? '') !== next.originAccountId;
  const lines: string[] = [];
  if (originMoved) {
    if (!from) lines.push(`WebSocket nodes get their origin names under ${to}.`);
    else if (!to)
      lines.push(
        `No zone for origin names any more: each WebSocket node enrolled from now on needs a hostname set by hand.`,
      );
    else if (from === to) lines.push(`Origin names stay under ${to}, through another account.`);
    else lines.push(`Origin names move from ${from} to ${to}.`);
  }
  for (const m of added)
    lines.push(`Adds the mode ${m.name || m.slug || 'without a name'} (${shapeWords(m.shape)}).`);
  for (const m of dropped) lines.push(`Takes out the mode ${m.name}, which was never set up.`);
  if (added.length > 0 || dropped.length > 0)
    return {
      changed: true,
      lines,
      effect:
        `The setup runs again as generation ${generation}. The modes already set up are found as ` +
        `they are, so nothing a node or a member uses is written` +
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
        `Recorded at once as generation ${generation}. Nothing on the backend or on any node ` +
        `changes${to ? `, and a WebSocket node waiting for a name gets one under ${to}` : ''}.`,
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
