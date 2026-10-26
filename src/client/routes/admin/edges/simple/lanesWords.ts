/**
 * The node page's "Trusted addresses" card (address lanes, docs/edges.md
 * "Address enumeration"): what lanes do, what switching them on and off does
 * to the addresses in use, and one line per transport. No em-dashes in this copy.
 */
import type { LanesView } from '@shared/contracts/edges';

export const LANES_CARD = {
  title: 'Trusted addresses',
  off: (days: number) =>
    `Every member of this node may be handed every address, so an account a censor signs up sees them all. With trusted addresses, new free accounts get only a few open addresses, which are expected to be blocked; the trusted ones go only to paid members and accounts older than ${days} days.`,
  setUp: 'Set up trusted addresses',
  change: 'Change',
  turnOff: 'Turn off',
} as const;

export const LANES_DIALOG = {
  title: 'Trusted addresses',
  open: 'Open addresses per transport',
  openHelp: 'Handed to new and suspected accounts. 0 leaves those accounts without an address.',
  trusted: 'Trusted addresses per transport',
  trustedHelp: 'Handed only to paid members and older accounts. Each one is a load balancer.',
  onBody:
    'Every address in use now has been handed to everyone, so it becomes open. FCP makes new trusted addresses and takes the old open ones out of use once those are in. While no open address works, new free accounts get nothing.',
  changeBody: 'The new numbers apply from the next automatic pass.',
  turnOn: 'Turn on',
  save: 'Save',
} as const;

export const LANES_OFF = {
  title: 'Turn trusted addresses off?',
  body: 'Every member may then be handed every address, so the trusted ones become open for good. Turning them on again starts with new addresses.',
  label: 'Turn off',
} as const;

/** One line per transport: what each lane holds against its target. */
export function laneLine(
  t: LanesView['transports'][number],
  targets: { open: number; trusted: number },
): string {
  const parts = [`${t.trusted} of ${targets.trusted} trusted`, `${t.open} of ${targets.open} open`];
  if (t.openExcess > 0)
    parts.push(
      t.trustedDeficit > 0
        ? `${t.openExcess} old ${t.openExcess === 1 ? 'address leaves' : 'addresses leave'} once the trusted ones are in`
        : `${t.openExcess} old ${t.openExcess === 1 ? 'address is' : 'addresses are'} leaving`,
    );
  return parts.join(', ') + '.';
}

export function openBudgetLine(view: Pick<LanesView, 'openReplacesToday' | 'openReplacesPerDay'>) {
  return `Open addresses replaced today: ${view.openReplacesToday} of ${view.openReplacesPerDay}.`;
}

/** The dialog's numbers, checked as the server checks them; null when they are fine. */
export function lanesInputProblem(open: number, trusted: number): string | null {
  const ok = (n: number, min: number) => Number.isInteger(n) && n >= min && n <= 32;
  if (!ok(open, 0)) return 'Open addresses: a whole number from 0 to 32.';
  if (!ok(trusted, 1)) return 'Trusted addresses: a whole number from 1 to 32.';
  return null;
}
