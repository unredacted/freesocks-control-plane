/**
 * The server-call attention actions, run (pure: every call and effect is injected).
 *
 * AttentionList confirms a call action (lib/attention.ts ATTENTION_ACTION_PLAN)
 * and hands it to the host page's `onAction`. Both host pages, the Nodes home
 * (plain words) and All origins, run it here, so a confirmed call does what its
 * confirm said: a publish publishes the standby the item names and opens the
 * rotation, it never only navigates. The switch covers every AttentionAction
 * (a new one fails typecheck).
 *
 *   publish, rotate, provision  the call, then the host opens the rotation
 *   qualify_front, test_credentials, thaw, rebalance   the call, then a toast
 *   verify_endpoint, require_edges  the host's `openTest` / `goLive`; without
 *                               one the row navigates to the node page
 *   an item without the ids its call needs (attentionCallable), and every
 *   navigate action: navigate to attentionTarget(item)
 *
 * A failed call throws. The confirmed ones fail inside their dialog (which shows
 * the reason); the others go to `deps.failed` first (a toast).
 *
 * Exports: runAttentionCall(item, deps), AttentionCallDeps, AttentionCallApi.
 */
import { codeLabel } from '../../../../lib/edgeCodes';
import { ATTENTION_ACTION_PLAN, attentionCallable, attentionTarget } from './attention';
import type { AttentionItem } from './attention';

type Started = Promise<{ rotationId: string }>;
type Checked = Promise<{ ok: boolean; code?: string | null }>;

/** The edge calls the actions make (edgesApi in the app, fakes in the tests). */
export interface AttentionCallApi {
  publish: (relayId: string, edgeId: string) => Started;
  rotate: (relayId: string, edgeId: string) => Started;
  provision: (relayId: string) => Started;
  qualify: (edgeId: string) => Checked;
  testCredentials: (accountId: string) => Checked;
  thaw: () => Promise<unknown>;
  rebalance: (relayId: string) => Promise<unknown>;
}

export interface AttentionCallDeps {
  api: AttentionCallApi;
  /** The simple screens: toasts in plain words. */
  plain: boolean;
  navigate: (href: string) => void;
  /** A started rotation (publish, rotate, provision): where the operator follows it. */
  openRotation: (item: AttentionItem, rotationId: string) => void;
  /** verify_endpoint in place (the test card); without it the row navigates. */
  openTest?: (item: AttentionItem) => void;
  /** require_edges in place (go live); without it the row navigates. */
  goLive?: (item: AttentionItem) => Promise<void>;
  success: (message: string) => void;
  error: (message: string) => void;
  /** A call that threw and has no dialog to show it (edgeErrorMessage in a toast). */
  failed: (e: unknown) => void;
  refresh: {
    /** The item's origin when it names one, else the overview. */
    item: (item: AttentionItem) => void;
    config: () => void;
    providers: () => void;
  };
}

const STARTED = {
  publish: {
    advanced: 'Publishing started. Follow the run on the origin page.',
    plain: 'Putting the address in use. Its progress opens now.',
  },
  rotate: {
    advanced: 'Replacement started. Follow the run on the origin page.',
    plain: 'Replacing the address. Its progress opens now.',
  },
  provision: {
    advanced: 'Provisioning started. Follow the run on the origin page.',
    plain: 'Creating an address. Its progress opens now.',
  },
} as const;

/** Run one attention item's action (see the header for what each one does). */
export async function runAttentionCall(
  item: AttentionItem,
  deps: AttentionCallDeps,
): Promise<void> {
  const words = deps.plain ? 'plain' : 'advanced';
  const plan = ATTENTION_ACTION_PLAN[item.action];
  if (plan.type === 'navigate' || !attentionCallable(item)) {
    deps.navigate(attentionTarget(item));
    return;
  }
  try {
    switch (item.action) {
      case 'publish':
      case 'rotate':
      case 'provision': {
        const res =
          item.action === 'provision'
            ? await deps.api.provision(item.relayId!)
            : await deps.api[item.action](item.relayId!, item.edgeId!);
        deps.success(STARTED[item.action][words]);
        deps.refresh.item(item);
        deps.openRotation(item, res.rotationId);
        return;
      }
      case 'qualify_front': {
        const res = await deps.api.qualify(item.edgeId!);
        if (res.ok)
          deps.success(
            deps.plain ? 'The address passed the check.' : 'The front passed qualification.',
          );
        else {
          const lead = deps.plain
            ? 'The address did not pass the check'
            : 'The front did not qualify';
          deps.error(res.code ? `${lead}: ${codeLabel(res.code)}.` : `${lead}.`);
        }
        deps.refresh.item(item);
        return;
      }
      case 'test_credentials': {
        const res = await deps.api.testCredentials(item.accountId!);
        if (res.ok) deps.success('The provider accepted the credentials.');
        else
          deps.error(
            res.code
              ? `The credential test failed: ${codeLabel(res.code)}.`
              : 'The credential test failed.',
          );
        deps.refresh.providers();
        return;
      }
      case 'thaw':
        await deps.api.thaw();
        deps.success(deps.plain ? 'New work is allowed again.' : 'New edge work is allowed again.');
        deps.refresh.config();
        return;
      case 'rebalance':
        await deps.api.rebalance(item.relayId!);
        deps.success(
          deps.plain
            ? 'Made room. The uncovered transport gets its address next.'
            : 'Made room. The uncovered listener gets its edge next.',
        );
        deps.refresh.item(item);
        return;
      case 'verify_endpoint':
        if (deps.openTest) deps.openTest(item);
        else deps.navigate(attentionTarget(item));
        return;
      case 'require_edges':
        if (deps.goLive) await deps.goLive(item);
        else deps.navigate(attentionTarget(item));
        return;
      // The navigate actions returned above.
      case 'resolve_quarantine':
      case 'resolve_operator':
      case 'look_at_host':
      case 'open_setup':
      case 'open_relay':
      case 'open_edge':
      case 'open_account':
      case 'open_settings':
      case 'protect_node':
      case 'open_node':
      case 'open_modes':
      case 'open_probes':
        deps.navigate(attentionTarget(item));
        return;
      default: {
        const unhandled: never = item.action;
        throw new Error(`unhandled attention action ${String(unhandled)}`);
      }
    }
  } catch (e) {
    if (!plan.confirm) deps.failed(e);
    throw e;
  }
}
