/**
 * Which templates a page lists, and where an old provider-filtered Templates
 * address lands now (pure; unit-tested in list.test.ts).
 *
 * Templates fold into each provider account (its Templates tab, every
 * template that account can use); "All templates" stays at
 * `/admin/servers/providers/templates`. The old `?provider=P[&template=T]`
 * view of that page is the account's tab now: it lands on the first account of
 * provider P (the Providers list order), or on the account a template T
 * belongs to when T is only for one account of P. With no account of P the
 * page stays and filters.
 *
 * Exports:
 *   availableTo(templates, account)            the templates an account can provision from
 *   templateRedirect(params, accounts, list)   the account tab to land on, or null to stay
 */
import { EDGE_PROVIDER_IDS } from '../../../../../shared/contracts/edges';
import { sortAccounts } from '../providers/accountList';
import { edgesPaths } from '../lib/routes';

interface TemplateLike {
  id: string;
  provider: string;
  accountId: string | null;
}
interface AccountLike {
  id: string;
  provider: string;
  enabled: boolean;
  name: string;
}

/** Its own templates and the ones shared by every account of its provider. */
export function availableTo<T extends TemplateLike>(
  templates: readonly T[],
  account: Pick<AccountLike, 'id' | 'provider'>,
): T[] {
  return templates.filter(
    (t) => t.provider === account.provider && (t.accountId === null || t.accountId === account.id),
  );
}

/**
 * `params` are the page's `?provider` and `?template`. A new template
 * (`template=new`) stays: that is All templates' own "New template".
 * `templates` may be null while they load; the first account is used then.
 */
export function templateRedirect(
  params: { provider: string | null; template: string | null },
  accounts: readonly AccountLike[],
  templates: readonly TemplateLike[] | null,
): string | null {
  const p = params.provider ?? '';
  if (!(EDGE_PROVIDER_IDS as readonly string[]).includes(p)) return null;
  const template = params.template || null;
  if (template === 'new') return null;
  const ofProvider = sortAccounts(accounts.filter((a) => a.provider === p));
  if (ofProvider.length === 0) return null;
  const owner = template ? templates?.find((t) => t.id === template)?.accountId : null;
  const target = ofProvider.find((a) => a.id === owner) ?? ofProvider[0]!;
  return edgesPaths.provider(target.id, { tab: 'templates', template: template ?? undefined });
}
