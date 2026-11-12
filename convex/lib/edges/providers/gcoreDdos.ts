/**
 * Gcore Advanced DDoS protection for a Gcore load balancer edge (Cloud API
 * `/cloud/v1/ddos/*`). Gcore protects an IP ADDRESS: a profile names one
 * address and one of the region's profile templates, and Gcore works out the
 * resource (here the load balancer) from the address. Every write is a task.
 *
 * Three uses:
 *  - PROVISIONING: when the template asks for it (`ddosProtection` `on` or
 *    `required`), a second step after the load balancer protects its public
 *    IPv4 (the address every member is given). `required` stops the run on any
 *    refusal (no edge is made unprotected); `on` lets the edge go on without
 *    it. The step's opRef carries what it needs between polls (pollStep is not
 *    given the template).
 *  - THE EDGE PAGE: a view (region coverage, the region's profile templates,
 *    the profiles on the edge's addresses, Gcore's price) and on/off/remove.
 *    These do not touch the ledger: a profile they make is found again by
 *    address, and the load balancer's destroy removes it first.
 *  - DESTROY: a ledgered profile goes before the load balancer
 *    (`GCORE_DESTROY_ORDER`), and the load balancer's own delete first removes
 *    any profile still on its addresses (`sweepProfiles`), so no profile is left
 *    billing on an address the edge gave back.
 *
 * Errors carry codes only (`ddos_*`), never Gcore's words or ids beyond the
 * profile number.
 */
import { z } from 'zod';
import type {
  Addresses,
  ChildResource,
  Discovery,
  GcoreConfig,
  Ledger,
  LedgerResource,
  DestroyOutcome,
  EdgeDdosChange,
  EdgeDdosChangeResult,
  EdgeDdosProfileView,
  EdgeDdosView,
  StepOutcome,
} from './types';
import { firstResource, metaOf, stepOf } from './types';
import { discoveryMaySettle } from './capabilities';
import { EdgeProviderError, isProviderNotFound, refusedCreate } from './http';
import {
  GcoreTasks,
  gcore,
  gcoreLbAddresses,
  gcoreScope,
  gcoreTask,
  getGcoreLb,
  taskState,
  type GcoreLbBody,
} from './gcoreHttp';
import type { GcoreDdosMode, GcoreTemplateParams } from './templates';

// --- schemas (lenient: only the fields we read) -------------------------------------

const AccessStatus = z
  .object({ is_accessible: z.boolean(), message: z.string().nullish() })
  .passthrough();
const ProfileTemplate = z
  .object({ id: z.number(), name: z.string().nullish(), description: z.string().nullish() })
  .passthrough();
const ProfileTemplateList = z
  .object({ results: z.array(ProfileTemplate).default([]) })
  .passthrough();
const Profile = z
  .object({
    id: z.number(),
    ip_address: z.string().nullish(),
    options: z
      .object({ active: z.boolean().nullish(), bgp: z.boolean().nullish() })
      .passthrough()
      .nullish(),
    status: z
      .object({ status: z.string().nullish(), error_description: z.string().nullish() })
      .passthrough()
      .nullish(),
    profile_template: z
      .object({ id: z.number().nullish(), name: z.string().nullish() })
      .passthrough()
      .nullish(),
    managed_by: z.string().nullish(),
  })
  .passthrough();
type ProfileBody = z.infer<typeof Profile>;
const ProfileList = z.object({ results: z.array(Profile).default([]) }).passthrough();
const Price = z
  .object({
    price: z
      .object({
        feature_name: z.string().nullish(),
        price_currency: z.string().nullish(),
        price_per_30d: z.number().nullish(),
        price_per_day: z.number().nullish(),
        unit_name: z.string().nullish(),
      })
      .passthrough()
      .nullish(),
  })
  .passthrough();

// --- the calls ---------------------------------------------------------------------------

const profilesPath = (cfg: GcoreConfig) => `/cloud/v1/ddos/profiles/${gcoreScope(cfg)}`;
const profilePath = (cfg: GcoreConfig, id: string | number) =>
  `${profilesPath(cfg)}/${encodeURIComponent(String(id))}`;

/** Whether the region has Advanced DDoS protection at all. */
async function regionAccess(cfg: GcoreConfig, step: string) {
  return gcore(
    cfg,
    step,
    'GET',
    `/cloud/v1/ddos/accessibility/${encodeURIComponent(String(cfg.regionId))}`,
    AccessStatus,
  );
}

async function profileTemplates(cfg: GcoreConfig, step: string) {
  const res = await gcore(
    cfg,
    step,
    'GET',
    `/cloud/v1/ddos/profile-templates/${encodeURIComponent(String(cfg.regionId))}`,
    ProfileTemplateList,
  );
  return res.results;
}

/** The profiles on one address (a single address, never a range). */
async function profilesOn(cfg: GcoreConfig, step: string, address: string) {
  const res = await gcore(
    cfg,
    step,
    'GET',
    `${profilesPath(cfg)}?ip_address=${encodeURIComponent(address)}`,
    ProfileList,
  );
  // The filter also matches a range holding the address: keep the address's own.
  return res.results.filter((p) => p.ip_address === address);
}

async function createProfile(
  cfg: GcoreConfig,
  step: string,
  templateId: number,
  address: string,
): Promise<string> {
  const res = await gcore(cfg, step, 'POST', profilesPath(cfg), GcoreTasks, {
    profile_template: templateId,
    ip_address: address,
  });
  return res.tasks[0];
}

async function changeTemplate(
  cfg: GcoreConfig,
  step: string,
  profileId: number,
  templateId: number,
  address: string,
): Promise<string> {
  const res = await gcore(cfg, step, 'PATCH', profilePath(cfg, profileId), GcoreTasks, {
    profile_template: templateId,
    ip_address: address,
  });
  return res.tasks[0];
}

async function setActive(
  cfg: GcoreConfig,
  step: string,
  profileId: number,
  active: boolean,
  bgp: boolean,
): Promise<string> {
  const res = await gcore(cfg, step, 'POST', `${profilePath(cfg, profileId)}/action`, GcoreTasks, {
    active,
    bgp,
  });
  return res.tasks[0];
}

/** Delete a profile; a 404 (already gone) answers null. */
async function deleteProfile(
  cfg: GcoreConfig,
  step: string,
  profileId: string | number,
): Promise<{ task?: string } | null> {
  try {
    const res = await gcore(
      cfg,
      step,
      'DELETE',
      profilePath(cfg, profileId),
      GcoreTasks.or(z.unknown()),
    );
    const task =
      res && typeof res === 'object' && 'tasks' in res
        ? (res as { tasks: string[] }).tasks[0]
        : undefined;
    return task ? { task } : {};
  } catch (e) {
    if (isProviderNotFound(e)) return null;
    throw e;
  }
}

// --- pure helpers ------------------------------------------------------------------------

export type DdosTemplateChoice =
  | { ok: true; id: number; name: string }
  | { ok: false; code: 'ddos_no_templates' | 'ddos_template_required' | 'ddos_template_unknown' };

/**
 * The template to use: `wanted` by its number, else by its name (any case);
 * absent = the region's only template. Exported for tests.
 */
export function chooseDdosTemplate(
  templates: ReadonlyArray<{ id: number; name?: string | null }>,
  wanted: string | undefined,
): DdosTemplateChoice {
  if (templates.length === 0) return { ok: false, code: 'ddos_no_templates' };
  const w = wanted?.trim();
  if (!w) {
    if (templates.length !== 1) return { ok: false, code: 'ddos_template_required' };
    const t = templates[0];
    return { ok: true, id: t.id, name: t.name ?? String(t.id) };
  }
  const byId = /^\d+$/.test(w) ? templates.find((t) => t.id === Number(w)) : undefined;
  const hit =
    byId ?? templates.find((t) => (t.name ?? '').trim().toLowerCase() === w.toLowerCase());
  return hit
    ? { ok: true, id: hit.id, name: hit.name ?? String(hit.id) }
    : { ok: false, code: 'ddos_template_unknown' };
}

/** Gcore's status words for a profile that is going away (not one that failed to). */
const isDeleting = (p: { status?: { status?: string | null } | null }) => {
  const s = p.status?.status ?? '';
  return /delet/i.test(s) && !/error/i.test(s);
};

const profileResource = (p: ProfileBody, address: string): ChildResource => ({
  kind: 'ddos_profile',
  resourceId: String(p.id),
  ownership: 'created',
  meta: { address },
});

export const ddosModeOf = (tpl: Pick<GcoreTemplateParams, 'ddosProtection'>): GcoreDdosMode =>
  tpl.ddosProtection ?? 'off';
const bgpOf = (tpl: Pick<GcoreTemplateParams, 'ddosBgp'>) => tpl.ddosBgp ?? true;

// --- the provisioning step ---------------------------------------------------------------

/** The step kind and id the adapter plans after the load balancer. */
export const DDOS_STEP_ID = 'ddos';
export const DDOS_STEP_KIND = 'create_ddos_profile' as const;

/**
 * What the step carries between polls, as its opRef (`ddos:` + JSON): the
 * template's wishes (pollStep is not given the template) and where it is.
 */
interface DdosStepState {
  mode: 'on' | 'required';
  bgp: boolean;
  want?: string;
  /** `wait`: the load balancer has no active public IPv4 yet. */
  phase: 'wait' | 'create' | 'activate';
  task?: string;
  address?: string;
  profileId?: number;
}
const OPREF_PREFIX = 'ddos:';
const encodeState = (st: DdosStepState) => `${OPREF_PREFIX}${JSON.stringify(st)}`;
export function decodeDdosState(opRef: string | undefined): DdosStepState | null {
  if (!opRef?.startsWith(OPREF_PREFIX)) return null;
  try {
    const st = JSON.parse(opRef.slice(OPREF_PREFIX.length)) as DdosStepState;
    return st && (st.mode === 'on' || st.mode === 'required') ? st : null;
  } catch {
    return null;
  }
}

const requested = (st: DdosStepState, resources: ChildResource[] = []): StepOutcome => ({
  status: 'requested',
  opRef: encodeState(st),
  resources,
});

/**
 * Protection could not be turned on. `required`: the run stops on `code` (the
 * provider answered; asking again gets the same answer) and keeps whatever
 * profile exists for the destroy walk. `on`: the edge goes on without it.
 */
function giveUp(
  st: Pick<DdosStepState, 'mode'>,
  code: string,
  resources: ChildResource[] = [],
  detail?: string,
): StepOutcome {
  if (st.mode === 'on') return { status: 'done', resources };
  return {
    status: 'partial',
    resources,
    code,
    refused: true,
    ...(detail ? { detail } : {}),
  };
}

async function lbOf(cfg: GcoreConfig, ledger: Ledger, step: string): Promise<GcoreLbBody | null> {
  const lb = firstResource(ledger, 'lb');
  return lb ? getGcoreLb(cfg, step, lb.resourceId) : null;
}

/** Start the step (runStep): protect the load balancer's public IPv4. */
export async function runDdosStep(
  cfg: GcoreConfig,
  tpl: GcoreTemplateParams,
  ledger: Ledger,
): Promise<StepOutcome> {
  const mode = ddosModeOf(tpl);
  if (mode === 'off') return { status: 'done', resources: [] };
  return advance(cfg, ledger, {
    mode,
    bgp: bgpOf(tpl),
    ...(tpl.ddosProfileTemplate ? { want: tpl.ddosProfileTemplate } : {}),
    phase: 'wait',
  });
}

/** Advance the step from its opRef (pollStep). */
export async function pollDdosStep(
  cfg: GcoreConfig,
  ledger: Ledger,
  opRef: string,
): Promise<StepOutcome> {
  const st = decodeDdosState(opRef);
  if (!st)
    throw new EdgeProviderError('gcore ddos: unreadable step state', {
      provider: 'gcore',
      step: DDOS_STEP_ID,
      code: 'ddos_state_unreadable',
      retryable: false,
      timedOut: false,
    });
  return advance(cfg, ledger, st);
}

async function advance(cfg: GcoreConfig, ledger: Ledger, st: DdosStepState): Promise<StepOutcome> {
  const step = DDOS_STEP_ID;
  if (st.phase === 'create' || st.phase === 'activate') {
    const t = await gcoreTask(cfg, step, st.task ?? '');
    const state = taskState(t);
    if (state === 'running') return requested(st);
    const address = st.address ?? '';
    const [p] = await profilesOn(cfg, step, address);
    const found = p ? [profileResource(p, address)] : [];
    if (state === 'error')
      return giveUp(
        st,
        st.phase === 'create' ? 'ddos_create_failed' : 'ddos_activate_failed',
        found,
      );
    if (!p) return giveUp(st, 'ddos_create_failed');
    if (st.phase === 'activate' || (p.options?.active === true && p.options?.bgp === st.bgp))
      return { status: 'done', resources: found };
    const task = await setActive(cfg, step, p.id, true, st.bgp);
    return requested({ ...st, phase: 'activate', task, profileId: p.id }, found);
  }

  // `wait`: the load balancer must be active with its public IPv4.
  const lb = await lbOf(cfg, ledger, step);
  if (!lb) return giveUp(st, 'ddos_no_lb');
  const address = gcoreLbAddresses(lb).v4;
  if ((lb.provisioning_status ?? '').toUpperCase() !== 'ACTIVE' || !address)
    return requested({ ...st, phase: 'wait' });

  // A profile already on the address (an earlier attempt whose answer was lost).
  const [existing] = await profilesOn(cfg, step, address);
  if (existing) {
    const found = [profileResource(existing, address)];
    if (existing.options?.active === true && existing.options?.bgp === st.bgp)
      return { status: 'done', resources: found };
    const task = await setActive(cfg, step, existing.id, true, st.bgp);
    return requested({ ...st, phase: 'activate', task, address, profileId: existing.id }, found);
  }

  const access = await regionAccess(cfg, step);
  if (!access.is_accessible) return giveUp(st, 'ddos_unavailable');
  const choice = chooseDdosTemplate(await profileTemplates(cfg, step), st.want);
  if (!choice.ok) return giveUp(st, choice.code);
  let task: string;
  try {
    task = await createProfile(cfg, step, choice.id, address);
  } catch (e) {
    // A 4xx (`validation-error`, `not-available`, `quota-exceeded`) built nothing.
    // Its HTTP status is dropped: a 403 here is the protection product, not the
    // key's hold on the load balancers, and must not count against the account.
    const refused = refusedCreate(e, 'ddos_refused');
    if (!refused || refused.status !== 'partial') throw e;
    return giveUp(st, 'ddos_refused', [], refused.detail);
  }
  return requested({ ...st, phase: 'create', task, address });
}

/**
 * Discovery for the step: a profile on the load balancer's public IPv4 is
 * found; a task still running is unresolved; otherwise absence settles like
 * the load balancer's own (>= 2 quiet looks and the settle window).
 */
export async function discoverDdos(
  cfg: GcoreConfig,
  ledger: Ledger,
  attempt: number,
): Promise<Discovery> {
  const step = DDOS_STEP_ID;
  const ls = stepOf(ledger, step);
  const st = decodeDdosState(ls?.opRef);
  if (st?.task && taskState(await gcoreTask(cfg, step, st.task)) === 'running')
    return { status: 'unresolved' };
  const lb = await lbOf(cfg, ledger, step);
  const address = lb ? gcoreLbAddresses(lb).v4 : st?.address;
  if (address) {
    const [p] = await profilesOn(cfg, step, address);
    if (p) return { status: 'found', resources: [profileResource(p, address)] };
  }
  return discoveryMaySettle('gcore', attempt, ls?.startedAt)
    ? { status: 'confirmed_absent' }
    : { status: 'unresolved' };
}

// --- destroy -----------------------------------------------------------------------------

/** Delete a ledgered profile (`GCORE_DESTROY_ORDER` puts it before the load balancer). */
export async function destroyProfile(cfg: GcoreConfig, r: LedgerResource): Promise<DestroyOutcome> {
  const res = await deleteProfile(cfg, 'destroy', r.resourceId);
  return res === null
    ? { status: 'confirmed_gone' }
    : { status: 'delete_requested', ...(res.task ? { opRef: res.task } : {}) };
}

/** Read a ledgered profile back after its delete: absent = gone. */
export async function confirmProfileDestroyed(
  cfg: GcoreConfig,
  r: LedgerResource,
): Promise<DestroyOutcome> {
  const address = metaOf(r).address;
  const res = await gcore(
    cfg,
    'confirm-destroy',
    'GET',
    typeof address === 'string'
      ? `${profilesPath(cfg)}?ip_address=${encodeURIComponent(address)}`
      : profilesPath(cfg),
    ProfileList,
  );
  const p = res.results.find((x) => String(x.id) === r.resourceId);
  if (!p) return { status: 'confirmed_gone' };
  return isDeleting(p) ? { status: 'unresolved' } : { status: 'still_present' };
}

/**
 * Before a load balancer is deleted: remove every profile on its public
 * addresses (one the ledger never recorded: turned on from the edge page, or
 * by hand at Gcore). Answers how many are still there; the caller deletes the
 * load balancer only at 0. A profile already going away is not asked again.
 */
export async function sweepProfiles(cfg: GcoreConfig, lb: GcoreLbBody): Promise<number> {
  const addrs = gcoreLbAddresses(lb);
  const ids = new Map<number, { status?: { status?: string | null } | null }>();
  if (lb.ddos_profile) ids.set(lb.ddos_profile.id, lb.ddos_profile);
  for (const a of [addrs.v4, addrs.v6]) {
    if (!a) continue;
    for (const p of await profilesOn(cfg, 'destroy', a)) ids.set(p.id, p);
  }
  let left = 0;
  for (const [id, p] of ids) {
    if (isDeleting(p)) {
      left++;
      continue;
    }
    if ((await deleteProfile(cfg, 'destroy', id)) !== null) left++;
  }
  return left;
}

// --- the edge page -----------------------------------------------------------------------

export type GcoreDdosProfileView = EdgeDdosProfileView;
export type GcoreDdosView = EdgeDdosView;

const profileView = (p: ProfileBody, address: string): GcoreDdosProfileView => ({
  id: String(p.id),
  address,
  active: p.options?.active ?? null,
  bgp: p.options?.bgp ?? null,
  status: p.status?.status ?? null,
  error: p.status?.error_description ? p.status.error_description.slice(0, 200) : null,
  templateId: p.profile_template?.id ?? null,
  templateName: p.profile_template?.name ?? null,
});

async function lbOrRefuse(cfg: GcoreConfig, ledger: Ledger, step: string): Promise<GcoreLbBody> {
  const lb = firstResource(ledger, 'lb');
  if (!lb)
    throw new EdgeProviderError('gcore ddos: no load balancer in the ledger', {
      provider: 'gcore',
      step,
      code: 'ddos_no_lb',
      retryable: false,
      timedOut: false,
    });
  return getGcoreLb(cfg, step, lb.resourceId);
}

/** What the edge page shows: coverage, templates, the profiles on the edge's addresses, price. */
export async function ddosView(cfg: GcoreConfig, ledger: Ledger): Promise<GcoreDdosView> {
  const step = 'ddos-view';
  const lb = await lbOrRefuse(cfg, ledger, step);
  const addresses = gcoreLbAddresses(lb);
  const unread: string[] = [];
  const soft = async <T>(name: string, fn: () => Promise<T>): Promise<T | null> => {
    try {
      return await fn();
    } catch {
      unread.push(name);
      return null;
    }
  };
  const [access, templates, price] = await Promise.all([
    soft('region', () => regionAccess(cfg, step)),
    soft('templates', () => profileTemplates(cfg, step)),
    soft('price', () =>
      gcore(
        cfg,
        step,
        'GET',
        `/cloud/v1/pricing/${encodeURIComponent(String(cfg.regionId))}/ddos`,
        Price,
      ),
    ),
  ]);
  const profiles: GcoreDdosProfileView[] = [];
  for (const a of [addresses.v4, addresses.v6]) {
    if (!a) continue;
    const on = await soft('profiles', () => profilesOn(cfg, step, a));
    for (const p of on ?? []) profiles.push(profileView(p, a));
  }
  return {
    available: access ? access.is_accessible : null,
    templates: (templates ?? []).map((t) => ({
      id: t.id,
      name: t.name ?? String(t.id),
      description: t.description ? t.description.slice(0, 300) : null,
    })),
    profiles,
    addresses,
    price: price?.price
      ? {
          feature: price.price.feature_name ?? null,
          per30d: price.price.price_per_30d ?? null,
          currency: price.price.price_currency ?? null,
        }
      : null,
    unread: [...new Set(unread)],
  };
}

export type GcoreDdosChange = EdgeDdosChange;
export type GcoreDdosChangeResult = EdgeDdosChangeResult;

/** How long one change waits for each of its tasks before answering `pending`. */
const TASK_WAIT_MS = 20_000;
const TASK_POLL_MS = 1_500;

async function waitTask(
  cfg: GcoreConfig,
  step: string,
  task: string,
  deadline: number,
): Promise<'finished' | 'pending'> {
  for (;;) {
    const s = taskState(await gcoreTask(cfg, step, task));
    if (s === 'finished') return 'finished';
    if (s === 'error')
      throw new EdgeProviderError('gcore ddos: the task failed', {
        provider: 'gcore',
        step,
        code: 'ddos_task_failed',
        retryable: false,
        timedOut: false,
      });
    if (Date.now() + TASK_POLL_MS > deadline) return 'pending';
    await new Promise((r) => setTimeout(r, TASK_POLL_MS));
  }
}

function refuse(code: string, step: string): never {
  throw new EdgeProviderError(`gcore ddos: ${code}`, {
    provider: 'gcore',
    step,
    code,
    retryable: false,
    timedOut: false,
  });
}

/**
 * Turn protection on (creating the profile when there is none, switching
 * template when one is named and differs), off (kept, inactive), or remove the
 * profile. The edge's public IPv4 is the protected address.
 */
export async function changeDdos(
  cfg: GcoreConfig,
  ledger: Ledger,
  req: GcoreDdosChange,
  now: () => number = Date.now,
): Promise<GcoreDdosChangeResult> {
  const step = `ddos-${req.action}`;
  const lb = await lbOrRefuse(cfg, ledger, step);
  const address = gcoreLbAddresses(lb).v4;
  if (!address) refuse('ddos_no_address', step);
  const deadline = now() + TASK_WAIT_MS;
  const [p] = await profilesOn(cfg, step, address);

  if (req.action === 'remove') {
    if (!p) return { state: 'unchanged' };
    const res = await deleteProfile(cfg, step, p.id);
    if (!res?.task) return { state: 'done' };
    return { state: await waitTaskState(cfg, step, res.task, deadline) };
  }
  if (req.action === 'disable') {
    if (!p || p.options?.active === false) return { state: 'unchanged' };
    const task = await setActive(cfg, step, p.id, false, false);
    return { state: await waitTaskState(cfg, step, task, deadline) };
  }

  const bgp = req.bgp ?? true;
  let profile = p;
  let template: DdosTemplateChoice | null = null;
  if (!profile || req.profileTemplate) {
    const access = await regionAccess(cfg, step);
    if (!access.is_accessible) refuse('ddos_unavailable', step);
    template = chooseDdosTemplate(await profileTemplates(cfg, step), req.profileTemplate);
    if (!template.ok) refuse(template.code, step);
  }
  let changed = false;
  if (!profile && template?.ok) {
    const task = await createProfile(cfg, step, template.id, address);
    changed = true;
    if ((await waitTask(cfg, step, task, deadline)) === 'pending') return { state: 'pending' };
    [profile] = await profilesOn(cfg, step, address);
    if (!profile) return { state: 'pending' };
  } else if (profile && template?.ok && profile.profile_template?.id !== template.id) {
    const task = await changeTemplate(cfg, step, profile.id, template.id, address);
    changed = true;
    if ((await waitTask(cfg, step, task, deadline)) === 'pending') return { state: 'pending' };
  }
  if (!profile) return { state: 'pending' };
  if (profile.options?.active === true && profile.options?.bgp === bgp)
    return { state: changed ? 'done' : 'unchanged' };
  const task = await setActive(cfg, step, profile.id, true, bgp);
  return { state: await waitTaskState(cfg, step, task, deadline) };
}

async function waitTaskState(
  cfg: GcoreConfig,
  step: string,
  task: string,
  deadline: number,
): Promise<'done' | 'pending'> {
  return (await waitTask(cfg, step, task, deadline)) === 'finished' ? 'done' : 'pending';
}
