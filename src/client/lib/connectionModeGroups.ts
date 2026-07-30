/**
 * Grouping rules for the two-level connection-mode picker. Pure and separate
 * from DeliveryPreference.svelte so the fiddly parts — a family collapsing to a
 * plain card, an admin-disabled mode the member is still sitting on, an orphan
 * with no family — are unit-testable rather than only observable by eye.
 *
 * The shapes are the SHARED CONTRACTS (zod-inferred), not local copies — the
 * mode shape used to exist in three hand-copied variants that drifted.
 */
import type {
  MemberCurrentMode,
  PublicConnectionMode,
  PublicConnectionModeFamily,
} from '../../shared/contracts/connectionModes';

export type PickerMode = PublicConnectionMode;
export type PickerFamily = PublicConnectionModeFamily;

export interface ModeGroup {
  /** null for an orphan leaf with no (visible) family — rendered as a plain card. */
  family: PickerFamily | null;
  children: PickerMode[];
}

/**
 * Is the mode selectable on `backendId`? Joins the per-backend availability
 * the server ships; falls back to the any-backend `available` bool when no
 * backend is in hand (anonymous surfaces) or against an older server that
 * doesn't ship `availableBackends` yet (deploy skew).
 */
export function availableOn(m: PickerMode, backendId: string | null | undefined): boolean {
  if (!backendId) return m.available;
  if (!m.availableBackends.length) return m.available;
  return m.availableBackends.includes(backendId);
}

/**
 * publicConfig omits admin-disabled modes (it is member-agnostic and shared by
 * every visitor, so it cannot special-case one caller). If the member's CURRENT
 * mode is one of those, synthesize an entry so they still see their selection
 * and can switch away, instead of a picker that has silently dropped them.
 *
 * `current` is the account view's resolved `currentMode` projection: with it
 * the synthesized entry carries the REAL deliveryStyle/label/family (a member
 * on a disabled rawConfig mode used to get URL-first delivery UI from the old
 * blind 'url' guess); without it (deploy skew) the guess remains the fallback.
 */
export function withCurrentMode(
  modes: PickerMode[],
  selected: string,
  current?: MemberCurrentMode | null,
): PickerMode[] {
  if (!selected || modes.some((m) => m.id === selected)) return modes;
  const projected = current && current.id === selected ? current : null;
  return [
    ...modes,
    {
      id: selected,
      family: projected?.family?.id,
      deliveryStyle: projected?.deliveryStyle ?? 'url',
      label: projected?.label ?? null,
      description: projected?.description ?? null,
      isDefault: false,
      isFamilyDefault: false,
      availableBackends: [],
      // Not selectable-to, but it IS the current selection; DeliveryPreference
      // keeps the current choice enabled so it can be moved off.
      available: false,
    },
  ];
}

/**
 * Families in catalog order with their visible children, followed by any leaf
 * whose family is absent (an orphan, or the synthesized current selection) as
 * its own standalone group — so no mode is ever unreachable in the UI.
 */
export function groupModesByFamily(modes: PickerMode[], families: PickerFamily[]): ModeGroup[] {
  const out: ModeGroup[] = [];
  for (const f of families) {
    const children = modes.filter((m) => m.family === f.id);
    if (children.length) out.push({ family: f, children });
  }
  const grouped = new Set(out.flatMap((g) => g.children.map((m) => m.id)));
  for (const m of modes) {
    if (!grouped.has(m.id)) out.push({ family: null, children: [m] });
  }
  return out;
}

/**
 * The leaf a family selects when the member picks the parent card: its declared
 * default if that is selectable, else the first selectable child, else the first
 * child at all (so a click is never a no-op on a fully-unavailable family).
 */
export function familyTargetMode(children: PickerMode[]): PickerMode | undefined {
  return (
    children.find((m) => m.isFamilyDefault && m.available) ??
    children.find((m) => m.available) ??
    children[0]
  );
}
