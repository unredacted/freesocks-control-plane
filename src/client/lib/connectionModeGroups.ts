/**
 * Grouping rules for the two-level connection-mode picker. Pure and separate
 * from DeliveryPreference.svelte so the fiddly parts — a family collapsing to a
 * plain card, an admin-disabled mode the member is still sitting on, an orphan
 * with no family — are unit-testable rather than only observable by eye.
 */

export interface PickerMode {
  id: string;
  family?: string;
  deliveryStyle: 'url' | 'rawConfig';
  label: string | null;
  description: string | null;
  isDefault: boolean;
  isFamilyDefault?: boolean;
  available: boolean;
}

export interface PickerFamily {
  id: string;
  label: string | null;
  description: string | null;
}

export interface ModeGroup {
  /** null for an orphan leaf with no (visible) family — rendered as a plain card. */
  family: PickerFamily | null;
  children: PickerMode[];
}

/**
 * publicConfig omits admin-disabled modes (it is member-agnostic and shared by
 * every visitor, so it cannot special-case one caller). If the member's CURRENT
 * mode is one of those, synthesize an entry so they still see their selection
 * and can switch away, instead of a picker that has silently dropped them.
 */
export function withCurrentMode(modes: PickerMode[], selected: string): PickerMode[] {
  if (!selected || modes.some((m) => m.id === selected)) return modes;
  return [
    ...modes,
    {
      id: selected,
      family: undefined,
      deliveryStyle: 'url',
      label: null,
      description: null,
      isDefault: false,
      isFamilyDefault: false,
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
