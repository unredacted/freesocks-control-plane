/**
 * Operator-facing backend display names for the ADMIN CMS.
 *
 * The `remnawave` id is an implementation detail (the management panel); end
 * users see it as "Xray" (the server default in convex/appSettings.ts and the
 * protocol family the apps speak). Admin screens were split — "Xray" in the
 * tier editor, "Remnawave" in settings — so the same id read as two different
 * products. One map ends that. Member-facing labels keep coming from
 * `config.backends.labels` (admin-editable), NOT from here.
 */
import type { BackendId } from '../../shared/contracts/backends';

export const ADMIN_BACKEND_LABELS: Record<BackendId, string> = {
  remnawave: 'Xray (Remnawave)',
  outline: 'Outline',
};
