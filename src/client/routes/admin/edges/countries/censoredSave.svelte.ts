/**
 * Saving the censored-country list (`PUT /api/v1/admin/censored-countries`,
 * the whole list at once), from the list editor and from one country's
 * "Checks from here". On success every view of the list is refreshed: the
 * status matrix editor (its rows are the listed countries), the edges probe
 * countries, the SNI countries and opt-ins, and the country pages.
 *
 * Usage (inside a component):
 *   const save = censoredSave({ success: 'Saved', onSaved: () => (draft = null) });
 *   save.mutate(nextRows);
 */
import { createMutation, useQueryClient } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { apiClient } from '@client/lib/api';
import { apiErrorMessage } from '@client/lib/errors';
import { queryKeys } from '@client/lib/queries';
import { edgeKeys } from '@client/lib/edgesApi';
import { sniKeys } from '@client/lib/sniApi';
import { AdminCensoredCountries, type CensoredCountry } from '@shared/contracts/admin';

export function censoredSave(opts: {
  /** The toast on success (a string, or one built from the saved list). */
  success: string | ((rows: CensoredCountry[]) => string);
  onSaved?: () => void;
}) {
  const qc = useQueryClient();
  return createMutation(() => ({
    mutationFn: (countries: CensoredCountry[]) =>
      apiClient.put('/api/v1/admin/censored-countries', { countries }, AdminCensoredCountries),
    onSuccess: (_res: unknown, rows: CensoredCountry[]) => {
      opts.onSaved?.();
      for (const queryKey of [
        queryKeys.adminCensoredCountries,
        queryKeys.adminStatusPage,
        edgeKeys.config,
        edgeKeys.countries,
        sniKeys.all,
      ])
        void qc.invalidateQueries({ queryKey });
      toast.success(typeof opts.success === 'string' ? opts.success : opts.success(rows));
    },
    onError: (err: unknown) => {
      toast.error('Could not save the censored countries', {
        description: apiErrorMessage(err),
      });
    },
  }));
}
