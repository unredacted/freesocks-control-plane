<script lang="ts">
  /**
   * Brand-theme picker (W3-3). Choose a preset (incl. a Classic monochrome) and,
   * for chromatic presets, an optional hue override. The selection previews LIVE
   * + transiently (applyThemeCss, no persist); Save PATCHes /api/v1/admin/theme,
   * persists for flash-free replay, and invalidates publicConfig so every tab +
   * the public site re-applies. Leaving without saving reverts to the saved theme.
   */
  import { z } from 'zod';
  import { onDestroy } from 'svelte';
  import AdminLayout from './AdminLayout.svelte';
  import { Button } from '@client/components/ui/button';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { configQuery, queryKeys } from '../../lib/queries';
  import {
    THEME_PRESETS,
    presetById,
    themeCss,
    applyThemeCss,
    applyTheme,
    effectiveHue,
  } from '../../lib/theme';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const config = configQuery();
  const qc = useQueryClient();

  let selectedPreset = $state('emerald');
  let hueOverride = $state<number | null>(null);
  let initialized = $state(false);

  let savedPreset = $derived(config.data?.theme?.preset ?? 'emerald');
  let savedHue = $derived(config.data?.theme?.hue ?? null);

  // Seed the editor from the saved theme once config loads (then leave it to edits).
  $effect(() => {
    if (config.data && !initialized) {
      selectedPreset = savedPreset;
      hueOverride = savedHue;
      initialized = true;
    }
  });

  // Live, transient preview (no persist) of the current selection.
  $effect(() => {
    if (initialized) applyThemeCss(themeCss(selectedPreset, hueOverride));
  });

  // Leaving without saving: revert the live preview to the saved theme.
  onDestroy(() => applyTheme(savedPreset, savedHue));

  let current = $derived(presetById(selectedPreset));
  let shownHue = $derived(effectiveHue(selectedPreset, hueOverride));
  let dirty = $derived(initialized && (selectedPreset !== savedPreset || hueOverride !== savedHue));

  function selectPreset(id: string) {
    selectedPreset = id;
    hueOverride = null; // start from the preset's own hue
  }

  const ThemeResponse = z.object({ preset: z.string(), hue: z.number().nullable() });
  const save = createMutation(() => ({
    mutationFn: () =>
      apiClient.patch(
        '/api/v1/admin/theme',
        { preset: selectedPreset, hue: hueOverride },
        ThemeResponse,
      ),
    onSuccess: () => {
      applyTheme(selectedPreset, hueOverride); // persist for the next load's FOUC replay
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Theme saved');
    },
    onError: (err) => toast.error('Could not save theme', { description: apiErrorMessage(err) }),
  }));
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-2">Theme</h1>
  <p class="text-sm text-muted-foreground mb-6">
    The brand accent for the whole site — buttons, links, focus rings, the membership card. Changes
    preview live here; <strong>Save</strong> applies them for everyone. The hue slider keeps each preset's
    tuned lightness, so any colour stays readable.
  </p>

  <div class="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
    {#each THEME_PRESETS as p (p.id)}
      {@const active = p.id === selectedPreset}
      <button
        type="button"
        onclick={() => selectPreset(p.id)}
        aria-pressed={active}
        class="flex flex-col items-start gap-2 rounded-lg border p-3 text-left transition-colors {active
          ? 'border-primary ring-2 ring-ring'
          : 'border-border hover:border-primary/50'}"
      >
        <span class="size-8 rounded-full border border-border" style="background:{p.swatch}"></span>
        <span class="text-sm font-medium">{p.label}</span>
      </button>
    {/each}
  </div>

  {#if current.hueAdjustable}
    <div class="mb-6 rounded-lg border border-border bg-card p-4">
      <div class="flex items-center justify-between">
        <label class="text-sm font-medium" for="hue">Hue — {shownHue}°</label>
        {#if hueOverride !== null}
          <Button variant="ghost" size="sm" onclick={() => (hueOverride = null)}>
            Reset to preset
          </Button>
        {/if}
      </div>
      <input
        id="hue"
        type="range"
        min="0"
        max="360"
        value={shownHue}
        oninput={(e) => (hueOverride = Number((e.currentTarget as HTMLInputElement).value))}
        class="mt-2 w-full accent-primary"
      />
      <p class="mt-1 text-xs text-muted-foreground">
        Rotates the accent around the colour wheel (0–360°), keeping the preset's
        lightness/contrast.
      </p>
    </div>
  {:else}
    <p class="mb-6 text-sm text-muted-foreground">Classic is monochrome — no hue to adjust.</p>
  {/if}

  <div class="flex items-center gap-3">
    <Button onclick={() => save.mutate()} disabled={save.isPending || !dirty}>
      {save.isPending ? 'Saving…' : 'Save theme'}
    </Button>
    {#if dirty}
      <span class="text-xs text-muted-foreground">Unsaved — previewing on this device only.</span>
    {/if}
  </div>
</AdminLayout>
