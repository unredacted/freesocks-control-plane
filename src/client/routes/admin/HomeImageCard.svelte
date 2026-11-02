<script lang="ts">
  /**
   * The picture beside the home page headline (Settings). Uploading replaces
   * the built-in poster for every visitor; "Use the built-in image" goes back.
   * The file travels as base64 in JSON (the API client signs text bodies) and
   * the server checks it again: PNG, JPEG or WebP, at most 512 KB, each side
   * 64 to 4096 pixels (convex/lib/siteImage.ts).
   *
   * The preview reads the chosen file as a data: URL, which the page's CSP
   * allows for images (blob: is not).
   */
  import { z } from 'zod';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import builtIn from '../../assets/home-poster.png';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { configQuery, queryKeys } from '../../lib/queries';
  import { SiteImageRef } from '../../../shared/contracts/auth';

  const MAX_BYTES = 512 * 1024;
  const TYPES = ['image/png', 'image/jpeg', 'image/webp'];
  const PATH = '/api/v1/admin/site/home-image';
  const Resp = z.object({ homeImage: SiteImageRef.nullable() });

  const qc = useQueryClient();
  const config = configQuery();
  const current = $derived(config.data?.site?.homeImage ?? null);

  // The chosen file, read as a data: URL (for the preview and the upload).
  let picked = $state<{ name: string; dataUrl: string } | null>(null);
  let input = $state<HTMLInputElement | null>(null);

  const shown = $derived(
    picked?.dataUrl ?? (current ? `/api/v1/site/home-image?v=${current.version}` : builtIn),
  );

  function clearPick() {
    picked = null;
    if (input) input.value = '';
  }

  function onPick(e: Event) {
    const file = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!file) return;
    if (!TYPES.includes(file.type)) {
      toast.error('Use a PNG, JPEG or WebP image');
      clearPick();
      return;
    }
    if (file.size > MAX_BYTES) {
      toast.error('That image is too large', {
        description: `It is ${Math.ceil(file.size / 1024)} KB; the limit is 512 KB.`,
      });
      clearPick();
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') picked = { name: file.name, dataUrl: reader.result };
    };
    reader.readAsDataURL(file);
  }

  function done(message: string) {
    clearPick();
    void qc.invalidateQueries({ queryKey: queryKeys.config });
    toast.success(message);
  }

  const upload = createMutation(() => ({
    mutationFn: () => {
      const data = picked?.dataUrl.slice(picked.dataUrl.indexOf(',') + 1) ?? '';
      return apiClient.put(PATH, { data }, Resp);
    },
    onSuccess: () => done('Home page image updated'),
    onError: (err) =>
      toast.error('Could not upload the image', { description: apiErrorMessage(err) }),
  }));

  const reset = createMutation(() => ({
    mutationFn: () => apiClient.delete(PATH, Resp),
    onSuccess: () => done('Back to the built-in image'),
    onError: (err) =>
      toast.error('Could not reset the image', { description: apiErrorMessage(err) }),
  }));

  const busy = $derived(upload.isPending || reset.isPending);
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Home page image</CardTitle>
    <CardDescription>
      The picture beside the headline on the home page. Every visitor sees the one you upload; until
      then, the built-in poster shows. PNG, JPEG or WebP, up to 512 KB, each side 64 to 4096 pixels.
      A portrait image (about 1000 by 1440 pixels) fills the space best.
    </CardDescription>
  </CardHeader>
  <CardContent class="text-sm">
    <div class="flex flex-col gap-5 sm:flex-row sm:items-start">
      <img
        src={shown}
        alt="The current home page image"
        class="block h-auto max-h-64 w-40 shrink-0 rounded-sm border border-border object-contain"
      />
      <div class="min-w-0 space-y-3">
        <p class="text-muted-foreground">
          {#if picked}
            Preview of <span class="font-medium text-foreground">{picked.name}</span>. Not saved
            yet.
          {:else if current}
            Showing your uploaded image ({current.width} by {current.height} pixels).
          {:else}
            Showing the built-in image.
          {/if}
        </p>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="home-image-file">
            Choose an image
          </label>
          <input
            id="home-image-file"
            type="file"
            accept={TYPES.join(',')}
            class="block w-full text-sm file:me-3 file:rounded-sm file:border-2 file:border-border file:bg-transparent file:px-3 file:py-1.5 file:font-semibold file:text-foreground"
            bind:this={input}
            onchange={onPick}
            disabled={busy}
          />
        </div>
        <div class="flex flex-wrap gap-2">
          <Button onclick={() => upload.mutate()} disabled={!picked || busy}>
            {upload.isPending ? 'Uploading…' : 'Upload image'}
          </Button>
          {#if picked}
            <Button variant="outline" onclick={clearPick} disabled={busy}>Cancel</Button>
          {:else if current}
            <Button variant="outline" onclick={() => reset.mutate()} disabled={busy}>
              {reset.isPending ? 'Resetting…' : 'Use the built-in image'}
            </Button>
          {/if}
        </div>
      </div>
    </div>
  </CardContent>
</Card>
