<script lang="ts">
  /**
   * The picture beside the home page headline. An admin can upload one on
   * Admin → Settings (served at /api/v1/site/home-image); until then, or if it
   * fails to load, the built-in poster shows. Decorative (aria-hidden): the
   * headline next to it says the same thing in words.
   *
   * Nothing is drawn until /api/v1/config answers, so a site with its own image
   * never flashes the built-in one first. The box keeps the image's own shape
   * from the config, so the hero does not shift when it arrives.
   */
  import builtIn from '../assets/home-poster.png';
  import { configQuery } from '../lib/queries';

  const BUILT_IN = { src: builtIn, width: 1000, height: 1440 };

  const config = configQuery();
  // The version that failed to load, so a broken upload falls back for good.
  let failed = $state<string | null>(null);

  const image = $derived.by(() => {
    const custom = config.data?.site?.homeImage;
    if (!custom || custom.version === failed) return BUILT_IN;
    return {
      src: `/api/v1/site/home-image?v=${custom.version}`,
      width: custom.width,
      height: custom.height,
      version: custom.version,
    };
  });
</script>

<figure class="m-0 w-full max-w-[260px] justify-self-center md:max-w-[400px]" aria-hidden="true">
  {#if config.isPending}
    <div class="w-full" style:aspect-ratio="{BUILT_IN.width} / {BUILT_IN.height}"></div>
  {:else}
    <img
      class="block h-auto max-h-[600px] w-full object-contain"
      src={image.src}
      width={image.width}
      height={image.height}
      alt=""
      decoding="async"
      onerror={() => {
        if ('version' in image) failed = image.version;
      }}
    />
  {/if}
</figure>
