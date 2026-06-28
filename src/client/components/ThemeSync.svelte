<script lang="ts">
  /**
   * Applies the admin-selected brand theme from publicConfig once it resolves,
   * and re-applies whenever it changes (e.g. after an admin saves). Renders
   * nothing. The applier caches the palette to localStorage so theme-init.js can
   * replay it before paint on the next load (no flash-of-default). First-ever
   * visit shows the baked Emerald default until this runs.
   */
  import { configQuery } from '../lib/queries';
  import { applyTheme } from '../lib/theme';

  const config = configQuery();
  $effect(() => {
    const theme = config.data?.theme;
    if (theme) applyTheme(theme.preset, theme.hue);
  });
</script>
