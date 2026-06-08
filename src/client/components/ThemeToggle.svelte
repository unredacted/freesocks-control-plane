<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import { mode, setMode } from 'mode-watcher';
  import Sun from '@lucide/svelte/icons/sun';
  import Moon from '@lucide/svelte/icons/moon';

  /**
   * Two-state light ↔ dark toggle. We DELIBERATELY skip the standard shadcn
   * three-state (light / dark / system) cycle because users hit a real-world
   * confusion: starting from dark, click 1 goes to "system" which, for the
   * many users on a dark-mode OS, looks IDENTICAL to dark, so the click
   * appears to do nothing and the toggle reads as broken.
   *
   * Two states keeps the contract obvious: every click flips the look. If we
   * ever need to expose "follow the system" as an option, do it as a
   * secondary settings affordance rather than baking it into the toggle
   * cycle.
   *
   * The actual class flip + localStorage persistence is handled by
   * `setMode` from mode-watcher; the FOUC-prevention script in `index.html`
   * applies the right class on first paint so reload-then-toggle does the
   * right thing.
   */

  // mode.current can be 'light' | 'dark' | 'system'. We resolve 'system' to
  // the effective theme (dark if the OS prefers dark) so the toggle action
  // is "go to the opposite of what's currently rendered".
  let effective = $derived.by<'light' | 'dark'>(() => {
    if (mode.current === 'light') return 'light';
    if (mode.current === 'dark') return 'dark';
    if (typeof window === 'undefined') return 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  });

  function toggle() {
    setMode(effective === 'light' ? 'dark' : 'light');
  }

  let label = $derived(effective === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
</script>

<Button
  variant="ghost"
  size="icon"
  onclick={toggle}
  aria-label={label}
  title={label}
  class="text-muted-foreground hover:text-foreground"
>
  {#if effective === 'dark'}
    <Sun />
  {:else}
    <Moon />
  {/if}
</Button>
