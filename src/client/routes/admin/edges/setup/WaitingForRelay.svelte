<script lang="ts">
  /**
   * `?relay=<slug>` names a relay that does not exist (yet): the operator is
   * waiting for the node role to register it. Checks again every few seconds.
   *
   * Props:
   *   slug: string
   *   onCheck: () => void
   *   onLeave: () => void
   */
  import { Button } from '@client/components/ui/button';
  import RoleVarsCard from './RoleVarsCard.svelte';

  interface Props {
    slug: string;
    onCheck: () => void;
    onLeave: () => void;
  }
  let { slug, onCheck, onLeave }: Props = $props();

  $effect(() => {
    const t = setInterval(onCheck, 5_000);
    return () => clearInterval(t);
  });
</script>

<div class="max-w-2xl space-y-4 rounded-lg border p-4">
  <div>
    <h2 class="text-base font-semibold">
      Waiting for relay <span class="font-mono">{slug}</span>
    </h2>
    <p class="text-muted-foreground text-sm">
      No relay with this slug exists yet. When the node role registers it, the setup continues here
      by itself. This page checks every few seconds.
    </p>
  </div>
  <RoleVarsCard
    roleVars={{ fcp_relay_slug: slug, fcp_relay_register_scope: 'admin:edges:register' }}
  />
  <div class="flex gap-2">
    <Button variant="outline" onclick={onCheck}>Check now</Button>
    <Button variant="ghost" onclick={onLeave}>Choose something else</Button>
  </div>
</div>
