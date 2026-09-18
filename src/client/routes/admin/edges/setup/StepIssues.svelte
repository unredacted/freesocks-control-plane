<script lang="ts">
  /**
   * The blockers and warnings of one setup step, in words, each with the link
   * that fixes it when the fix lives on another page.
   *
   * Props:
   *   step: SetupStep
   *   ctx: IssueLinkContext
   *   hide?: string[]                  codes the step body already explains with its own controls
   */
  import type { SetupStep } from '@shared/contracts/edges';
  import { buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import { issueLink, type IssueLinkContext } from './issueActions';

  interface Props {
    step: SetupStep;
    ctx: IssueLinkContext;
    hide?: string[];
  }
  let { step, ctx, hide = [] }: Props = $props();

  const blockers = $derived(step.blockers.filter((b) => !hide.includes(b.code)));
  const warnings = $derived(step.warnings.filter((b) => !hide.includes(b.code)));
</script>

{#if blockers.length > 0 || warnings.length > 0}
  <div class="space-y-1.5">
    {#each blockers as b, i (`b:${b.code}:${b.subject ?? ''}:${i}`)}
      {@const link = issueLink(b.code, ctx)}
      <CodeNote issue={b} tone="blocker">
        {#snippet actions()}
          {#if link}
            <Link href={link.href} class={buttonVariants({ size: 'sm', variant: 'outline' })}>
              {link.label}
            </Link>
          {/if}
        {/snippet}
      </CodeNote>
    {/each}
    {#each warnings as w, i (`w:${w.code}:${w.subject ?? ''}:${i}`)}
      {@const link = issueLink(w.code, ctx)}
      <CodeNote issue={w} tone="warning">
        {#snippet actions()}
          {#if link}
            <Link href={link.href} class={buttonVariants({ size: 'sm', variant: 'outline' })}>
              {link.label}
            </Link>
          {/if}
        {/snippet}
      </CodeNote>
    {/each}
  </div>
{/if}
