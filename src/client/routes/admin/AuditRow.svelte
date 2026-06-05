<script lang="ts">
  import type { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import * as Collapsible from '@client/components/ui/collapsible';
  import { AuditEntry } from '../../../shared/contracts/admin';
  import { redact } from './AdminAudit.svelte';

  interface Props {
    entry: z.infer<typeof AuditEntry>;
  }
  let { entry }: Props = $props();

  // Always two views available — redacted (default) and raw (toggle). The
  // Collapsible drives the raw view; the redacted view is always rendered
  // above it so admins see what the row is about without expanding.
  let payload = $derived(
    entry.payload === null || entry.payload === undefined ? null : entry.payload,
  );
  let open = $state(false);
</script>

<Card>
  <CardHeader class="py-3">
    <CardTitle class="text-sm font-mono">{entry.action}</CardTitle>
  </CardHeader>
  <CardContent class="py-2 text-xs space-y-1">
    <div>
      Actor: <strong>{entry.actorType}</strong>
      {entry.actorId ?? ''}
    </div>
    <div>
      Target: {entry.targetType ?? '-'}
      {entry.targetId ?? ''}
    </div>
    <div class="text-muted-foreground">
      {new Date(entry.createdAt).toLocaleString()} · request {entry.requestId ?? '-'}
    </div>
    {#if payload !== null}
      <div class="mt-2">
        <pre class="text-xs bg-muted px-2 py-1 rounded overflow-x-auto">{JSON.stringify(
            redact(payload),
            null,
            2,
          )}</pre>
        <Collapsible.Root bind:open class="mt-1">
          <Collapsible.Trigger
            class="text-xs text-primary underline hover:no-underline cursor-pointer"
          >
            {open ? 'Hide raw payload' : 'Show raw payload (may contain PII)'}
          </Collapsible.Trigger>
          <Collapsible.Content>
            <pre
              class="text-xs bg-amber-500/5 border border-amber-500/30 px-2 py-1 rounded overflow-x-auto mt-1">{JSON.stringify(
                payload,
                null,
                2,
              )}</pre>
          </Collapsible.Content>
        </Collapsible.Root>
      </div>
    {/if}
  </CardContent>
</Card>
