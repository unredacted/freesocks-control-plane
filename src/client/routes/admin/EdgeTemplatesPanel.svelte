<script lang="ts">
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminEdgeTemplatesQuery } from '../../lib/queries';
  import {
    EDGE_PROVIDER_IDS,
    RelayIdResponse,
    RelayOkResponse,
    EdgeTemplateValidateResponse,
    type EdgeProviderId,
    type EdgeTemplateAdmin,
    type EdgeTemplateField,
  } from '../../../shared/contracts/relays';
  import AdminListState from './AdminListState.svelte';

  /**
   * Edge templates: the full provisioning parameters per provider (flavor/plan,
   * health monitor, timeouts, allowed CIDRs, tags, IP family…), edited through a
   * form generated from the adapter's field descriptors, or as raw JSON. Every
   * save is validated by the adapter's schema server-side; provisioning records
   * the template hash on the edge, and a changed template on a qualified account
   * needs re-qualification. Placeholders: {'{{name}}'} {'{{originAddress}}'}
   * {'{{originPort}}'} {'{{edgePort}}'}.
   */
  const templates = adminEdgeTemplatesQuery();
  const qc = useQueryClient();
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['admin', 'relays'] });
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  type Draft = {
    id: string | null;
    provider: EdgeProviderId;
    name: string;
    params: Record<string, unknown>;
    raw: string;
    useRaw: boolean;
    isDefault: boolean;
  };
  let editor = $state<Draft | null>(null);
  let issues = $state<string[]>([]);

  function getPath(obj: Record<string, unknown>, key: string): unknown {
    return key
      .split('.')
      .reduce<unknown>(
        (acc, k) =>
          acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined,
        obj,
      );
  }
  function setPath(obj: Record<string, unknown>, key: string, value: unknown) {
    const parts = key.split('.');
    let cur = obj;
    for (const p of parts.slice(0, -1)) {
      if (!cur[p] || typeof cur[p] !== 'object') cur[p] = {};
      cur = cur[p] as Record<string, unknown>;
    }
    cur[parts[parts.length - 1] ?? key] = value;
  }
  function newDraft(provider: EdgeProviderId = 'gcore'): Draft {
    const defaults = (templates.data?.schemas[provider]?.defaults ?? {}) as Record<string, unknown>;
    const params = JSON.parse(JSON.stringify(defaults)) as Record<string, unknown>;
    return {
      id: null,
      provider,
      name: '',
      params,
      raw: JSON.stringify(params, null, 2),
      useRaw: false,
      isDefault: false,
    };
  }
  function editDraft(t: EdgeTemplateAdmin): Draft {
    const params = JSON.parse(JSON.stringify(t.params ?? {})) as Record<string, unknown>;
    return {
      id: t.id,
      provider: t.provider,
      name: t.name,
      params,
      raw: JSON.stringify(params, null, 2),
      useRaw: false,
      isDefault: t.isDefault,
    };
  }
  function currentParams(): unknown {
    if (!editor) return {};
    if (editor.useRaw) {
      try {
        return JSON.parse(editor.raw);
      } catch {
        throw new Error('Raw JSON is not valid');
      }
    }
    return editor.params;
  }
  function fieldValue(f: EdgeTemplateField): string {
    const v = getPath(editor!.params, f.key);
    if (f.type === 'string-list') return Array.isArray(v) ? v.join('\n') : '';
    return v === undefined || v === null ? '' : String(v);
  }
  function setField(f: EdgeTemplateField, raw: string | boolean) {
    if (!editor) return;
    let v: unknown = raw;
    if (f.type === 'number') v = raw === '' ? undefined : Number(raw);
    else if (f.type === 'string-list')
      v = String(raw)
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
    else if (f.type === 'boolean') v = Boolean(raw);
    setPath(editor.params, f.key, v);
    editor.raw = JSON.stringify(editor.params, null, 2);
  }

  const validate = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/admin/relay/templates/validate',
        { provider: editor!.provider, params: currentParams() },
        EdgeTemplateValidateResponse,
      ),
    onSuccess: (r) => {
      issues = r.ok ? [] : r.issues;
      if (r.ok) toast.success('Template is valid');
    },
    onError: onError('Validation failed'),
  }));
  const save = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      const params = currentParams();
      if (d.id)
        return apiClient.patch(
          `/api/v1/admin/relay/templates/${d.id}`,
          { name: d.name.trim(), params, isDefault: d.isDefault },
          RelayOkResponse,
        );
      return apiClient.post(
        '/api/v1/admin/relay/templates',
        { provider: d.provider, name: d.name.trim(), params, isDefault: d.isDefault },
        RelayIdResponse,
      );
    },
    onSuccess: () => {
      editor = null;
      issues = [];
      invalidate();
      toast.success('Template saved');
    },
    onError: (err) => {
      issues = [apiErrorMessage(err)];
      onError('Could not save the template')(err);
    },
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/relay/templates/${id}`, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Template removed');
    },
    onError: onError('Could not remove the template'),
  }));
  const fields = $derived((editor && templates.data?.schemas[editor.provider]?.fields) ?? []);
</script>

<div class="space-y-4">
  <div class="flex justify-end">
    <Button onclick={() => (editor = newDraft())}>New template</Button>
  </div>
  {#if templates.isError}<AdminListState
      error={templates.error}
      onRetry={() => void templates.refetch()}
    />{/if}
  {#each EDGE_PROVIDER_IDS as provider (provider)}
    {@const rows = (templates.data?.templates ?? []).filter((t) => t.provider === provider)}
    <Card>
      <CardHeader class="pb-2">
        <CardTitle class="text-base">{provider}</CardTitle>
        <CardDescription
          >{rows.length} template{rows.length === 1 ? '' : 's'}{rows.length === 0
            ? ' (the compiled default is used until one is saved)'
            : ''}</CardDescription
        >
      </CardHeader>
      <CardContent>
        <ul class="divide-y text-sm">
          {#each rows as t (t.id)}
            <li class="flex flex-wrap items-center justify-between gap-2 py-2">
              <div>
                <span class="font-medium">{t.name}</span>
                {#if t.isDefault}<span class="ml-2 rounded-full border px-2 py-0.5 text-xs"
                    >default</span
                  >{/if}
                <span class="ml-2 font-mono text-xs text-muted-foreground"
                  >{t.paramsHash.slice(0, 12)}</span
                >
              </div>
              <div class="flex gap-1.5">
                <Button size="sm" variant="ghost" onclick={() => (editor = editDraft(t))}
                  >Edit</Button
                >
                <Button
                  size="sm"
                  variant="ghost"
                  class="text-destructive"
                  onclick={() => remove.mutate(t.id)}>Remove</Button
                >
              </div>
            </li>
          {/each}
        </ul>
        {#if rows.length === 0}
          <Button
            size="sm"
            variant="outline"
            class="mt-2"
            onclick={() => (editor = newDraft(provider))}>Create from defaults</Button
          >
        {/if}
      </CardContent>
    </Card>
  {/each}
</div>

<Dialog.Root open={editor !== null} onOpenChange={(v) => !v && (editor = null)}>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit template' : 'New template'}</Dialog.Title>
      <Dialog.Description
        >Validated against the provider adapter's schema. Placeholders: {'{{name}}'}, {'{{originAddress}}'},
        {'{{originPort}}'}, {'{{edgePort}}'}.</Dialog.Description
      >
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3">
        <div class="grid gap-3 sm:grid-cols-2">
          {#if !editor.id}
            <label class="text-xs"
              >Provider
              <Select.Root
                type="single"
                value={editor.provider}
                onValueChange={(v) => (editor = newDraft(v as EdgeProviderId))}
              >
                <Select.Trigger class="mt-1 w-full">{editor.provider}</Select.Trigger>
                <Select.Content
                  >{#each EDGE_PROVIDER_IDS as p (p)}<Select.Item value={p}>{p}</Select.Item
                    >{/each}</Select.Content
                >
              </Select.Root>
            </label>
          {/if}
          <label class="text-xs"
            >Name<Input class="mt-1" bind:value={editor.name} placeholder="default" /></label
          >
        </div>
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.isDefault} /> Default for this provider</label
        >
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.useRaw} /> Edit as raw JSON</label
        >
        {#if editor.useRaw}
          <textarea
            class="w-full rounded-md border bg-background p-2 font-mono text-xs"
            rows="16"
            bind:value={editor.raw}
          ></textarea>
        {:else}
          <div class="grid gap-3 sm:grid-cols-2">
            {#each fields as f (f.key)}
              <label class="text-xs">
                {f.label}{f.required ? ' *' : ''}
                {#if f.type === 'boolean'}
                  <div class="mt-1">
                    <Checkbox
                      checked={Boolean(getPath(editor.params, f.key))}
                      onCheckedChange={(v) => setField(f, Boolean(v))}
                    />
                  </div>
                {:else if f.type === 'select'}
                  <Select.Root
                    type="single"
                    value={fieldValue(f)}
                    onValueChange={(v) => setField(f, v)}
                  >
                    <Select.Trigger class="mt-1 w-full"
                      >{(f.options?.find((o) => o.value === fieldValue(f))?.label ??
                        fieldValue(f)) ||
                        'Select'}</Select.Trigger
                    >
                    <Select.Content
                      >{#each f.options ?? [] as o (o.value)}<Select.Item value={o.value}
                          >{o.label}</Select.Item
                        >{/each}</Select.Content
                    >
                  </Select.Root>
                {:else if f.type === 'string-list'}
                  <textarea
                    class="mt-1 w-full rounded-md border bg-background p-2 font-mono text-xs"
                    rows="3"
                    value={fieldValue(f)}
                    oninput={(e) => setField(f, (e.currentTarget as HTMLTextAreaElement).value)}
                  ></textarea>
                {:else}
                  <Input
                    class="mt-1"
                    type={f.type === 'number' ? 'number' : 'text'}
                    value={fieldValue(f)}
                    oninput={(e) => setField(f, (e.currentTarget as HTMLInputElement).value)}
                  />
                {/if}
                {#if f.help}<span class="mt-0.5 block text-[11px] text-muted-foreground"
                    >{f.help}</span
                  >{/if}
              </label>
            {/each}
          </div>
        {/if}
        {#if issues.length > 0}
          <ul
            class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive"
          >
            {#each issues as i, k (k)}<li>{i}</li>{/each}
          </ul>
        {/if}
      </div>
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (editor = null)}>Cancel</Button>
      <Button variant="outline" disabled={validate.isPending} onclick={() => validate.mutate()}
        >Validate</Button
      >
      <Button disabled={save.isPending} onclick={() => save.mutate()}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
