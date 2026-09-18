<script lang="ts">
  /**
   * Template editor body (rendered inside the Templates page's Sheet).
   * Descriptor-driven: every field of `schema.fields` is rendered by its type;
   * "Advanced JSON" edits the same params object as text (two-way).
   *
   * Props:
   *   template: EdgeTemplateAdmin | null       null = a new template
   *   provider: EdgeProviderId                 the provider (fixed; chosen before the editor opens)
   *   schema: { fields, defaults }             `schemas[provider]` of the templates response
   *   accounts: { id, name }[]                 accounts of this provider (the scope select)
   *   onsaved(id: string)                      after create / update
   *   ondelete?()                              ask the page to open its delete dialog
   *   oncancel()
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import * as Collapsible from '@client/components/ui/collapsible';
  import * as Select from '@client/components/ui/select';
  import InlineError from '@client/components/InlineError.svelte';
  import type {
    EdgeProviderId,
    EdgeTemplateAdmin,
    EdgeTemplateField,
  } from '../../../../../shared/contracts/edges';
  import {
    createTemplate,
    invalidateProviders,
    templateValidateQuery,
    updateTemplate,
    type ValidateTemplateBody,
  } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { providerLabel } from '../lib/format';
  import TemplateField from './TemplateField.svelte';
  import {
    asParams,
    changedKeys,
    deepEqual,
    formatParams,
    getPath,
    issueInWords,
    parseParamsJson,
    resetField,
    setPath,
    unsetPath,
    type Params,
  } from './params';

  interface Props {
    template: EdgeTemplateAdmin | null;
    provider: EdgeProviderId;
    schema: { fields: EdgeTemplateField[]; defaults: Record<string, unknown> };
    accounts: Array<{ id: string; name: string }>;
    onsaved: (id: string) => void;
    ondelete?: () => void;
    oncancel: () => void;
  }
  let { template, provider, schema, accounts, onsaved, ondelete, oncancel }: Props = $props();

  const qc = useQueryClient();
  const ALL = '__all__';

  // Seeded once per mount (the page keys this component by template id).
  const initial = untrack(() => ({
    name: template?.name ?? '',
    params: template ? asParams(template.params) : { ...schema.defaults },
    isDefault: template?.isDefault ?? false,
    accountId: template?.accountId ?? null,
  }));
  let name = $state(initial.name);
  let params = $state<Params>(initial.params);
  let isDefault = $state(initial.isDefault);
  let accountId = $state<string | null>(initial.accountId);

  // --- form <-> JSON (one params object, two views) --------------------------------------------
  let jsonText = $state(formatParams(initial.params));
  let jsonError = $state<string | null>(null);
  function setParams(next: Params) {
    params = next;
    jsonText = formatParams(next);
    jsonError = null;
  }
  function onJsonInput(text: string) {
    jsonText = text;
    const parsed = parseParamsJson(text);
    if (parsed.ok) {
      params = parsed.params;
      jsonError = null;
    } else {
      jsonError = parsed.error;
    }
  }
  const setField = (key: string, value: unknown) =>
    setParams(value === undefined ? unsetPath(params, key) : setPath(params, key, value));

  const changed = $derived(new Set(changedKeys(params, schema.defaults, schema.fields)));
  const dirty = $derived(
    name !== initial.name ||
      isDefault !== initial.isDefault ||
      accountId !== initial.accountId ||
      !deepEqual(params, initial.params),
  );

  // --- live validation (debounced) ---------------------------------------------------------------
  let validateBody = $state<ValidateTemplateBody | null>(null);
  $effect(() => {
    const body: ValidateTemplateBody = { provider, params: $state.snapshot(params) };
    if (jsonError !== null) {
      validateBody = null;
      return;
    }
    const timer = setTimeout(() => (validateBody = body), 500);
    return () => clearTimeout(timer);
  });
  const validation = templateValidateQuery(() => validateBody);
  const settled = $derived(
    validateBody !== null && deepEqual(validateBody.params, $state.snapshot(params)),
  );
  const issues = $derived(
    validation.data && !validation.data.ok
      ? validation.data.issues.map((i) => issueInWords(i, schema.fields))
      : [],
  );
  const valid = $derived(settled && validation.data?.ok === true);

  const nameOk = $derived(name.trim().length > 0);
  const canSave = $derived(nameOk && jsonError === null && valid && (template === null || dirty));

  const save = createMutation(() => ({
    mutationFn: async () => {
      const body = {
        name: name.trim(),
        params: $state.snapshot(params),
        isDefault,
        accountId,
      };
      if (template) {
        await updateTemplate(template.id, body);
        return template.id;
      }
      return (await createTemplate({ provider, ...body })).id;
    },
    onSuccess: (id) => {
      invalidateProviders(qc);
      toast.success(template ? 'Template saved' : 'Template created');
      onsaved(id);
    },
    onError: (err: unknown) =>
      toast.error('Could not save the template', { description: edgeErrorMessage(err) }),
  }));
</script>

<div class="space-y-5">
  <div class="grid gap-3 sm:grid-cols-2">
    <div class="space-y-1.5">
      <Label for="tpl-name">Name</Label>
      <Input id="tpl-name" bind:value={name} placeholder="Standard" aria-invalid={!nameOk} />
    </div>
    <div class="space-y-1.5">
      <Label for="tpl-scope">Available to</Label>
      <Select.Root
        type="single"
        value={accountId ?? ALL}
        onValueChange={(v) => (accountId = v === ALL ? null : v)}
      >
        <Select.Trigger id="tpl-scope" class="w-full">
          {accountId === null
            ? `Every ${providerLabel(provider)} account`
            : (accounts.find((a) => a.id === accountId)?.name ?? 'An account that was removed')}
        </Select.Trigger>
        <Select.Content>
          <Select.Item value={ALL}>Every {providerLabel(provider)} account</Select.Item>
          {#each accounts as a (a.id)}
            <Select.Item value={a.id}>Only {a.name}</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
    </div>
  </div>

  <label class="flex items-start gap-3 text-sm">
    <Switch bind:checked={isDefault} class="mt-0.5" />
    <span>
      <span class="font-medium">Default template</span>
      <span class="block text-xs text-muted-foreground">
        Accounts in its scope that name no template of their own provision from this one. Making it
        the default replaces the current default of the same scope, and accounts whose effective
        template changes lose their qualification.
      </span>
    </span>
  </label>

  <div class="space-y-4">
    <div class="flex items-center justify-between gap-2">
      <h3 class="text-sm font-semibold">Parameters</h3>
      {#if changed.size > 0}
        <Button
          size="sm"
          variant="ghost"
          class="h-7 text-xs"
          onclick={() => setParams({ ...schema.defaults })}
        >
          Reset all {changed.size} to default
        </Button>
      {:else}
        <Badge variant="muted">All provider defaults</Badge>
      {/if}
    </div>
    {#if schema.fields.length === 0}
      <p class="text-sm text-muted-foreground">
        This provider declares no form fields. Edit the parameters as JSON below.
      </p>
    {/if}
    <div class="grid gap-4 sm:grid-cols-2">
      {#each schema.fields as f (f.key)}
        <TemplateField
          field={f}
          value={getPath(params, f.key)}
          defaultValue={getPath(schema.defaults, f.key)}
          changed={changed.has(f.key)}
          disabled={jsonError !== null}
          onchange={(v) => setField(f.key, v)}
          onreset={() => setParams(resetField(params, schema.defaults, f.key))}
        />
      {/each}
    </div>
  </div>

  <Collapsible.Root>
    <Collapsible.Trigger
      class="group flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground"
    >
      <ChevronRight class="size-4 transition-transform group-data-[state=open]:rotate-90" />
      Advanced JSON
    </Collapsible.Trigger>
    <Collapsible.Content class="space-y-1.5 pt-2">
      <Label for="tpl-json" class="sr-only">Parameters as JSON</Label>
      <textarea
        id="tpl-json"
        rows="14"
        spellcheck="false"
        class="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs shadow-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        aria-invalid={jsonError !== null}
        value={jsonText}
        oninput={(e) => onJsonInput(e.currentTarget.value)}
      ></textarea>
      <p class="text-xs text-muted-foreground">
        The same parameters the form edits, including any the form has no field for. Text values may
        use the placeholders {'{{name}}'}, {'{{originAddress}}'}, {'{{originPort}}'} and
        {'{{edgePort}}'}.
      </p>
      {#if jsonError}<InlineError message={jsonError} />{/if}
    </Collapsible.Content>
  </Collapsible.Root>

  <div aria-live="polite" class="text-sm">
    {#if jsonError}
      <p class="text-muted-foreground">Fix the JSON to check the parameters.</p>
    {:else if validation.isError && settled}
      <InlineError message={edgeErrorMessage(validation.error)} />
    {:else if !settled || validation.isFetching}
      <p class="text-muted-foreground">Checking the parameters</p>
    {:else if issues.length > 0}
      <div class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2">
        <p class="font-medium text-destructive">
          {issues.length === 1 ? 'One problem to fix' : `${issues.length} problems to fix`}
        </p>
        <ul class="mt-1 list-disc space-y-0.5 ps-5 text-destructive">
          {#each issues as i (i)}<li>{i}</li>{/each}
        </ul>
      </div>
    {:else if valid}
      <p class="text-emerald-700 dark:text-emerald-300">The provider accepts these parameters.</p>
    {/if}
  </div>

  <div class="flex flex-wrap items-center justify-between gap-2 border-t pt-4">
    <div>
      {#if template && ondelete}
        <Button variant="ghost" class="text-destructive" onclick={ondelete}>Delete template</Button>
      {/if}
    </div>
    <div class="flex gap-2">
      <Button variant="outline" onclick={oncancel}>Cancel</Button>
      <Button disabled={!canSave || save.isPending} onclick={() => save.mutate()}>
        {save.isPending ? 'Saving' : template ? 'Save template' : 'Create template'}
      </Button>
    </div>
  </div>
</div>
