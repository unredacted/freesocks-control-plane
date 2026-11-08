<script lang="ts">
  /**
   * Add a country list, or edit one. Where it comes from (an address or a
   * paste) is chosen once, when the list is added.
   *
   * Props:
   *   open: boolean (bindable)
   *   list?: CountryListView          edit this one; absent: add a new one
   *   defaultFetchHours: number       `edge.lists.defaultFetchHours`
   *   onSaved?: (id: string) => void
   */
  import { untrack } from 'svelte';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import { ApiCallError } from '@client/lib/api';
  import {
    createCountryList,
    invalidateCountryLists,
    updateCountryList,
  } from '@client/lib/countryListsApi';
  import {
    MAX_LIST_NETWORKS,
    type CountryListRegime,
    type CountryListView,
  } from '@shared/contracts/countryLists';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { parseAsns } from '../names/lib/words';
  import { listErrorWords, REGIME_WORDS } from './listWords';

  interface Props {
    open: boolean;
    list?: CountryListView;
    defaultFetchHours: number;
    onSaved?: (id: string) => void;
  }
  let { open = $bindable(), list, defaultFetchHours, onSaved }: Props = $props();

  const SELECT = 'border-border bg-background min-h-9 w-full rounded-md border px-2 py-1.5 text-sm';
  const qc = useQueryClient();
  const uid = $props.id();

  let label = $state('');
  let country = $state('');
  let regime = $state<CountryListRegime>('allowlist');
  let kind = $state<'url' | 'paste'>('url');
  let url = $state('');
  let networks = $state('');
  let hours = $state(24);
  let enabled = $state(true);
  let busy = $state(false);

  // Fill the form when it opens, and only then: the page refetches the list
  // while the dialog is open, which must not undo what is being typed.
  let wasOpen = false;
  $effect(() => {
    const isOpen = open;
    if (isOpen && !wasOpen) untrack(fill);
    wasOpen = isOpen;
  });
  function fill() {
    label = list?.label ?? '';
    country = list?.country ?? '';
    regime = list?.regime ?? 'allowlist';
    kind = list?.source.kind ?? 'url';
    url = list?.source.kind === 'url' ? list.source.url : '';
    networks = (list?.networks ?? []).map((n) => `AS${n}`).join(' ');
    hours = list?.fetchEveryHours ?? defaultFetchHours;
    enabled = list?.enabled ?? true;
  }

  // A country list covers up to 32 networks (MAX_LIST_NETWORKS in convex/countryLists.ts).
  let parsedNetworks = $derived(parseAsns(networks, MAX_LIST_NETWORKS));
  let valid = $derived(
    label.trim().length > 0 &&
      /^[A-Za-z]{2}$/.test(country.trim()) &&
      parsedNetworks !== null &&
      (kind === 'paste' || url.trim().startsWith('https://')) &&
      Number.isInteger(hours) &&
      hours >= 1 &&
      hours <= 168,
  );

  async function save() {
    if (!valid || busy) return;
    busy = true;
    try {
      const common = {
        label: label.trim(),
        country: country.trim().toUpperCase(),
        regime,
        networks: parsedNetworks ?? [],
        fetchEveryHours: hours,
      };
      if (list) {
        await updateCountryList(list.id, {
          ...common,
          enabled,
          ...(list.source.kind === 'url' ? { url: url.trim() } : {}),
        });
        toast.success('List saved.');
        onSaved?.(list.id);
      } else {
        const r = await createCountryList({
          ...common,
          source: kind === 'url' ? { kind: 'url', url: url.trim() } : { kind: 'paste' },
        });
        toast.success(
          kind === 'url'
            ? 'List added. Fetch it from its page.'
            : 'List added. Paste it on its page.',
        );
        onSaved?.(r.id);
      }
      open = false;
    } catch (e) {
      toast.error(listErrorWords(e instanceof ApiCallError ? e.payload.error.code : null));
    } finally {
      busy = false;
      invalidateCountryLists(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-md`}>
    <Dialog.Header>
      <Dialog.Title>{list ? `Edit ${list.label}` : 'Add a country list'}</Dialog.Title>
      <Dialog.Description>
        Hostnames and addresses reported to work, or to be blocked, in one country. It is evidence
        only and never changes what members get.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-3"
      onsubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-label`}>Name</Label>
        <Input id={`${uid}-label`} bind:value={label} autocomplete="off" />
      </div>
      <div class="grid grid-cols-2 gap-3">
        <div class="space-y-1.5">
          <Label for={`${uid}-country`}>Country code</Label>
          <Input
            id={`${uid}-country`}
            bind:value={country}
            maxlength={2}
            placeholder="RU"
            autocomplete="off"
            autocapitalize="characters"
            spellcheck={false}
          />
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-regime`}>What it lists</Label>
          <select id={`${uid}-regime`} bind:value={regime} class={SELECT}>
            <option value="allowlist">{REGIME_WORDS.allowlist.label}</option>
            <option value="blocklist">{REGIME_WORDS.blocklist.label}</option>
          </select>
        </div>
      </div>
      <p class="text-muted-foreground text-xs">{REGIME_WORDS[regime].explain}</p>
      {#if !list}
        <div class="space-y-1.5">
          <Label for={`${uid}-kind`}>Where it comes from</Label>
          <select id={`${uid}-kind`} bind:value={kind} class={SELECT}>
            <option value="url">An address FCP fetches</option>
            <option value="paste">A copy you paste</option>
          </select>
        </div>
      {/if}
      {#if kind === 'url'}
        <div class="space-y-1.5">
          <Label for={`${uid}-url`}>Address</Label>
          <Input
            id={`${uid}-url`}
            bind:value={url}
            placeholder="https://example.com/list.txt"
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
          />
          <p class="text-muted-foreground text-xs">
            The file itself, over https. FCP does not follow redirects.
          </p>
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-hours`}>Fetch every (hours)</Label>
          <Input id={`${uid}-hours`} type="number" min={1} max={168} bind:value={hours} />
        </div>
      {/if}
      <div class="space-y-1.5">
        <Label for={`${uid}-networks`}>Networks it covers (optional ASNs)</Label>
        <Input
          id={`${uid}-networks`}
          bind:value={networks}
          placeholder="AS64500 AS64501"
          autocomplete="off"
          autocapitalize="off"
          spellcheck={false}
          aria-invalid={parsedNetworks === null}
        />
        <p class="text-muted-foreground text-xs">
          Empty: some networks in the country, without saying which.
        </p>
      </div>
      {#if list}
        <div class="flex items-center gap-3">
          <Switch id={`${uid}-enabled`} bind:checked={enabled} />
          <Label for={`${uid}-enabled`} class="font-normal">
            On: FCP fetches it and reads it as evidence
          </Label>
        </div>
      {/if}
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!valid || busy}>{busy ? 'Working…' : 'Save'}</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
