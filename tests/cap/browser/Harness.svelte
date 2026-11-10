<script lang="ts">
  import CapWidget from '../../../src/client/components/CapWidget.svelte';

  const siteKey = new URLSearchParams(location.search).get('siteKey')!;
  let widget: CapWidget;
  let token = $state('');
</script>

<CapWidget bind:this={widget} apiEndpoint="/cap" {siteKey} onVerify={(value) => (token = value)} />
<output data-testid="token">{token}</output>
<button onclick={() => widget.reset()}>Retry submission</button>
