import { mount } from 'svelte';
import Harness from './Harness.svelte';

window.CAP_SCRIPT_NONCE =
  document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')!.content;
mount(Harness, { target: document.getElementById('app')! });
