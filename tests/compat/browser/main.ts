import { mount } from 'svelte';
import './style.css';
import '../../../src/client/lib/cap-wasm-config';
import Harness from './Harness.svelte';
mount(Harness, { target: document.getElementById('app')! });
