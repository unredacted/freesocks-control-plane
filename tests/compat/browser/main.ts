import { mount } from 'svelte';
import './style.css';
import '../../../src/client/lib/cap-wasm-config';
import Harness from './Harness.svelte';
import AdminRegister from '../../../src/client/routes/admin/AdminRegister.svelte';

const target = document.getElementById('app')!;
if (window.location.pathname === '/admin/register') mount(AdminRegister, { target });
else mount(Harness, { target });
