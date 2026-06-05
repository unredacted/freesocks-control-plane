import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Svelte 5 runes mode — use $state/$derived/$effect, opt out of legacy reactivity.
    runes: true,
  },
};
