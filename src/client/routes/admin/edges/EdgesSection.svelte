<script lang="ts">
  /**
   * Admin -> Edges section shell: the admin chrome plus the section's own router.
   * AdminRouter lazy-imports this file for every `/admin/edges` path, so the whole
   * section (pages, drawers, charts) is one chunk outside the main admin bundle.
   */
  import AdminLayout from '../AdminLayout.svelte';
  import EdgesRouter from './EdgesRouter.svelte';
</script>

<AdminLayout>
  <EdgesRouter />
</AdminLayout>
