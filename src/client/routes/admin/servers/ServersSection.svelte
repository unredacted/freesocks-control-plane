<script lang="ts">
  /**
   * Admin -> Servers section shell: the admin chrome plus the section's page.
   * AdminRouter lazy-imports this file for every `/admin/servers` path, so the
   * section is one chunk outside the main admin bundle.
   */
  import AdminLayout from '../AdminLayout.svelte';
  import ServersHome from './ServersHome.svelte';
</script>

<AdminLayout>
  <ServersHome />
</AdminLayout>
