<script lang="ts">
  import Heart from '@lucide/svelte/icons/heart';

  /**
   * Brief framing card explaining how the service is funded. We deliberately
   * don't enumerate specific programs / impact items here — doing so
   * requires knowing the real allocation, which lives on the Unredacted
   * website itself. We just link there. Donations are the active funding
   * path today; membership signup is being designed and will appear here
   * once the signup flow is wired end-to-end.
   */
</script>

<section class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-4">
  <div class="flex items-start gap-3">
    <div class="rounded-full bg-primary/10 p-2 text-primary shrink-0" aria-hidden="true">
      <Heart class="size-5" />
    </div>
    <div>
      <h2 class="text-xl font-display font-bold tracking-tight">Donations support Unredacted</h2>
      <p class="text-sm text-muted-foreground mt-1 max-w-xl leading-relaxed">
        Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations
        fund the work — see what that work is on the Unredacted site.
      </p>
    </div>
  </div>

  <div class="pt-2 flex flex-wrap gap-3">
    <a href="https://unredacted.org/donate" target="_blank" rel="noopener noreferrer">
      <span
        class="inline-flex items-center gap-1.5 text-sm underline hover:text-foreground text-muted-foreground"
      >
        Donate
      </span>
    </a>
    <a href="https://unredacted.org" target="_blank" rel="noopener noreferrer">
      <span
        class="inline-flex items-center gap-1.5 text-sm underline hover:text-foreground text-muted-foreground"
      >
        unredacted.org
      </span>
    </a>
    <span class="inline-flex items-center gap-1.5 text-sm text-muted-foreground/60">
      Membership (coming soon)
    </span>
  </div>
</section>
