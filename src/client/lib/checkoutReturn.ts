/**
 * Where the browser goes after POST /api/v1/billing/checkout. A hosted order
 * full-page redirects to the processor's page (as every rail always has). A
 * DIRECT order (a crypto rail set to "On FreeSocks" in Admin -> Billing) stays
 * on our origin: the return page's order poll carries the address, amount and
 * network, so the payer never needs to reach the processor's domain.
 */
import { router } from '../stores/router.svelte';
import type { CheckoutResponse } from '../../shared/contracts/billing';

export function followCheckout(res: CheckoutResponse, returnPath: '/account' | '/donate'): void {
  if (res.direct) {
    router.navigate(`${returnPath}?order=${encodeURIComponent(res.orderRef)}`);
    window.scrollTo({ top: 0 });
    return;
  }
  window.location.href = res.redirectUrl;
}
