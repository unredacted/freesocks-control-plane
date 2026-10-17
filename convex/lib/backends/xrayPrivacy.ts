/**
 * The no-client-IP-logging Xray `log` block FCP enforces on every config profile
 * (matches docs/privacy.md §5): no access log (the per-connection source-IP
 * record), no error log, DNS logging off, and address masking as belt-and-
 * suspenders if an operator later raises the level.
 *
 * Its own module so the profile template (which the typed profile edits build
 * transports with) does not import the provider that applies those edits.
 */
export const PRIVACY_XRAY_LOG = {
  access: 'none',
  error: 'none',
  loglevel: 'none',
  dnsLog: false,
  maskAddress: 'full',
} as const;
