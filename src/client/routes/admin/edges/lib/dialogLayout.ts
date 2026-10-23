/**
 * Dialog sizing for the edges admin: a dialog never grows past the window.
 * Options, a location picker or a long error can make one taller than the
 * screen; its footer (the buttons) must stay reachable by mouse.
 *
 *   CONFIRM_FIT, CONFIRM_BODY  the confirm dialog (components/ConfirmDialog.svelte):
 *                              header and footer stay put, the body between scrolls
 *   DIALOG_FIT                 any other dialog: its content scrolls inside the window
 *   STICKY_FOOTER              that dialog's footer stays in view while the content
 *                              scrolls under it (opaque: the footer's tint over the popover)
 *
 * A test (dialogLayout.test.ts) pins every edges dialog to one of these.
 */
export const CONFIRM_FIT = 'flex max-h-[calc(100dvh-2rem)] flex-col';
export const CONFIRM_BODY = '-mx-4 -my-1 flex min-h-0 flex-col gap-4 overflow-y-auto px-4 py-1';
export const DIALOG_FIT = 'max-h-[calc(100dvh-2rem)] overflow-y-auto';
// `-bottom-4`: a sticky offset counts from inside the content's padding (`p-4`),
// so the footer sits flush with the dialog's bottom edge as it does unstuck.
export const STICKY_FOOTER =
  'sticky -bottom-4 z-10 bg-[color-mix(in_oklab,var(--muted)_50%,var(--popover))]';
