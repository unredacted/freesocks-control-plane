/**
 * Component tests (`*.svelte.test.ts`): each test ends with the body as it
 * found it.
 *
 * A bits-ui dialog locks the page's scroll by styling `document.body`, and
 * after the last one closes or unmounts it puts that style back on a timer. A
 * timer still waiting when the file's DOM is torn down fires into no
 * `document` and fails the whole run with an unhandled error (whenever the
 * worker outlives the DOM, so only on a slow runner). This afterEach runs
 * after the test file's own (hooks run in reverse), once the test has
 * unmounted what it mounted, and waits for that restore.
 */
import { afterEach, beforeEach, expect, vi } from 'vitest';

let bodyStyle = '';

beforeEach(() => {
  bodyStyle = document.body.getAttribute('style') ?? '';
});

afterEach(async () => {
  await vi.waitFor(() =>
    expect(
      document.body.getAttribute('style') ?? '',
      'the body is still styled by an open dialog: unmount what the test mounted',
    ).toBe(bodyStyle),
  );
});
