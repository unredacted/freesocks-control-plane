import { describe, expect, it, vi } from 'vitest';

// The shared error copy is i18n-backed (a Svelte runes module); this file pins the edge wording only.
vi.mock('../../../../lib/errors', () => ({ apiErrorMessage: () => 'shared copy' }));

import { ApiCallError } from '../../../../lib/api';
import { EdgeRefusalError, edgeErrorMessage } from './edgeErrors';

describe('edgeErrorMessage', () => {
  const refused = (code: string, status = 409) =>
    new ApiCallError(status, { error: { code, message: 'raw server text' } });

  it('words a refusal code from the shared table as what happened plus what to do', () => {
    const line = edgeErrorMessage(refused('edge.listener_in_use'));
    expect(line).toBe(
      'Edges still use this listener. Destroy or delete those edges first (Edges tab), then try again.',
    );
    expect(edgeErrorMessage(new EdgeRefusalError('edge.node_already_bound'))).toBe(
      'Another origin already covers this node.',
    );
  });

  it('words a throttled call whatever code it carries', () => {
    for (const err of [refused('edge.anything', 429), refused('rate_limited', 429)]) {
      expect(edgeErrorMessage(err)).toContain('asked too often');
    }
  });

  it('keeps label plus fix for the status codes', () => {
    expect(edgeErrorMessage(refused('edge.pool_empty'))).toBe('Pool empty. Publish an edge.');
  });
});
