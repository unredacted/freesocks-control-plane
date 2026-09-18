import { describe, expect, it } from 'vitest';
import { ApiCallError } from '../../../../lib/api';
import { accountDeleteRefusal, deleteRefusal, templateDeleteRefusal } from './refusals';

const err = (code: string) =>
  new ApiCallError(409, { error: { code, message: 'raw server text' } });

describe('delete refusals', () => {
  it('explains an account that is still in use', () => {
    expect(accountDeleteRefusal(err('edge.account_in_use'))).toContain('Edges still live');
    expect(accountDeleteRefusal(err('edge.account_referenced'))).toContain('DNS');
    expect(accountDeleteRefusal(new Error('x'))).toBeNull();
  });
  it('explains the last template of a provider', () => {
    expect(templateDeleteRefusal(err('edge.template_last_of_provider'))).toContain('last template');
    expect(deleteRefusal(err('edge.template_last_of_provider'), 'template')).not.toContain(
      'raw server text',
    );
  });
});
