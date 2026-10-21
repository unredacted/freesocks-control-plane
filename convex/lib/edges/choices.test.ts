import { describe, expect, it } from 'vitest';
import { accountOptionDefaultsOf, builtForChoices, certificateValuesFor } from './choices';
import { parseOptionValues } from './providers/options';

const parse = (json: string | undefined) => parseOptionValues(json);

describe('account option defaults', () => {
  it('reads the stored defaults over a copy a row still keeps under settings', () => {
    expect(
      accountOptionDefaultsOf({
        provider: 'fastly',
        settings: { type: 'fastly', dnsAccountId: 'd', certificateAuthority: 'globalsign' },
        optionDefaults: JSON.stringify({ certificateScope: 'wildcard' }),
      }),
    ).toEqual({ certificateAuthority: 'globalsign', certificateScope: 'wildcard' });
    expect(accountOptionDefaultsOf({ provider: 'gcore', settings: { type: 'gcore' } })).toEqual({});
  });
});

describe('certificateValuesFor', () => {
  it('declared defaults, then the account, then the pick', () => {
    expect(certificateValuesFor('fastly', {}, null)).toEqual({
      certificateAuthority: 'certainly',
      certificateScope: 'per_host',
    });
    expect(
      certificateValuesFor(
        'fastly',
        { certificateScope: 'wildcard' },
        { certificateAuthority: 'lets-encrypt' },
      ),
    ).toEqual({ certificateAuthority: 'lets-encrypt', certificateScope: 'wildcard' });
    // Tuning choices never leak into the certificate.
    expect(certificateValuesFor('fastly', {}, { preferIpv6: true })).not.toHaveProperty(
      'preferIpv6',
    );
    expect(certificateValuesFor('gcore', {}, { flavor: 'x' })).toEqual({});
  });
});

describe('builtForChoices', () => {
  it('an edge from before options fits a pick from before options', () => {
    expect(builtForChoices({ provider: 'gcore', intent: null }, null, {}, parse)).toBe(true);
  });

  it('compares the tuning choices an edge froze with what the pick asks now', () => {
    const edge = {
      provider: 'gcore' as const,
      choices: JSON.stringify({ flavor: 'lb1-2-4' }),
      intent: null,
    };
    expect(builtForChoices(edge, { flavor: 'lb1-2-4' }, {}, parse)).toBe(true);
    expect(builtForChoices(edge, { flavor: 'lb1-4-8' }, {}, parse)).toBe(false);
    expect(builtForChoices(edge, {}, {}, parse)).toBe(false);
    // An edge from before options under a pick that now chooses a size does not fit.
    expect(
      builtForChoices({ provider: 'gcore', intent: null }, { flavor: 'lb1-4-8' }, {}, parse),
    ).toBe(false);
  });

  it('compares the certificate an edge froze in its intent with what the pick would get now', () => {
    // An edge planned before options: its intent froze the account's authority then.
    const legacy = { provider: 'fastly' as const, intent: { certificateAuthority: 'certainly' } };
    // A pick protected since (its options snapshot the account default) still fits it.
    expect(builtForChoices(legacy, { certificateAuthority: 'certainly' }, {}, parse)).toBe(true);
    expect(builtForChoices(legacy, { certificateAuthority: 'lets-encrypt' }, {}, parse)).toBe(
      false,
    );
    // The account's default only counts where the pick does not choose.
    expect(builtForChoices(legacy, {}, { certificateAuthority: 'lets-encrypt' }, parse)).toBe(
      false,
    );
    const wild = {
      provider: 'fastly' as const,
      choices: JSON.stringify({ certificateScope: 'wildcard' }),
      intent: { certificateAuthority: 'certainly', certificateScope: 'wildcard' },
    };
    expect(builtForChoices(wild, { certificateScope: 'wildcard' }, {}, parse)).toBe(true);
    expect(builtForChoices(wild, { certificateScope: 'per_host' }, {}, parse)).toBe(false);
  });
});
