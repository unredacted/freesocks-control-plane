import { describe, expect, test } from 'vitest';
import { splitLead } from './splitLead';

describe('splitLead', () => {
  test('one sentence has no rest', () => {
    expect(splitLead('One node has no working address there.')).toEqual({
      lead: 'One node has no working address there.',
      rest: '',
    });
  });

  test('splits at the first sentence end', () => {
    expect(
      splitLead('Freedom XHTTP: 1 suggested SNI to add. No node behind this port is fronted.'),
    ).toEqual({
      lead: 'Freedom XHTTP: 1 suggested SNI to add.',
      rest: 'No node behind this port is fronted.',
    });
  });

  test('keeps every later sentence in the rest', () => {
    expect(splitLead('A. B c. D e.').rest).toBe('B c. D e.');
  });

  test('never splits inside a number or before a lower-case word', () => {
    expect(splitLead('About 1.5 GB used, e.g. today.').rest).toBe('');
  });

  test('trims', () => {
    expect(splitLead('  Ready.  ')).toEqual({ lead: 'Ready.', rest: '' });
  });

  test('text with no sentence end is the lead', () => {
    expect(splitLead('Automatic replacement held')).toEqual({
      lead: 'Automatic replacement held',
      rest: '',
    });
  });
});
