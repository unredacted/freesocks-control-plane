import { describe, expect, test } from 'vitest';
import { tagOfName, transportName } from './transportName';

describe('transportName', () => {
  test('the mode name whose tag it is', () => {
    expect(tagOfName('Freedom-Reality')).toBe('FREEDOM_REALITY');
    expect(transportName('FREEDOM_REALITY', ['Freedom-WebSocket', 'Freedom-Reality'])).toBe(
      'Freedom-Reality',
    );
  });

  test('otherwise the tag read as words', () => {
    expect(transportName('FREEDOM_WEBSOCKET')).toBe('Freedom WebSocket');
    expect(transportName('FREEDOM_XHTTP')).toBe('Freedom XHTTP');
    expect(transportName('FREEDOM_REALITY', [null, ''])).toBe('Freedom REALITY');
    expect(transportName('PRIVACY_HYSTERIA2')).toBe('Privacy Hysteria2');
  });

  test('something that is not a tag stays as it is', () => {
    expect(transportName('vless-ws')).toBe('vless-ws');
    expect(transportName('freedomweb2hl30v')).toBe('freedomweb2hl30v');
    expect(transportName(null)).toBe('a transport');
  });
});
