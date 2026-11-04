import { describe, expect, it } from 'vitest';
import { CDN_PLACE_LINE, memberPlaceLine } from './memberPlaceWords';

describe('memberPlaceLine', () => {
  it('shows the name members read, with the flag and the letters', () => {
    expect(memberPlaceLine({ name: 'Example City', country: 'BR' })).toBe(
      `In members' apps: "🇧🇷 via Example City" ("🇧🇷 via Example City A", "B" for a member with two addresses here).`,
    );
    expect(memberPlaceLine({ name: ' Example,  City ', country: null })).toBe(
      `In members' apps: "via Example City" ("via Example City A", "B" for a member with two addresses here).`,
    );
  });
  it('no name: via relay A, and no flag even with a country', () => {
    expect(memberPlaceLine({ name: '', country: 'BR' })).toBe(
      `In members' apps: "via relay A". No place name yet, so no flag either.`,
    );
    expect(memberPlaceLine({ name: null, country: null })).toContain('"via relay A"');
  });
  it('a CDN zone never carries a place', () => {
    expect(CDN_PLACE_LINE).toContain('"🌐 via CDN 1"');
  });
});
