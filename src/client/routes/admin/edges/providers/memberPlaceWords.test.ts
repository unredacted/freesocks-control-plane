import { describe, expect, it } from 'vitest';
import { CDN_PLACE_LINE, memberPlaceLine } from './memberPlaceWords';

describe('memberPlaceLine', () => {
  it("shows the name members read after the node's own place, with the letters", () => {
    expect(memberPlaceLine({ name: 'Example City', country: 'BR' })).toBe(
      `In members' apps, after the node's own place: "… via Example City" ("… via Example City A", "B" for a member with two addresses here). The country's flag shows only for a node with no place of its own ("🇧🇷 via Example City").`,
    );
    expect(memberPlaceLine({ name: ' Example,  City ', country: null })).toBe(
      `In members' apps, after the node's own place: "… via Example City" ("… via Example City A", "B" for a member with two addresses here).`,
    );
  });
  it('no name: via relay A', () => {
    expect(memberPlaceLine({ name: '', country: 'BR' })).toBe(
      `In members' apps, after the node's own place: "… via relay A". No place name yet.`,
    );
    expect(memberPlaceLine({ name: null, country: null })).toContain('"… via relay A"');
  });
  it('a CDN zone never carries a place', () => {
    expect(CDN_PLACE_LINE).toContain('"… via CDN 1"');
  });
});
