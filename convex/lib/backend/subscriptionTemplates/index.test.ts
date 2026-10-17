import { describe, expect, test } from 'vitest';
import {
  SUBSCRIPTION_TEMPLATES,
  TEMPLATE_FAMILIES,
  base64Utf8,
  desiredTemplateBody,
  shippedTemplateHashes,
  stageShippedTemplates,
  templateDrift,
  templateHash,
  templatesOutdated,
} from './index';
import { SINGBOX_JSON } from './SINGBOX';

describe('subscription templates', () => {
  test('every family has a body and the YAML ones keep the splice anchors byte-exact', () => {
    for (const f of TEMPLATE_FAMILIES) {
      const d = SUBSCRIPTION_TEMPLATES[f];
      if (d.kind === 'yaml') expect(d.body).toContain('proxies: # LEAVE THIS LINE!');
      else expect(d.body).toBeTypeOf('object');
    }
  });

  test('base64 is standard and UTF-8 (the arrow in the group name survives)', () => {
    expect(base64Utf8('→ Remnawave')).toBe('4oaSIFJlbW5hd2F2ZQ==');
  });

  test('drift: JSON structurally, YAML by its base64 body', () => {
    const singbox = SUBSCRIPTION_TEMPLATES.SINGBOX;
    const live = {
      templateJson: JSON.parse(JSON.stringify(singbox.body)),
      encodedTemplateYaml: null,
    };
    expect(templateDrift(live, singbox)).toBe(false);
    expect(
      templateDrift({ ...live, templateJson: { ...live.templateJson, log: {} } }, singbox),
    ).toBe(true);

    const mihomo = SUBSCRIPTION_TEMPLATES.MIHOMO;
    const body = desiredTemplateBody(mihomo);
    expect('encodedTemplateYaml' in body).toBe(true);
    const yamlLive = {
      templateJson: null,
      encodedTemplateYaml: (body as { encodedTemplateYaml: string }).encodedTemplateYaml,
    };
    expect(templateDrift(yamlLive, mihomo)).toBe(false);
    expect(
      templateDrift({ templateJson: null, encodedTemplateYaml: base64Utf8('x') }, mihomo),
    ).toBe(true);
    expect(templateDrift({ templateJson: null, encodedTemplateYaml: null }, mihomo)).toBe(true);
  });

  test('apart from the selector group, no template names the backend product', () => {
    // The group's name is renamed in what members receive; nothing else in a
    // template is, and a member can read the raw body (docs/privacy.md §5c).
    for (const f of TEMPLATE_FAMILIES) {
      const d = SUBSCRIPTION_TEMPLATES[f];
      const text = d.kind === 'yaml' ? d.body : JSON.stringify(d.body);
      expect(text.replaceAll('→ Remnawave', ''), f).not.toMatch(/remnawave/i);
    }
    expect(SINGBOX_JSON.experimental.cache_file).toMatchObject({
      path: 'cache.db',
      cache_id: 'default',
    });
  });

  test('outdated: anything not matched, or matched under a template FCP no longer ships', async () => {
    const shipped = await shippedTemplateHashes();
    expect(shipped.SINGBOX).toBe(await templateHash(SUBSCRIPTION_TEMPLATES.SINGBOX));
    const matched = TEMPLATE_FAMILIES.map((family) => ({
      family,
      hash: shipped[family],
      state: 'matched',
    }));
    expect(templatesOutdated(matched, shipped)).toBe(false);
    expect(templatesOutdated([], shipped)).toBe(false);
    expect(templatesOutdated([{ ...matched[0]!, hash: 'an-earlier-release' }], shipped)).toBe(true);
    expect(templatesOutdated([{ ...matched[1]!, state: 'drifted' }], shipped)).toBe(true);
    expect(templatesOutdated([{ ...matched[2]!, state: 'refused' }], shipped)).toBe(true);
    expect(templatesOutdated([{ family: 'GONE', hash: 'x', state: 'matched' }], shipped)).toBe(
      false,
    );
  });

  test('staging: an entry FCP ships differently takes the new hash, not matched; the rest stay', () => {
    const shipped = { SINGBOX: 'new', MIHOMO: 'm' };
    expect(
      stageShippedTemplates(
        [
          { family: 'SINGBOX', hash: 'old', state: 'matched' as const },
          { family: 'MIHOMO', hash: 'm', state: 'refused' as const },
          { family: 'GONE', hash: 'x', state: 'matched' as const },
        ],
        shipped,
      ),
    ).toEqual([
      { family: 'SINGBOX', hash: 'new', state: 'drifted' },
      { family: 'MIHOMO', hash: 'm', state: 'refused' },
      { family: 'GONE', hash: 'x', state: 'matched' },
    ]);
  });
});
