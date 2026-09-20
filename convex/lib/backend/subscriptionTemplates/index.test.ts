import { describe, expect, test } from 'vitest';
import {
  SUBSCRIPTION_TEMPLATES,
  TEMPLATE_FAMILIES,
  base64Utf8,
  desiredTemplateBody,
  liveTemplateHash,
  templateDrift,
  templateHash,
} from './index';

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

  test('the live hash equals the desired hash when the bodies match', async () => {
    const stash = SUBSCRIPTION_TEMPLATES.STASH;
    const live = desiredTemplateBody(stash) as { encodedTemplateYaml: string };
    expect(await liveTemplateHash({ templateJson: null, ...live })).toBe(await templateHash(stash));
    const singbox = SUBSCRIPTION_TEMPLATES.SINGBOX;
    expect(await liveTemplateHash({ templateJson: singbox.body, encodedTemplateYaml: null })).toBe(
      await templateHash(singbox),
    );
    expect(await liveTemplateHash({ templateJson: null, encodedTemplateYaml: null })).toBeNull();
  });
});
