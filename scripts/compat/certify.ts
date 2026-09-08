/** Optional release gate: unverified applications must never count as passes. */
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { clients } from '../../tests/compat/manifest';
const evidenceSchema = z.array(
  z.object({
    client: z.string(),
    appVersion: z.string().min(1),
    os: z.string().min(1),
    backendVersion: z.string().min(1),
    fcpCommit: z.string().regex(/^[a-f0-9]{40}$/),
    testedAt: z.iso.datetime(),
    testedBy: z.string().min(1),
    evidence: z.string().url(),
    import: z.literal('passed'),
    connection: z.literal('passed'),
    dns: z.literal('passed'),
    https: z.literal('passed'),
    refresh: z.enum(['passed', 'not-applicable']),
  }),
);
const records = evidenceSchema.parse(
  JSON.parse(await readFile('tests/compat/application-evidence.json', 'utf8')),
);
const commit = process.env.FCP_COMPAT_CERTIFY_COMMIT ?? process.env.GITHUB_SHA;
if (!commit || !/^[a-f0-9]{40}$/.test(commit))
  throw new Error('Set the exact tested FCP commit before certification');
let missing = false;
for (const client of clients) {
  const valid = records.some(
    (record) =>
      record.client === client.name &&
      record.fcpCommit === commit &&
      Date.parse(record.testedAt) <= Date.now() &&
      Date.now() - Date.parse(record.testedAt) < 30 * 86400_000 &&
      (record.refresh === 'passed' || client.format === 'outline'),
  );
  console.log(
    `${client.name}: ${valid ? 'verified for recorded version and OS' : 'MISSING current application evidence'}`,
  );
  missing ||= !valid;
}
process.exitCode = missing ? 1 : 0;
