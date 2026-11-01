/**
 * Records one passed application test in tests/compat/application-evidence.json
 * (docs/client-device-checklists.md). It asks the tester to confirm each check
 * and writes nothing unless every one passed: the file holds passes only, and a
 * failure is a bug to report, never a record.
 *
 *   bun --no-env-file scripts/compat/evidence.ts --client Hiddify \
 *     --app-version 4.1.2 --os "Android 15" --backend-version 2.4.3 \
 *     --commit <40-char FCP commit beta ran> --tested-by <name> \
 *     --evidence <private link to the screenshots>
 */
import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { clients } from '../../tests/compat/manifest';
import {
  EVIDENCE_FILE,
  evidenceRecord,
  evidenceSchema,
  type EvidenceRecord,
} from '../../tests/compat/evidence';

const { values } = parseArgs({
  options: {
    client: { type: 'string' },
    'app-version': { type: 'string' },
    os: { type: 'string' },
    'backend-version': { type: 'string' },
    commit: { type: 'string' },
    'tested-by': { type: 'string' },
    evidence: { type: 'string' },
    'tested-at': { type: 'string' },
  },
});
const client = clients.find((c) => c.name === values.client);
if (!client)
  throw new Error(
    `--client must be one of: ${clients.map((c) => JSON.stringify(c.name)).join(', ')}`,
  );

const checks = [
  [
    'import',
    'Import: the profile holds every server of the subscription (the same names as in the other apps)',
  ],
  ['connection', 'Connection: the app connected through one of them'],
  ['dns', 'DNS: names resolved while connected, and no resolver of your own network showed'],
  ['https', 'HTTPS: an HTTPS page loaded, from an address that is not your own'],
  ...(client.format === 'outline'
    ? []
    : [
        [
          'refresh',
          'Refresh: an update in the app succeeded and the server list is unchanged',
        ] as const,
      ]),
] as const;
for (const [, question] of checks) {
  const answer = prompt(`${question}? [y/N]`);
  if (!/^y(es)?$/i.test(answer?.trim() ?? '')) {
    console.error('Not recorded: only a run where every check passed is evidence.');
    process.exit(1);
  }
}

const record: EvidenceRecord = evidenceRecord.parse({
  client: client.name,
  appVersion: values['app-version'],
  os: values.os,
  backendVersion: values['backend-version'],
  fcpCommit: values.commit,
  testedAt: values['tested-at'] ?? new Date().toISOString(),
  testedBy: values['tested-by'],
  evidence: values.evidence,
  import: 'passed',
  connection: 'passed',
  dns: 'passed',
  https: 'passed',
  refresh: client.format === 'outline' ? 'not-applicable' : 'passed',
});
const records = evidenceSchema.parse(JSON.parse(await readFile(EVIDENCE_FILE, 'utf8')));
records.push(record);
await writeFile(EVIDENCE_FILE, JSON.stringify(records, null, 2) + '\n');
console.log(
  `Recorded ${record.client} ${record.appVersion} on ${record.os} for ${record.fcpCommit}.`,
);
