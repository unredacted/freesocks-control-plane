/** Optional release gate: unverified applications must never count as passes. */
import { readFile } from 'node:fs/promises';
import { clients } from '../../tests/compat/manifest';
import { EVIDENCE_FILE, EVIDENCE_MAX_AGE_MS, evidenceSchema } from '../../tests/compat/evidence';
const records = evidenceSchema.parse(JSON.parse(await readFile(EVIDENCE_FILE, 'utf8')));
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
      Date.now() - Date.parse(record.testedAt) < EVIDENCE_MAX_AGE_MS &&
      (record.refresh === 'passed' || client.format === 'outline'),
  );
  console.log(
    `${client.name}: ${valid ? 'verified for recorded version and OS' : 'MISSING current application evidence'}`,
  );
  missing ||= !valid;
}
process.exitCode = missing ? 1 : 0;
