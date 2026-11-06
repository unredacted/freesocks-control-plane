/** One application-evidence record (tests/compat/application-evidence.json), as the certify gate reads it. */
import { z } from 'zod';

export const EVIDENCE_FILE = 'tests/compat/application-evidence.json';
/** Evidence certifies a release for this long after the test. */
export const EVIDENCE_MAX_AGE_MS = 30 * 86400_000;

export const evidenceRecord = z.object({
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
  /**
   * The Hysteria 2 checks (docs/client-device-checklists.md § "Hysteria"), run
   * on a `privacy-hysteria` key: the app imported FCP's raw config through its
   * own importer, connected over UDP, and refused to connect once one
   * character of the entry's certificate pin was changed. Only a record with
   * this block lets the catalog mark the app `hysteria2: true`
   * (convex/clientCompatibility.test.ts).
   */
  hysteria2: z
    .object({
      rawImport: z.literal('passed'),
      udp: z.literal('passed'),
      wrongPinRefused: z.literal('passed'),
    })
    .optional(),
});
export type EvidenceRecord = z.infer<typeof evidenceRecord>;
export const evidenceSchema = z.array(evidenceRecord);
