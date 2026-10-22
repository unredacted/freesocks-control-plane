'use node';
/**
 * Test helper: an in-memory AWS account (CloudFront + ACM in us-east-1) behind
 * the CloudFront adapter's API seam, and an in-memory DNS zone behind its DNS
 * seam. Not a test file itself.
 *
 * It keeps the rules the adapter depends on, as CloudFront and ACM document
 * them, so a test fails when the adapter breaks one:
 *  - a create repeating a `CallerReference` is `DistributionAlreadyExists`, an
 *    alias another distribution serves is `CNAMEAlreadyExists`, a viewer
 *    certificate that is not issued is `InvalidViewerCertificate`;
 *  - an update or delete must name the current `ETag` (`PreconditionFailed`),
 *    and only a disabled, deployed distribution can be deleted
 *    (`DistributionNotDisabled`); a change is `InProgress` for a few reads;
 *  - a policy takes 100 distributions, an account 20 custom policies;
 *  - ACM answers the same certificate to a repeated idempotency token, names
 *    the same validation record for every certificate of one name in the
 *    account, issues a pending certificate once that record is in the zone,
 *    and refuses to delete a certificate a distribution uses.
 * Errors are built by the wrapper's own reducer (`toCloudFrontError`), so the
 * adapter sees exactly what the SDK path would give it.
 */
import type { DistributionConfig, OriginRequestPolicyConfig } from '@aws-sdk/client-cloudfront';
import {
  toCloudFrontError,
  type AcmCertificate,
  type AcmCertificateSummary,
  type CloudFrontApi,
  type CloudFrontDistribution,
  type CloudFrontOriginRequestPolicy,
} from '../providers/cloudfront/sdk';
import type { DnsClient, DnsCreateArgs, DnsRecord, DnsRecordType } from '../providers/dns/types';
import type { CloudflareDnsConfig } from '../providers/types';

export const FAKE_AWS_ACCOUNT = '123456789012';
const DAY = 24 * 60 * 60_000;

function hex8(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

function awsError(step: string, name: string, status: number): Error {
  return toCloudFrontError(step, {
    name,
    message: `${name} (fake answer)`,
    $metadata: { httpStatusCode: status },
  });
}

function timeout(step: string): Error {
  return toCloudFrontError(step, { name: 'TimeoutError', message: 'socket timed out' });
}

export interface FakeCertificate {
  arn: string;
  domainName: string;
  status: string;
  type: string;
  managedBy?: string;
  notAfter?: string;
  failureReason?: string;
  renewalStatus?: string;
  record: { name: string; value: string };
  /** Names beside the domain name (ACM lists the domain name among them too). */
  extraNames?: string[];
  /** Resources outside FCP's distributions that use it (ARNs). */
  otherUsers?: string[];
}

export interface FakeDistribution {
  id: string;
  arn: string;
  domainName: string;
  config: DistributionConfig;
  status: 'InProgress' | 'Deployed';
  etag: string;
  /** Reads since the last change (it deploys after `deployAfterReads`). */
  reads: number;
}

/** A failure for the next call of one operation: an AWS refusal, or `lost` (done, answer lost). */
export type FakeFailure = { name: string; status: number } | 'lost';

export class FakeCloudFrontAccount {
  certificates: FakeCertificate[] = [];
  distributions: FakeDistribution[] = [];
  policies: Array<{ id: string; config: OriginRequestPolicyConfig }> = [];
  /** Every call the adapter made, in order (the operation names of the API seam). */
  calls: string[] = [];
  /** Reads of an `InProgress` distribution before it reports `Deployed`. */
  deployAfterReads = 2;
  /** The zone ACM validates against (a pending certificate issues once its record is there). */
  dns?: FakeDnsZone;
  /** One failure per operation, consumed by its next call. */
  failures = new Map<string, FakeFailure>();
  private seq = 0;
  private readonly tokens = new Map<string, string>();

  /** The validation CNAME ACM names for `domain` in this account (the same for every certificate). */
  validationRecordFor(domain: string): { name: string; value: string } {
    const base = domain.replace(/^\*\./, '');
    const h = hex8(`${FAKE_AWS_ACCOUNT}|${base}`);
    return { name: `_${h}.${base}.`, value: `_${hex8(h)}.abcdefghij.acm-validations.aws.` };
  }

  /** A certificate as the operator (or another tool) left it in the account. */
  addCertificate(c: Partial<FakeCertificate> & { domainName: string }): FakeCertificate {
    const cert: FakeCertificate = {
      arn: `arn:aws:acm:us-east-1:${FAKE_AWS_ACCOUNT}:certificate/fake-${++this.seq}`,
      status: 'ISSUED',
      type: 'AMAZON_ISSUED',
      notAfter: new Date(Date.now() + 395 * DAY).toISOString(),
      record: this.validationRecordFor(c.domainName),
      ...c,
    };
    this.certificates.push(cert);
    return cert;
  }

  certificate(arn: string): FakeCertificate | undefined {
    return this.certificates.find((c) => c.arn === arn);
  }

  distribution(id: string): FakeDistribution | undefined {
    return this.distributions.find((d) => d.id === id);
  }

  /** Distributions using a policy (CloudFront's own count). */
  usersOfPolicy(id: string): number {
    return this.distributions.filter(
      (d) => d.config.DefaultCacheBehavior?.OriginRequestPolicyId === id,
    ).length;
  }

  private fail(op: string): FakeFailure | undefined {
    const f = this.failures.get(op);
    if (f) this.failures.delete(op);
    return f;
  }

  /** The step name errors report: the wrapper's diagnostic one when the caller asked for it. */
  private diagnostic: string | undefined;

  /** Run `op`, applying a queued failure: a refusal before it, a lost answer after it. */
  private async run<T>(op: string, fn: () => T): Promise<T> {
    this.calls.push(op);
    const step = this.diagnostic ?? op;
    const f = this.fail(op);
    if (f && f !== 'lost') throw awsError(step, f.name, f.status);
    const out = fn();
    if (f === 'lost') throw timeout(step);
    return out;
  }

  private summaryOf(c: FakeCertificate): AcmCertificateSummary {
    return {
      arn: c.arn,
      domainName: c.domainName,
      status: c.status,
      type: c.type,
      ...(c.managedBy ? { managedBy: c.managedBy } : {}),
      inUse: this.inUse(c.arn),
      ...(c.notAfter ? { notAfter: c.notAfter } : {}),
    };
  }

  private users(arn: string): string[] {
    return [
      ...this.distributions
        .filter((d) => d.config.ViewerCertificate?.ACMCertificateArn === arn)
        .map((d) => d.arn),
      ...(this.certificate(arn)?.otherUsers ?? []),
    ];
  }

  private inUse(arn: string): boolean {
    return this.users(arn).length > 0;
  }

  private view(d: FakeDistribution, withEtag: boolean): CloudFrontDistribution {
    const c = d.config;
    const o = c.Origins?.Items?.[0];
    return {
      id: d.id,
      arn: d.arn,
      status: d.status,
      domainName: d.domainName,
      enabled: c.Enabled === true,
      ...(c.Comment ? { comment: c.Comment } : {}),
      aliases: [...(c.Aliases?.Items ?? [])],
      origins: o
        ? [
            {
              id: o.Id ?? '',
              domainName: o.DomainName ?? '',
              httpPort: o.CustomOriginConfig?.HTTPPort,
              httpsPort: o.CustomOriginConfig?.HTTPSPort,
              protocolPolicy: o.CustomOriginConfig?.OriginProtocolPolicy,
            },
          ]
        : [],
      ...(c.DefaultCacheBehavior?.OriginRequestPolicyId
        ? { originRequestPolicyId: c.DefaultCacheBehavior.OriginRequestPolicyId }
        : {}),
      ...(c.DefaultCacheBehavior?.CachePolicyId
        ? { cachePolicyId: c.DefaultCacheBehavior.CachePolicyId }
        : {}),
      ...(c.ViewerCertificate?.ACMCertificateArn
        ? { certificateArn: c.ViewerCertificate.ACMCertificateArn }
        : {}),
      ...(withEtag ? { etag: d.etag } : {}),
    };
  }

  private policyView(p: {
    id: string;
    config: OriginRequestPolicyConfig;
  }): CloudFrontOriginRequestPolicy {
    return {
      id: p.id,
      name: p.config.Name ?? '',
      ...(p.config.Comment ? { comment: p.config.Comment } : {}),
      ...(p.config.HeadersConfig?.HeaderBehavior
        ? { headerBehavior: p.config.HeadersConfig.HeaderBehavior }
        : {}),
      headers: [...(p.config.HeadersConfig?.Headers?.Items ?? [])],
      ...(p.config.CookiesConfig?.CookieBehavior
        ? { cookieBehavior: p.config.CookiesConfig.CookieBehavior }
        : {}),
      ...(p.config.QueryStringsConfig?.QueryStringBehavior
        ? { queryStringBehavior: p.config.QueryStringsConfig.QueryStringBehavior }
        : {}),
    };
  }

  /** A read of a distribution: an `InProgress` one deploys after a few reads. */
  private read(d: FakeDistribution): void {
    if (d.status !== 'InProgress') return;
    d.reads++;
    if (d.reads >= this.deployAfterReads) d.status = 'Deployed';
  }

  /** ACM issues a pending certificate once its validation record is in the zone. */
  private settle(c: FakeCertificate): void {
    if (c.status !== 'PENDING_VALIDATION' || !this.dns) return;
    const name = c.record.name.replace(/\.$/, '');
    const value = c.record.value.replace(/\.$/, '');
    if (this.dns.rows.some((r) => r.name === name && r.content.replace(/\.$/, '') === value)) {
      c.status = 'ISSUED';
      c.notAfter = new Date(Date.now() + 395 * DAY).toISOString();
    }
  }

  /** The API one adapter call sees (`diagnostic`: `cloudFrontApiFor`'s step name for every error). */
  api(diagnostic?: string): CloudFrontApi {
    this.diagnostic = diagnostic;
    return {
      requestCertificate: (o) =>
        this.run('requestCertificate', () => {
          const known = this.tokens.get(o.idempotencyToken);
          if (known) return known;
          const cert = this.addCertificate({
            domainName: o.domainName,
            status: 'PENDING_VALIDATION',
            notAfter: undefined,
          });
          this.tokens.set(o.idempotencyToken, cert.arn);
          return cert.arn;
        }),
      describeCertificate: (arn) =>
        this.run('describeCertificate', (): AcmCertificate => {
          const c = this.certificate(arn);
          if (!c) throw awsError('describeCertificate', 'ResourceNotFoundException', 400);
          this.settle(c);
          return {
            ...this.summaryOf(c),
            ...(c.failureReason ? { failureReason: c.failureReason } : {}),
            ...(c.renewalStatus ? { renewalStatus: c.renewalStatus } : {}),
            subjectAlternativeNames: [c.domainName, ...(c.extraNames ?? [])],
            inUseBy: this.users(arn),
            validationRecords: [{ ...c.record, type: 'CNAME' }],
          };
        }),
      listCertificates: () =>
        this.run('listCertificates', () => ({
          items: this.certificates.map((c) => this.summaryOf(c)),
          truncated: false,
        })),
      deleteCertificate: (arn) =>
        this.run('deleteCertificate', () => {
          const i = this.certificates.findIndex((c) => c.arn === arn);
          if (i < 0) throw awsError('deleteCertificate', 'ResourceNotFoundException', 400);
          if (this.inUse(arn)) throw awsError('deleteCertificate', 'ResourceInUseException', 400);
          this.certificates.splice(i, 1);
        }),
      createDistribution: (config) =>
        this.run('createDistribution', () => {
          if (this.distributions.some((d) => d.config.CallerReference === config.CallerReference))
            throw awsError('createDistribution', 'DistributionAlreadyExists', 409);
          for (const alias of config.Aliases?.Items ?? [])
            if (this.distributions.some((d) => d.config.Aliases?.Items?.includes(alias)))
              throw awsError('createDistribution', 'CNAMEAlreadyExists', 409);
          const arn = config.ViewerCertificate?.ACMCertificateArn ?? '';
          if (this.certificate(arn)?.status !== 'ISSUED')
            throw awsError('createDistribution', 'InvalidViewerCertificate', 400);
          const policyId = config.DefaultCacheBehavior?.OriginRequestPolicyId ?? '';
          if (!this.policies.some((p) => p.id === policyId))
            throw awsError('createDistribution', 'NoSuchOriginRequestPolicy', 404);
          if (this.usersOfPolicy(policyId) >= 100)
            throw awsError(
              'createDistribution',
              'TooManyDistributionsAssociatedToOriginRequestPolicy',
              400,
            );
          const id = `EFAKE${++this.seq}`;
          const d: FakeDistribution = {
            id,
            arn: `arn:aws:cloudfront::${FAKE_AWS_ACCOUNT}:distribution/${id}`,
            domainName: `d${hex8(id)}.cloudfront.net`,
            config: structuredClone(config),
            status: 'InProgress',
            etag: `${id}-v1`,
            reads: 0,
          };
          this.distributions.push(d);
          return this.view(d, true);
        }),
      getDistribution: (id) =>
        this.run('getDistribution', () => {
          const d = this.distribution(id);
          if (!d) throw awsError('getDistribution', 'NoSuchDistribution', 404);
          this.read(d);
          return this.view(d, true);
        }),
      getDistributionConfig: (id) =>
        this.run('getDistributionConfig', () => {
          const d = this.distribution(id);
          if (!d) throw awsError('getDistributionConfig', 'NoSuchDistribution', 404);
          return { config: structuredClone(d.config), etag: d.etag };
        }),
      updateDistribution: (id, config, ifMatch) =>
        this.run('updateDistribution', () => {
          const d = this.distribution(id);
          if (!d) throw awsError('updateDistribution', 'NoSuchDistribution', 404);
          if (ifMatch !== d.etag) throw awsError('updateDistribution', 'PreconditionFailed', 412);
          d.config = structuredClone(config);
          d.status = 'InProgress';
          d.reads = 0;
          d.etag = `${d.id}-v${Number(d.etag.split('-v')[1]) + 1}`;
          return this.view(d, true);
        }),
      deleteDistribution: (id, ifMatch) =>
        this.run('deleteDistribution', () => {
          const i = this.distributions.findIndex((d) => d.id === id);
          if (i < 0) throw awsError('deleteDistribution', 'NoSuchDistribution', 404);
          const d = this.distributions[i]!;
          if (ifMatch !== d.etag) throw awsError('deleteDistribution', 'PreconditionFailed', 412);
          if (d.config.Enabled !== false || d.status !== 'Deployed')
            throw awsError('deleteDistribution', 'DistributionNotDisabled', 409);
          this.distributions.splice(i, 1);
        }),
      listDistributions: () =>
        this.run('listDistributions', () => ({
          items: this.distributions.map((d) => this.view(d, false)),
          truncated: false,
        })),
      listOriginRequestPolicies: () =>
        this.run('listOriginRequestPolicies', () => this.policies.map((p) => this.policyView(p))),
      createOriginRequestPolicy: (config) =>
        this.run('createOriginRequestPolicy', () => {
          if (this.policies.some((p) => p.config.Name === config.Name))
            throw awsError('createOriginRequestPolicy', 'OriginRequestPolicyAlreadyExists', 409);
          if (this.policies.length >= 20)
            throw awsError('createOriginRequestPolicy', 'TooManyOriginRequestPolicies', 400);
          const p = { id: `orp-${++this.seq}`, config: structuredClone(config) };
          this.policies.push(p);
          return this.policyView(p);
        }),
      countDistributionsOfPolicy: (id) =>
        this.run('countDistributionsOfPolicy', () => this.usersOfPolicy(id)),
    };
  }
}

/** An in-memory DNS zone behind the adapter's DNS seam (the Cloudflare client's interface). */
export interface FakeDnsZone extends DnsClient {
  rows: DnsRecord[];
  deleted: string[];
  /** The zone's `cname_flattening` as `flattensAllCnames` answers it (null: unreadable). */
  flattenAll: boolean | null;
  /** Fail the next `deleteRecord` (a DNS API that does not answer). */
  failNextDelete: boolean;
}

export function fakeDnsZone(dns: CloudflareDnsConfig, seed: DnsRecord[] = []): FakeDnsZone {
  const rows = [...seed];
  const deleted: string[] = [];
  let next = seed.length + 1;
  const norm = (n: string) => n.trim().toLowerCase().replace(/\.$/, '');
  const zone: FakeDnsZone = {
    rows,
    deleted,
    flattenAll: false,
    failNextDelete: false,
    zoneId: dns.zoneId,
    zoneName: dns.zoneName,
    accountId: dns.accountId,
    async createRecord(args: DnsCreateArgs) {
      if (rows.some((r) => r.name === norm(args.name) && r.type === 'CNAME'))
        throw new Error('fake dns: a CNAME already exists at that name');
      const rec: DnsRecord = { id: `rec${next++}`, ...args, name: norm(args.name) };
      rows.push(rec);
      return rec;
    },
    async findRecordsByName(name: string, type?: DnsRecordType) {
      return rows.filter((r) => r.name === norm(name) && (!type || r.type === type));
    },
    async getRecord(id: string) {
      return rows.find((r) => r.id === id) ?? null;
    },
    async deleteRecord(id: string) {
      if (zone.failNextDelete) {
        zone.failNextDelete = false;
        throw new Error('fake dns: the API did not answer');
      }
      deleted.push(id);
      const i = rows.findIndex((r) => r.id === id);
      if (i >= 0) rows.splice(i, 1);
    },
    async listCaa() {
      return [];
    },
    async flattensAllCnames() {
      return zone.flattenAll;
    },
    async readZone() {
      return { id: dns.zoneId, name: dns.zoneName, status: 'active', paused: false, plan: 'free' };
    },
  };
  return zone;
}
