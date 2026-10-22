// @vitest-environment node
/**
 * The CloudFront SDK wrapper's pure half: what an SDK error becomes (a status
 * and the exception's name, never its words on the error itself), and how the
 * SDK's records are read. The wire format is pinned by wireContract.test.ts.
 */
import { describe, expect, test } from 'vitest';
import {
  awsErrorCode,
  certificateOf,
  distributionOf,
  isCloudFrontNotFound,
  toCloudFrontError,
} from './sdk';
import { refusalOf } from '../http';

const SECRET = 'SECRET-aws-0123456789abcdefghij';

describe('cloudfront sdk: errors', () => {
  test('an exception name becomes a snake_case code; anything else none', () => {
    expect(awsErrorCode('NoSuchDistribution')).toBe('no_such_distribution');
    expect(awsErrorCode('CNAMEAlreadyExists')).toBe('cname_already_exists');
    expect(awsErrorCode('TooManyDistributionsAssociatedToOriginRequestPolicy')).toBe(
      'too_many_distributions_associated_to_origin_request_policy',
    );
    expect(awsErrorCode('ResourceNotFoundException')).toBe('resource_not_found_exception');
    expect(awsErrorCode('Error')).toBeUndefined();
    expect(awsErrorCode('Not an identifier')).toBeUndefined();
    expect(awsErrorCode(42)).toBeUndefined();
  });

  test("a refusal keeps the provider's words aside, redacted, and off the error", () => {
    const e = toCloudFrontError(
      'distribution-create',
      {
        name: 'InvalidArgument',
        message: `The parameter origin 198.51.100.7 is invalid ${SECRET}`,
        $metadata: { httpStatusCode: 400 },
      },
      [SECRET],
    );
    expect(e.meta).toMatchObject({
      provider: 'cloudfront',
      step: 'distribution-create',
      status: 400,
      code: 'invalid_argument',
      retryable: false,
      timedOut: false,
    });
    expect(e.meta.detail).toBeUndefined();
    expect(`${e.message} ${JSON.stringify(e.meta)}`).not.toMatch(/198\.51|SECRET/);
    const said = refusalOf(e)!;
    expect(said).toMatch(/InvalidArgument|parameter origin/);
    expect(said).not.toContain(SECRET);
    expect(said).not.toContain('198.51.100.7');
  });

  test('a diagnostic step (the credential test) keeps the redacted words as its detail', () => {
    const e = toCloudFrontError('test', {
      name: 'AccessDenied',
      message: 'User is not authorized to perform: cloudfront:ListDistributions',
      $metadata: { httpStatusCode: 403 },
    });
    expect(e.meta.code).toBe('access_denied');
    expect(e.meta.detail).toMatch(/not authorized/);
  });

  test('throttling and server faults are retryable; a timeout is an unknown outcome', () => {
    expect(
      toCloudFrontError('x', { name: 'Throttling', $metadata: { httpStatusCode: 429 } }).meta
        .retryable,
    ).toBe(true);
    expect(
      toCloudFrontError('x', { name: 'InternalFailure', $metadata: { httpStatusCode: 500 } }).meta
        .retryable,
    ).toBe(true);
    const t = toCloudFrontError('x', { name: 'TimeoutError', message: 'socket hang up' });
    expect(t.meta).toMatchObject({ timedOut: true, retryable: true });
  });

  test('not found: a CloudFront 404, or ACM 400 ResourceNotFoundException', () => {
    expect(
      isCloudFrontNotFound(
        toCloudFrontError('x', { name: 'NoSuchDistribution', $metadata: { httpStatusCode: 404 } }),
      ),
    ).toBe(true);
    expect(
      isCloudFrontNotFound(
        toCloudFrontError('x', {
          name: 'ResourceNotFoundException',
          $metadata: { httpStatusCode: 400 },
        }),
      ),
    ).toBe(true);
    expect(
      isCloudFrontNotFound(
        toCloudFrontError('x', { name: 'InvalidArgument', $metadata: { httpStatusCode: 400 } }),
      ),
    ).toBe(false);
  });
});

describe('cloudfront sdk: records', () => {
  test("a certificate's validation record is read once, from the request or a renewal", () => {
    const record = {
      Name: '_x.example.org.',
      Type: 'CNAME' as const,
      Value: '_y.acm-validations.aws.',
    };
    const c = certificateOf({
      CertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
      DomainName: '*.example.org',
      Status: 'ISSUED',
      Type: 'AMAZON_ISSUED',
      NotAfter: new Date('2027-11-01T00:00:00Z'),
      InUseBy: ['arn:aws:cloudfront::123456789012:distribution/E1'],
      DomainValidationOptions: [{ DomainName: '*.example.org', ResourceRecord: record }],
      RenewalSummary: {
        RenewalStatus: 'PENDING_AUTO_RENEWAL',
        UpdatedAt: new Date(),
        DomainValidationOptions: [{ DomainName: '*.example.org', ResourceRecord: record }],
      },
    });
    expect(c).toEqual({
      arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
      domainName: '*.example.org',
      status: 'ISSUED',
      type: 'AMAZON_ISSUED',
      notAfter: '2027-11-01T00:00:00.000Z',
      inUse: true,
      renewalStatus: 'PENDING_AUTO_RENEWAL',
      inUseBy: ['arn:aws:cloudfront::123456789012:distribution/E1'],
      validationRecords: [
        { name: '_x.example.org.', type: 'CNAME', value: '_y.acm-validations.aws.' },
      ],
    });
  });

  test('a distribution reads the same from a full answer and from a listing summary', () => {
    const config = {
      CallerReference: 'fcp-relay-x',
      Comment: 'fcp-relay-x',
      Enabled: true,
      Aliases: { Quantity: 1, Items: ['a.example.org'] },
      Origins: {
        Quantity: 1,
        Items: [
          {
            Id: 'origin',
            DomainName: 'node.example',
            CustomOriginConfig: {
              HTTPPort: 80,
              HTTPSPort: 8443,
              OriginProtocolPolicy: 'https-only' as const,
            },
          },
        ],
      },
      DefaultCacheBehavior: {
        TargetOriginId: 'origin',
        ViewerProtocolPolicy: 'https-only' as const,
        OriginRequestPolicyId: 'orp-1',
        CachePolicyId: 'cp-1',
      },
      ViewerCertificate: { ACMCertificateArn: 'arn:cert' },
    };
    const full = distributionOf(
      {
        Id: 'E1',
        ARN: 'arn:d',
        Status: 'Deployed',
        DomainName: 'd1.cloudfront.net',
        LastModifiedTime: new Date('2026-10-22T00:00:00Z'),
        InProgressInvalidationBatches: 0,
        DistributionConfig: config as never,
      },
      'E1-v1',
    );
    const summary = distributionOf({
      Id: 'E1',
      ARN: 'arn:d',
      Status: 'Deployed',
      DomainName: 'd1.cloudfront.net',
      LastModifiedTime: new Date('2026-10-22T00:00:00Z'),
      ...(config as object),
    } as never);
    expect(full).toEqual({ ...summary, etag: 'E1-v1' });
    expect(summary).toMatchObject({
      id: 'E1',
      enabled: true,
      comment: 'fcp-relay-x',
      aliases: ['a.example.org'],
      origins: [{ domainName: 'node.example', httpsPort: 8443, protocolPolicy: 'https-only' }],
      originRequestPolicyId: 'orp-1',
      certificateArn: 'arn:cert',
    });
  });
});
