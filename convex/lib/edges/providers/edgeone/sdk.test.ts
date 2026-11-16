// @vitest-environment node
/**
 * The EdgeOne SDK wrapper's error reduction: Tencent's codes become a status
 * and a short code FCP acts on, the refusal's words keep Tencent's code and
 * the CAM action (redacted, off the error), and nothing a message echoed (a
 * name, a secret) reaches the error itself.
 */
import { describe, expect, test } from 'vitest';
import { EDGEONE_ERROR_CODES, reduceEdgeOneCode, toEdgeOneError } from './sdk';
import { refusalOf } from '../http';

describe('edgeone error reduction', () => {
  test.each([
    ['AuthFailure.SecretIdNotFound', 401, 'token_rejected'],
    ['AuthFailure.SignatureFailure', 401, 'token_rejected'],
    ['AuthFailure.TokenFailure', 401, 'token_rejected'],
    ['AuthFailure.UnauthorizedOperation', 403, 'permission_missing'],
    ['UnauthorizedOperation.CamUnauthorized', 403, 'permission_missing'],
    ['UnauthorizedOperation.NoPermission', 403, 'permission_missing'],
    ['LimitExceeded', 400, 'plan_limit'],
    ['LimitExceeded.PackNotAllow', 400, 'plan_limit'],
    ['LimitExceeded.RuleLimitExceeded', 400, 'plan_limit'],
    ['OperationDenied.UnsupportedPlan', 400, 'plan_limit'],
    ['OperationDenied.PlanHasBeenExpired', 400, 'plan_limit'],
    ['InvalidParameter.ZoneHasNotBeenBoundToPlan', 400, 'plan_limit'],
    ['ResourcesSoldOut.L7LackOfResources', 400, 'plan_limit'],
    ['RequestLimitExceeded', 429, 'rate_limited'],
    ['LimitExceeded.RateLimitExceeded', 429, 'rate_limited'],
    ['OperationDenied.ResourceLockedTemporary', 409, 'provider_busy'],
    ['InvalidParameter.ZoneIsGrayPublishing', 409, 'provider_busy'],
    ['InvalidParameter.HostStatusNotAllowApplyCertificate', 409, 'tls_waiting_for_dns'],
    ['OperationDenied.DomainNoICP', 400, 'icp_filing_required'],
    ['ResourceUnavailable.DomainAlreadyExists', 400, 'domain_taken_elsewhere'],
    ['ResourceInUse.DnsRecord', 400, 'dns_record_exists'],
    ['ResourceUnavailable.DomainNotFound', 404, 'not_found'],
    ['ResourceUnavailable.ZoneNotFound', 404, 'not_found'],
    ['InvalidParameter.ZoneNotFound', 404, 'not_found'],
    ['InternalError', 500, 'provider_error'],
    ['FailedOperation', 500, 'provider_error'],
    ['InvalidParameter.InvalidServerName', 400, 'refused'],
    ['OperationDenied', 400, 'refused'],
  ])('%s -> %i %s', (code, status, short) => {
    expect(reduceEdgeOneCode(code)).toEqual({ status, code: short });
    expect(EDGEONE_ERROR_CODES).toContain(short);
  });

  test('the error says status and code only; the words go aside with the action', () => {
    const secret = 'SECRET_TENCENT_KEY_0123456789';
    const e = toEdgeOneError(
      'domain-create',
      'CreateAccelerationDomain',
      {
        code: 'LimitExceeded.PackNotAllow',
        message: `plan does not allow k3m7q9zbx2wd.example.org (key ${secret})`,
        requestId: 'req-1',
      },
      [secret],
    );
    expect(e.message).toBe('edgeone 400 on domain-create (plan_limit)');
    expect(e.meta).toMatchObject({
      provider: 'edgeone',
      status: 400,
      code: 'plan_limit',
      retryable: false,
    });
    expect(JSON.stringify(e)).not.toContain('example.org');
    expect(JSON.stringify(e)).not.toContain(secret);
    const said = refusalOf(e)!;
    expect(said).toContain('LimitExceeded.PackNotAllow on teo:CreateAccelerationDomain');
    expect(said).not.toContain(secret);
  });

  test('a diagnostic step (the credential test) keeps the words as its detail', () => {
    const e = toEdgeOneError('test', 'DescribeZones', {
      code: 'UnauthorizedOperation.CamUnauthorized',
      message: 'not authorized',
    });
    expect(e.meta.detail).toContain('teo:DescribeZones');
  });

  test('no Tencent code: a dropped connection or a timeout, retryable; a gateway status kept', () => {
    expect(
      toEdgeOneError('domain-list', 'DescribeAccelerationDomains', {
        message: 'network timeout at: x',
      }).meta,
    ).toMatchObject({
      timedOut: true,
      retryable: true,
    });
    expect(
      toEdgeOneError('domain-list', 'DescribeAccelerationDomains', {
        httpCode: 502,
        message: 'bad gateway',
      }).meta,
    ).toMatchObject({ status: 502, retryable: true });
    expect(
      toEdgeOneError('domain-list', 'DescribeAccelerationDomains', { message: 'socket hang up' })
        .meta.code,
    ).toBeUndefined();
  });

  test('a code that is not a bare identifier is not trusted as one', () => {
    const e = toEdgeOneError('x', 'DescribeZones', { code: 'evil code <script>', message: 'm' });
    expect(e.meta.code).toBeUndefined();
  });
});
