import type { Db } from '../db/client';
import { auditLog } from '../db/schema';
import type { Logger } from '../lib/logger';

export interface AuditEntryInput {
  actorType: 'system' | 'admin' | 'member' | 'anonymous' | 'webhook';
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  payload?: unknown;
  requestId?: string;
  ipHash?: string;
}

export class AuditService {
  constructor(
    private readonly db: Db,
    private readonly logger: Logger,
  ) {}

  async record(entry: AuditEntryInput): Promise<void> {
    try {
      await this.db.insert(auditLog).values({
        actorType: entry.actorType,
        actorId: entry.actorId ?? null,
        action: entry.action,
        targetType: entry.targetType ?? null,
        targetId: entry.targetId ?? null,
        payload: entry.payload !== undefined ? JSON.stringify(entry.payload) : null,
        requestId: entry.requestId ?? null,
        ipHash: entry.ipHash ?? null,
      });
    } catch (err) {
      this.logger.error('audit_write_failed', { error: String(err), action: entry.action });
    }
  }
}
