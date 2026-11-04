/**
 * Convex-side derivation of the app notice's kinds of app
 * (src/shared/contracts/appNotice.ts), kept apart from lib/appNotice.ts so the
 * schema imports a validator, not the renderer.
 */
import { v } from 'convex/values';
import { APP_NOTICE_FAMILIES, type AppNoticeFamily } from '../../src/shared/contracts/appNotice';

export { APP_NOTICE_FAMILIES, type AppNoticeFamily };

export const appNoticeFamilyValidator = v.union(...APP_NOTICE_FAMILIES.map((f) => v.literal(f)));
