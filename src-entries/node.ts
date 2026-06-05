import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import cron from 'node-cron';
import { createApp } from '../src/server/app';
import { buildNodeAdapter, flushPendingTasks } from '../src/server/platform/node';
import { runCronTask } from '../src/server/jobs/dispatcher';

const sqlitePath = process.env.SQLITE_PATH ?? './data/freesocks.sqlite';
const port = parseInt(process.env.PORT ?? '3000', 10);

const platform = buildNodeAdapter({ sqlitePath, env: process.env });
const app = createApp(platform);

// Static SPA
app.use('*', serveStatic({ root: path.resolve(process.cwd(), 'dist/client') }));

// SPA fallback: serve the built index.html (read once, then cached) for non-API
// client routes, so deep links / refreshes boot the app instead of returning a
// blank page. (Previously this returned an empty body, breaking the Node deploy.)
let cachedIndexHtml: string | null = null;
async function readIndexHtml(): Promise<string | null> {
  if (cachedIndexHtml !== null) return cachedIndexHtml;
  try {
    cachedIndexHtml = await readFile(
      path.resolve(process.cwd(), 'dist/client/index.html'),
      'utf-8',
    );
  } catch {
    return null;
  }
  return cachedIndexHtml;
}
app.notFound(async (c) => {
  if (!c.req.path.startsWith('/api/')) {
    const html = await readIndexHtml();
    if (html) return c.html(html);
    return c.text('SPA build missing — run `bun run build:prod` to populate dist/client.', 500);
  }
  return c.json({ error: { code: 'not_found', message: 'Not found' } }, 404);
});

const server = serve({ fetch: app.fetch, port });
platform.logger.info('node_server_started', { port });

// In-process overlap guard so a long-running task doesn't double-fire on the
// self-host scheduler. (Cross-instance locking for the Workers/KV path is
// handled separately.)
type CronTaskName = Parameters<typeof runCronTask>[0];
const runningTasks = new Set<CronTaskName>();
const runGuarded = async (task: CronTaskName) => {
  if (runningTasks.has(task)) {
    platform.logger.warn('cron_skip_overlap', { task });
    return;
  }
  runningTasks.add(task);
  try {
    await runCronTask(task, platform);
  } finally {
    runningTasks.delete(task);
  }
};
cron.schedule('*/5 * * * *', () => runGuarded('propagate-tier-changes'));
cron.schedule('*/10 * * * *', () => runGuarded('grace-sweep'));
cron.schedule('0 3 * * *', () => runGuarded('cleanup-expired-free'));

const shutdown = async () => {
  platform.logger.info('node_server_shutting_down');
  await flushPendingTasks();
  server.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
