import { createApp } from '../src/server/app';
import { buildCloudflareAdapter, type WorkersEnv } from '../src/server/platform/cloudflare';
import { runCronTask, scheduledHandlerToTask } from '../src/server/jobs/dispatcher';

export default {
  async fetch(request: Request, env: WorkersEnv, ctx: ExecutionContext): Promise<Response> {
    const platform = buildCloudflareAdapter(env, ctx);
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const app = createApp(platform);
      return app.fetch(request, env, ctx);
    }
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response('Not found', { status: 404 });
  },
  async scheduled(event: ScheduledEvent, env: WorkersEnv, ctx: ExecutionContext): Promise<void> {
    const platform = buildCloudflareAdapter(env, ctx);
    const task = scheduledHandlerToTask(event.cron);
    if (!task) {
      platform.logger.warn('cron_unmapped', { cron: event.cron });
      return;
    }
    await runCronTask(task, platform);
  },
};
