// Cap v4 removed DISABLE_ERROR_LOGGING. Install the privacy boundary BEFORE
// importing any upstream code: exceptions can contain request data. Keep fixed
// severity notices, never arbitrary arguments, URLs, stack traces or IPs.
const notice = (level) => process.stderr.write(`[cap] ${level}: details suppressed for privacy\n`);
for (const level of ['log', 'info', 'debug', 'warn', 'error']) {
  console[level] = () => notice(level);
}
for (const event of ['uncaughtException', 'unhandledRejection']) {
  process.on(event, () => {
    notice('fatal');
    process.exit(1);
  });
}
try {
  await import('../src/index.js');
} catch {
  notice('startup failed');
  process.exit(1);
}
