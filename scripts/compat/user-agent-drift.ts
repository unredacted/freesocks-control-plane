/**
 * Re-reads, at each open-source app's NEWEST release, the source line its
 * subscription User-Agent comes from (tests/compat/userAgents.ts, `source`
 * evidence), and fails when that line is gone: the app may now send a
 * User-Agent FCP classifies into another family (or `other`). Run by the
 * nightly `latest` discovery job; never on the PR gate (it reads GitHub).
 *
 * A failure means: read the app's new source, update its entry (the
 * User-Agent, tag, commit, line and needle), and let
 * convex/clientUserAgents.test.ts say whether the classifier still agrees.
 */
import { appUserAgents, type UserAgentEvidence } from '../../tests/compat/userAgents';

type Source = Extract<UserAgentEvidence, { kind: 'source' }>;

const headers: Record<string, string> = {
  accept: 'application/vnd.github+json',
  'x-github-api-version': '2022-11-28',
  ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
};

async function github(path: string, accept?: string): Promise<Response> {
  return fetch(`https://api.github.com${path}`, {
    headers: accept ? { ...headers, accept } : headers,
    signal: AbortSignal.timeout(30_000),
  });
}

/** The ref the check reads: the tracked branch, else the newest release tag, else the default branch. */
async function newestRef(e: Source): Promise<string> {
  if (e.track) return e.track.branch;
  const release = await github(`/repos/${e.repo}/releases/latest`);
  if (release.ok) return String((await release.json()).tag_name);
  if (release.status !== 404) throw new Error(`${e.repo}: release lookup HTTP ${release.status}`);
  const repo = await github(`/repos/${e.repo}`);
  if (!repo.ok) throw new Error(`${e.repo}: repository lookup HTTP ${repo.status}`);
  return String((await repo.json()).default_branch);
}

const failures: string[] = [];
let checked = 0;
for (const app of appUserAgents) {
  for (const e of app.evidence) {
    if (e.kind !== 'source') continue;
    checked++;
    const where = `${app.app} (${e.repo} ${e.path})`;
    try {
      const ref = await newestRef(e);
      const file = await github(
        `/repos/${e.repo}/contents/${e.path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(ref)}`,
        'application/vnd.github.raw+json',
      );
      if (file.status === 404) {
        failures.push(`${where}: the file is gone at ${ref}`);
        continue;
      }
      if (!file.ok) throw new Error(`HTTP ${file.status}`);
      const text = await file.text();
      if (!text.includes(e.needle)) {
        failures.push(`${where}: \`${e.needle}\` is no longer in the file at ${ref}`);
        continue;
      }
      const moved = ref !== e.ref && !e.track ? ` (newest release ${ref}, recorded ${e.ref})` : '';
      console.log(`ok   ${where}${moved}`);
    } catch (err) {
      failures.push(`${where}: ${(err as Error).message}`);
    }
  }
}

console.log(`\n${checked} User-Agent source lines checked, ${failures.length} changed.`);
if (failures.length) {
  for (const f of failures) console.error(`FAIL ${f}`);
  console.error(
    "\nRead each app's new source and update tests/compat/userAgents.ts; convex/clientUserAgents.test.ts then says whether FCP still classifies it.",
  );
  process.exit(1);
}
