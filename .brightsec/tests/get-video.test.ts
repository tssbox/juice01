import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /video', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['xss', 'csrf', 'lfi', 'ssrf', 'sqli', 'open_database'],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/video`,
      headers: {
        'Content-Range': 'bytes 0-1023/1024',
        'Accept-Ranges': 'bytes',
        'Content-Length': '1024',
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Type': 'video/mp4'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});