import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

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

test('POST /repos/tssbox/juice01/contents/server.ts', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'xss', 'csrf', 'sqli', 'ssrf', 'osi', 'secret_tokens', 'open_database'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/repos/tssbox/juice01/contents/server.ts`,
      body: {
        branch: 'bright/1d59109e-d5fe-44ae-9941-a6e7683ea18d',
        owner: 'tssbox',
        repo: 'juice01',
        path: 'server.ts'
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
