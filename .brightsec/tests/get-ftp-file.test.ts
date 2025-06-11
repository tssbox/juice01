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

test('GET /ftp/:file', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['lfi', 'file_upload', 'full_path_disclosure', 'ssrf'],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/ftp/samplefile`,
      headers: { 'X-Recruiting': 'We are hiring! Check our careers page for more information.' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
