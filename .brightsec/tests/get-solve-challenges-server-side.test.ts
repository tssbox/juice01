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

test('GET /solve/challenges/server-side', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'ssrf', 'ssti', 'xss', 'osi'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`,
      headers: { 'X-Recruiting': 'We are hiring!' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
