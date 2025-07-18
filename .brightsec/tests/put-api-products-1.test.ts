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

test('PUT /api/products/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'stored_xss', 'sqli', 'csrf', 'http_method_fuzzing'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Products/1`,
      headers: { 'Authorization': 'Bearer <token>' },
      body: {
        description: '<a href="http://kimminich.de" target="_blank">More...</a>'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
