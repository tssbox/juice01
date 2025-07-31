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

test('PATCH /rest/products/:id/reviews', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'nosql', 'stored_xss', 'csrf', 'jwt'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PATCH,
      url: `${baseUrl}/rest/products/507f1f77bcf86cd799439011/reviews`,
      body: {
        id: '507f1f77bcf86cd799439011',
        message: 'This is an updated review message.'
      },
      headers: { 'Authorization': 'Bearer <token>', 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
