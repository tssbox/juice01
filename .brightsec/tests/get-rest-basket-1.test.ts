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

test('GET /rest/basket/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'test/api/basketApiSpec.ts',
        'test/api/basketItemApiSpec.ts',
        'test/cypress/e2e/basket.spec.ts',
        'test/api/securityQuestionApiSpec.ts',
        'test/server/insecuritySpec.ts'
      ],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/rest/basket/1`,
      headers: { 'X-Recruiting': 'We are hiring! Visit our careers page for more information.' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});