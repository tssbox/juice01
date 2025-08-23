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

test('POST /rest/2fa/verify', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'secret_tokens', 'xss', 'osi'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        databases: ['SQLite', 'MongoDB']
      },
      skipStaticParams: false
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/2fa/verify`,
      body: {
        tmpToken: 'sampleTmpToken123',
        totpToken: '123456'
      },
      headers: {
        'Content-Type': 'application/json',
        'X-Recruiting': 'We are hiring!'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});