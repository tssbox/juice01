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

test('POST /api/challenges/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'stored_xss', 'sqli', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges/1`,
      body: {
        name: 'Sample Challenge',
        description: 'This is a sample challenge description.',
        difficulty: 2,
        solved: false
      },
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.BRIGHT_AUTH_ID}`
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
