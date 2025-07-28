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

test('PUT /api/challenges/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'xss', 'sqli', 'osi', 'ssti', 'stored_xss'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Challenges/1`,
      body: {
        name: 'Sample Challenge',
        category: 'Security',
        description: 'A sample challenge description.',
        difficulty: 3,
        hint: 'Try harder!',
        hintUrl: 'http://example.com/hint',
        mitigationUrl: 'http://example.com/mitigation',
        key: 'restfulXssChallenge',
        disabledEnv: null,
        tutorialOrder: 1,
        tags: 'sample,security',
        solved: false,
        codingChallengeStatus: 0,
        hasCodingChallenge: false
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
