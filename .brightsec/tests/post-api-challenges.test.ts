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

test('POST /api/challenges', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'xss', 'csrf', 'bopla', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges`,
      body: {
        name: 'Sample Challenge',
        category: 'Security',
        description: 'This is a sample challenge description.',
        difficulty: 3,
        hint: 'Try harder!',
        hintUrl: 'http://example.com/hint',
        mitigationUrl: 'http://example.com/mitigation',
        key: 'sample-key',
        disabledEnv: 'production',
        tutorialOrder: 1,
        tags: 'sample,challenge',
        solved: false,
        codingChallengeStatus: 0
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
