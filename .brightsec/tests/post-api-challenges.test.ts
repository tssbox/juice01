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
      tests: ['csrf', 'sqli', 'stored_xss', 'bopla', 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges`,
      body: {
        id: 1,
        key: 'exampleKey',
        name: 'Sample Challenge',
        category: 'Security',
        tags: 'xss,sql',
        description: 'Solve the challenge to learn about security.',
        difficulty: 3,
        hint: 'Try SQL injection.',
        hintUrl: 'http://example.com/hint',
        mitigationUrl: 'http://example.com/mitigation',
        solved: false,
        disabledEnv: null,
        tutorialOrder: 1,
        codingChallengeStatus: 0
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
