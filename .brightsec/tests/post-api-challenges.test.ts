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

test('POST /api/challenges', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['stored_xss', 'csrf', 'bopla', 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges`,
      body: {
        name: 'Challenge',
        category: 'Security',
        description: 'Solve the challenge to gain points.',
        difficulty: 3,
        hint: 'Try looking at the logs.',
        hintUrl: null,
        mitigationUrl: null,
        key: 'restfulXssChallenge',
        disabledEnv: null,
        tutorialOrder: null,
        tags: 'xss,security',
        solved: false,
        codingChallengeStatus: 0,
        hasCodingChallenge: false
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
