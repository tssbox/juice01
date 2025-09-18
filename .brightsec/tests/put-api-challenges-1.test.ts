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

test('PUT /api/challenges/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'xss', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Challenges/1`,
      body: {
        name: "Example Challenge",
        category: "Security",
        description: "This is a sample challenge description.",
        difficulty: 3,
        hint: "Try looking at the logs.",
        hintUrl: "http://example.com/hint",
        mitigationUrl: "http://example.com/mitigation",
        key: "restfulXssChallenge",
        disabledEnv: "production",
        tutorialOrder: 1,
        tags: "xss,security",
        solved: false,
        codingChallengeStatus: 0,
        hasCodingChallenge: true
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});