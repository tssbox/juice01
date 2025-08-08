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
      tests: ['sqli', 'xss', 'csrf', 'bopla', 'stored_xss'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {}
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges`,
      body: {
        id: 1,
        name: "SQL Injection",
        category: "Injection",
        description: "Challenge to test SQL Injection vulnerability.",
        difficulty: 3,
        hint: "Try using SQL keywords.",
        hintUrl: "http://example.com/hint",
        mitigationUrl: "http://example.com/mitigation",
        key: "restfulXssChallenge",
        disabledEnv: null,
        tutorialOrder: 1,
        tags: "security,sql",
        solved: false,
        codingChallengeStatus: 0,
        hasCodingChallenge: true
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
