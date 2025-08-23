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
      tests: ['stored_xss', 'csrf', 'bopla', 'business_constraint_bypass', 'html_injection'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        databases: ['SQLite', 'MongoDB']
      }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges`,
      body: {
        key: 'restfulXssChallenge',
        name: 'Cross-Site Scripting',
        category: 'Security',
        description: 'Identify and exploit XSS vulnerabilities.',
        difficulty: 3,
        hint: 'Look for input fields that reflect user input.',
        hintUrl: 'http://example.com/hint',
        mitigationUrl: 'http://example.com/mitigation',
        solved: false,
        disabledEnv: null,
        tutorialOrder: 1,
        codingChallengeStatus: 0,
        hasCodingChallenge: true
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});