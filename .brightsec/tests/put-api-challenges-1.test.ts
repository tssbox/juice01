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
      tests: ['sqli', 'csrf', 'bopla', 'xss', 'osi', 'stored_xss', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Challenges/1`,
      body: {
        name: 'SQL Injection Challenge',
        category: 'Injection',
        description: 'Identify and exploit SQL injection vulnerabilities.',
        difficulty: 3,
        hint: 'Look for input fields that interact with the database.',
        hintUrl: 'http://example.com/hint',
        mitigationUrl: 'http://example.com/mitigation',
        key: 'sql-injection',
        disabledEnv: null,
        tutorialOrder: 1,
        tags: 'security,sql',
        solved: false,
        codingChallengeStatus: 0
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
