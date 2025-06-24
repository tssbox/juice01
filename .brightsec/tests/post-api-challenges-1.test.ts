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
      tests: ['sqli', 'csrf', 'stored_xss', 'bopla', 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Challenges/1`,
      body: {
        id: 1,
        name: 'SQL Injection',
        category: 'Injection',
        description: 'Find and exploit SQL Injection vulnerabilities.',
        difficulty: 3,
        hint: 'Check for SQL syntax errors.',
        hintUrl: 'http://example.com/hint',
        mitigationUrl: 'http://example.com/mitigation',
        key: 'sqli',
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
