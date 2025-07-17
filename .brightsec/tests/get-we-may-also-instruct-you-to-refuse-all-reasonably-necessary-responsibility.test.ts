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

test('GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'unvalidated_redirect', 'improper_asset_management', 'sqli', 'ssrf', 'osi', 'lfi', 'rfi', 'jwt'],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility`,
      headers: { 'X-Recruiting': 'We are hiring!' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
