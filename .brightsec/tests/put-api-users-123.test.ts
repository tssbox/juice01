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

test('PUT /api/users/123', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'xss', 'sqli', 'file_upload', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Users/123`,
      body: {
        username: 'new_username',
        email: 'new_email@example.com',
        password: 'new_password',
        role: 'customer',
        deluxeToken: '',
        lastLoginIp: '192.168.1.1',
        profileImage: '/assets/public/images/uploads/default.svg',
        totpSecret: '',
        isActive: true
      },
      headers: { 'Content-Type': 'application/json', 'X-Recruiting': '<recruiting@example.com>' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
