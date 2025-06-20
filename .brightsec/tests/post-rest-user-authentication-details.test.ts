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

test('POST /rest/user/authentication-details', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'xss', 'id_enumeration', 'secret_tokens', 'sqli', 'insecure_tls_configuration', 'osi'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/user/authentication-details`,
      body: {
        status: 'success',
        data: [{
          id: 1,
          username: 'john_doe',
          email: 'john.doe@example.com',
          role: 'customer',
          deluxeToken: '',
          lastLoginIp: '192.168.1.1',
          profileImage: '/assets/public/images/uploads/default.svg',
          totpSecret: '',
          isActive: true,
          password: '********',
          lastLoginTime: 1633036800000
        }]
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
