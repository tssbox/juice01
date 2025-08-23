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

test('POST /api/products', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['stored_xss', 'xss', 'bopla', 'sqli', 'proto_pollution'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        databases: ['SQLite', 'MongoDB']
      }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Products`,
      body: {
        name: 'XSS Juice (42ml)',
        description: '<iframe src="javascript:alert(`xss`)">',
        price: 9999.99,
        image: 'xss3juice.jpg'
      },
      headers: {
        Authorization: `Bearer ${process.env.BRIGHT_AUTH_ID}`,
        'Content-Type': 'application/json'
      }
    });
});