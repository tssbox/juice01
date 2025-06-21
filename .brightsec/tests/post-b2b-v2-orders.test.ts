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

test('POST /b2b/v2/orders', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['osi', 'sqli', 'xss', 'csrf', 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/b2b/v2/orders`,
      body: {
        cid: 'JS0815DE',
        orderLinesData: '[{"productId":12,"quantity":10000,"customerReference":["PO0000001.2", "SM20180105|042"],"couponCode":"pes[Bh.u*t"},{"productId":13,"quantity":2000,"customerReference":"PO0000003.4"}]'
      },
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer <token>'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
