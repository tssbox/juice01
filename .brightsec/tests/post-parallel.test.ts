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

test('POST /parallel', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'bopla', 'proto_pollution', 'osi', 'ssti', 'ssrf', 'file_upload'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/parallel`,
      body: {
        tool_uses: [
          {
            recipient_name: "functions.similarity_search",
            parameters: {
              fileTypes: ["code"],
              query: "global or parent prefixes for API endpoints"
            }
          },
          {
            recipient_name: "functions.similarity_search",
            parameters: {
              fileTypes: ["code"],
              query: "request inputs for POST /profile/image/file endpoint"
            }
          }
        ]
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
