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

test('POST /rest/memories', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'stored_xss', 'bopla', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/memories`,
      headers: { 'Content-Type': 'application/json' },
      body: {
        mimeType: 'multipart/form-data',
        text: `--boundary\nContent-Disposition: form-data; name="caption"\n\nA beautiful memory\n--boundary\nContent-Disposition: form-data; name="image"; filename="memory.jpg"\nContent-Type: image/jpeg\n\n<binary data>\n--boundary\nContent-Disposition: form-data; name="UserId"\n\n123\n--boundary--`
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
