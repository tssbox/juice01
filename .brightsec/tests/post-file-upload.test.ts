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

test('POST /file-upload', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'ssrf', 'xxe'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        databases: ['SQLite', 'MongoDB']
      }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/file-upload`,
      headers: { 'Content-Type': 'multipart/form-data' },
      body: "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"example.zip\"\r\nContent-Type: application/zip\r\n\r\n<binary data>\r\n--boundary--",
      auth: process.env.BRIGHT_AUTH_ID
    });
});