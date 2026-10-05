import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = await mkdtemp(join(tmpdir(), 'blanche-target-request-templates-'));

try {
  const outputPath = join(outputDirectory, 'targetRequestTemplates.mjs');
  await build({
    entryPoints: [
      join(repoRoot, 'chromium-extension/src/shared/targetRequestTemplates.ts')
    ],
    outfile: outputPath,
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2022',
    logLevel: 'silent'
  });

  const templates = await import(pathToFileURL(outputPath).href);
  testExactParameterExtraction(templates);
  testGetRequest(templates);
  testPostRequest(templates);
  testAuthoritiesAndCredentials(templates);
  testValidation(templates);

  console.log('Target request template tests passed.');
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}

function testExactParameterExtraction({ getTargetUrlParameters }) {
  const rawQuery = 'a=1&a=2&blank=&bare&plus=hello+world&space=hello%20world&slash=%2f%2F';
  assert.equal(
    getTargetUrlParameters(`https://example.test/search?${rawQuery}#ignored?fragment=value`),
    rawQuery
  );
  assert.equal(getTargetUrlParameters('https://example.test/path#fragment?not=a-query'), '');
  assert.equal(getTargetUrlParameters('https://example.test/path'), '');
  assert.equal(getTargetUrlParameters('ftp://example.test/file?q=preserved'), 'q=preserved');
  assert.throws(() => getTargetUrlParameters('not an absolute URL'), TypeError);
}

function testGetRequest({ buildBurpGetRequest }) {
  const rawQuery = 'a=1&a=2&blank=&bare&plus=a+b&encoded=%2f%3F';
  const request = buildBurpGetRequest(
    `https://example.test:8443/a/b?${rawQuery}#not-sent`
  );
  assert.equal(
    request,
    `GET /a/b?${rawQuery} HTTP/1.1\r\nHost: example.test:8443\r\n\r\n`
  );
  assert.equal(request.replaceAll('\r\n', '').includes('\n'), false);
  assert.equal(buildBurpGetRequest('https://example.test'), 'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n');
}

function testPostRequest({ buildBurpPostRequest }) {
  const body = 'term=café&symbol=✓&item=1&item=2';
  const byteLength = new TextEncoder().encode(body).byteLength;
  const request = buildBurpPostRequest(`https://example.test/search?${body}#ignored`);
  assert.equal(
    request,
    'POST /search HTTP/1.1\r\n' +
      'Host: example.test\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      `Content-Length: ${byteLength}\r\n` +
      `\r\n${body}`
  );
  assert.equal(request.replaceAll('\r\n', '').includes('\n'), false);
  assert.equal(
    buildBurpPostRequest('http://example.test/submit'),
    'POST /submit HTTP/1.1\r\n' +
      'Host: example.test\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 0\r\n\r\n'
  );
}

function testAuthoritiesAndCredentials({ buildBurpGetRequest, buildBurpPostRequest }) {
  assert.equal(
    buildBurpGetRequest('https://user:password@example.test:443/private?q=1'),
    'GET /private?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n'
  );
  assert.match(buildBurpGetRequest('http://[2001:db8::1]:8080/x'), /Host: \[2001:db8::1\]:8080/);
  assert.match(buildBurpPostRequest('http://example.test:80/x?q=1'), /Host: example\.test\r\n/);
}

function testValidation({ getTargetUrlParameters, buildBurpGetRequest, buildBurpPostRequest }) {
  assert.throws(
    () => buildBurpGetRequest('ftp://example.test/file?q=1'),
    /HTTP or HTTPS target URL/
  );
  assert.throws(
    () => buildBurpPostRequest('chrome://settings/?q=1'),
    /HTTP or HTTPS target URL/
  );
  assert.throws(() => buildBurpGetRequest('not a URL'), TypeError);
  for (const unsafeUrl of [
    'https://example.test/?value=1\r\nX-Injected: yes',
    'https://example.test/?value=1\tX-Injected',
    'https://example.test/?value=1\u0000X-Injected',
    'https://example.test/?value=1\u007fX-Injected'
  ]) {
    assert.throws(
      () => getTargetUrlParameters(unsafeUrl),
      /raw ASCII control characters/
    );
    assert.throws(
      () => buildBurpGetRequest(unsafeUrl),
      /raw ASCII control characters/
    );
    assert.throws(
      () => buildBurpPostRequest(unsafeUrl),
      /raw ASCII control characters/
    );
  }
}
