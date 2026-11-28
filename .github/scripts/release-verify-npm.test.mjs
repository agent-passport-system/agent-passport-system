import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyNpmFailure, runWithRetry } from './release-verify-npm.mjs';

const V = '8.2.0';

// Taken from release run 46104176094 (v8.2.0), where the tarball 404 was not retried.
const TARBALL_404 = `npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/agent-passport-system/-/agent-passport-system-8.2.0.tgz - Not found`;
const ETARGET = `npm error code ETARGET
npm error notarget No matching version found for agent-passport-system@8.2.0.`;
const ATTESTATIONS_404 = `npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/-/npm/v1/attestations/agent-passport-system@8.2.0 - Not found`;

test('availability failures for this version are retried', () => {
  for (const log of [TARBALL_404, ETARGET, ATTESTATIONS_404]) {
    assert.equal(classifyNpmFailure(log, V).kind, 'unavailable', log);
  }
  assert.equal(classifyNpmFailure('npm error code E429\nretry-after: 30', V).retryAfterMs, 30_000);
  assert.equal(classifyNpmFailure('npm error code ECONNRESET', V).kind, 'unavailable');
  assert.equal(classifyNpmFailure('npm error code E503', V).kind, 'unavailable');
});

test('integrity, signature and provenance failures are never retried', () => {
  for (const log of [
    'npm error code EINTEGRITY\nnpm error sha512-abc integrity checksum failed when using sha512',
    '1 package has an invalid registry signature:\nagent-passport-system@8.2.0',
    '1 package has invalid attestations:\nagent-passport-system@8.2.0',
  ]) {
    assert.equal(classifyNpmFailure(log, V).kind, 'fail', log);
  }
});

test('a missing version or tarball of another package or version is not retried', () => {
  assert.equal(classifyNpmFailure(ETARGET.replace('agent-passport-system@8.2.0', 'some-dependency@1.0.0'), V).kind, 'fail');
  assert.equal(classifyNpmFailure(TARBALL_404.replaceAll('8.2.0', '8.1.9'), V).kind, 'fail');
  assert.equal(classifyNpmFailure('npm error code EACCES', V).kind, 'fail');
});

function fakeClock() {
  let t = 0;
  return { now: () => t, sleep: async (ms) => { t += ms; }, log: () => {} };
}

test('a temporary 404 followed by success passes', async () => {
  const results = [{ status: 1, output: TARBALL_404 }, { status: 1, output: ATTESTATIONS_404 }, { status: 0, output: '' }];
  const { tries } = await runWithRetry('step', () => results.shift(), (o) => classifyNpmFailure(o, V), fakeClock());
  assert.equal(tries, 3);
});

test('a 404 that persists past the deadline fails verification', async () => {
  const clock = fakeClock();
  let calls = 0;
  await assert.rejects(
    runWithRetry('step', () => { calls++; return { status: 1, output: TARBALL_404 }; }, (o) => classifyNpmFailure(o, V), { ...clock, deadlineMs: 120_000 }),
    /still unavailable after \d+ attempts \(tarball not served yet\); verification failed/,
  );
  assert.ok(clock.now() <= 120_000, 'never waits past the deadline');
  assert.ok(calls > 1, 'retried before failing');
});

test('a signature failure fails on the first attempt', async () => {
  let calls = 0;
  await assert.rejects(
    runWithRetry('step', () => { calls++; return { status: 1, output: '1 package has an invalid registry signature' }; }, (o) => classifyNpmFailure(o, V), fakeClock()),
    /invalid registry signature; not retried/,
  );
  assert.equal(calls, 1);
});

test('backoff doubles and is capped, and Retry-After is honoured', async () => {
  const waits = [];
  const clock = fakeClock();
  const results = [
    { status: 1, output: 'npm error code E503' },
    { status: 1, output: 'npm error code E503' },
    { status: 1, output: 'npm error code E503' },
    { status: 1, output: 'npm error code E429\nretry-after: 5' },
    { status: 0, output: '' },
  ];
  await runWithRetry('step', () => results.shift(), (o) => classifyNpmFailure(o, V), {
    ...clock, sleep: async (ms) => { waits.push(ms); await clock.sleep(ms); }, baseDelayMs: 15_000, maxDelayMs: 40_000,
  });
  assert.deepEqual(waits, [15_000, 30_000, 40_000, 5_000]);
});
