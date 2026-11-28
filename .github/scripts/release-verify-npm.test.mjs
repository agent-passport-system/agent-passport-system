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

// Regressions for the deadline, Retry-After, version matching and subprocess handling.

test('an attempt that runs into the deadline fails, and no attempt starts after it', async () => {
  const clock = fakeClock();
  const budgets = [];
  await assert.rejects(
    runWithRetry('step', (timeoutMs) => {
      budgets.push(timeoutMs);
      clock.sleep(70_000); // the attempt itself takes 70 s
      return { status: 1, output: TARBALL_404 };
    }, (o) => classifyNpmFailure(o, V), { ...clock, deadlineMs: 100_000, baseDelayMs: 15_000 }),
    /verification failed/,
  );
  assert.equal(budgets[0], 100_000, 'the first attempt gets the whole remaining time');
  assert.ok(budgets.every((b) => b > 0), 'never starts an attempt with no time left');
  assert.ok(clock.now() <= 100_000 + 70_000, 'stops after the attempt that crossed the deadline');
});

test('a success that only finishes after the deadline is not accepted', async () => {
  const clock = fakeClock();
  await assert.rejects(
    runWithRetry('step', () => { clock.sleep(200_000); return { status: 0, output: '' }; }, (o) => classifyNpmFailure(o, V), { ...clock, deadlineMs: 100_000 }),
    /succeeded only after the deadline/,
  );
});

test('a Retry-After longer than the local backoff limit is honoured in full', async () => {
  const waits = [];
  const clock = fakeClock();
  const results = [{ status: 1, output: 'npm error code E429\nretry-after: 120' }, { status: 0, output: '' }];
  await runWithRetry('step', () => results.shift(), (o) => classifyNpmFailure(o, V), {
    ...clock, sleep: async (ms) => { waits.push(ms); await clock.sleep(ms); }, maxDelayMs: 60_000, deadlineMs: 600_000,
  });
  assert.deepEqual(waits, [120_000]);
});

test('a Retry-After longer than the remaining time fails instead of retrying early', async () => {
  const clock = fakeClock();
  let calls = 0;
  await assert.rejects(
    runWithRetry('step', () => { calls++; return { status: 1, output: 'npm error code E429\nretry-after: 900' }; }, (o) => classifyNpmFailure(o, V), { ...clock, deadlineMs: 600_000 }),
    /registry rate limit\); verification failed, the next wait of 900s passes the deadline/,
  );
  assert.equal(calls, 1);
  assert.equal(clock.now(), 0, 'did not sleep');
});

test('a 404 or missing version for a prerelease of the same base version is not this version', () => {
  assert.equal(classifyNpmFailure(TARBALL_404.replaceAll('8.2.0', '8.2.0-beta.1'), V).kind, 'fail');
  assert.equal(classifyNpmFailure(ATTESTATIONS_404.replaceAll('8.2.0', '8.2.0-beta.1'), V).kind, 'fail');
  assert.equal(classifyNpmFailure(ETARGET.replace('8.2.0.', '8.2.0-rc.1.'), V).kind, 'fail');
  assert.equal(classifyNpmFailure(ETARGET, V).kind, 'unavailable', 'the exact version still matches');
  // And the reverse: a prerelease being verified does not match its release line.
  assert.equal(classifyNpmFailure(TARBALL_404, '8.2.0-beta.1').kind, 'fail');
});

test('a subprocess timeout or spawn error fails at once', async () => {
  let calls = 0;
  await assert.rejects(
    runWithRetry('step', () => { calls++; return { status: 1, output: '', timedOut: true }; }, (o) => classifyNpmFailure(o, V), fakeClock()),
    /did not finish before the deadline/,
  );
  await assert.rejects(
    runWithRetry('step', () => { calls++; return { status: 1, output: '', spawnError: 'spawn npm ENOENT' }; }, (o) => classifyNpmFailure(o, V), fakeClock()),
    /could not run npm \(spawn npm ENOENT\); not retried/,
  );
  assert.equal(calls, 2);
});

test('an integrity failure in the same output as a transient error is not retried', () => {
  const mixed = 'npm error code ECONNRESET\nnpm error sha512-abc integrity checksum failed when using sha512\nnpm error code EINTEGRITY';
  assert.deepEqual(classifyNpmFailure(mixed, V), { kind: 'fail', reason: 'integrity mismatch' });
  const mixed404 = `${TARBALL_404}\n1 package has an invalid registry signature`;
  assert.equal(classifyNpmFailure(mixed404, V).kind, 'fail');
});
