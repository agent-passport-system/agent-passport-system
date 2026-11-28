#!/usr/bin/env node

// Post-publish verification through the npm client: install the exact published
// version, then `npm audit signatures`, which checks registry signatures and
// provenance attestations.
//
// Three states are kept apart. Published: npm accepted the package. Available: the
// version, its tarball and its attestations are served. Verified: integrity,
// signatures and provenance check out. Only "not yet available" conditions are
// retried. An integrity, signature or provenance failure fails at once, and so does
// anything this script does not recognise.
//
// Deadline: one overall limit of DEADLINE_MS for the whole verification, both
// stages together. Every npm run is given only the time that remains, no attempt
// starts after the deadline, and a wait that would end after it fails instead.
// A server Retry-After is never shortened or capped.
//
// Failure classification reads npm CLI output. It was written against npm 10 and
// 11; the release job pins its npm CLI, and the version in use is logged.
//
// The script publishes nothing, so it can be run again against an existing version
// (see .github/workflows/verify-release.yml).

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const PACKAGE_NAME = 'agent-passport-system';
// The 8.0.0 release took about six minutes to become fully visible. Ten minutes
// matches the window release-registry.mjs uses for the registry document.
export const DEADLINE_MS = 10 * 60_000;
export const BASE_DELAY_MS = 15_000;
export const MAX_DELAY_MS = 60_000;

const unavailable = (reason, retryAfterMs) => ({ kind: 'unavailable', reason, retryAfterMs });
const fail = (reason) => ({ kind: 'fail', reason });
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Classify the output of a failed npm command for this package version. */
export function classifyNpmFailure(log, version) {
  // The version must end where a version ends, so 8.2.0 does not match 8.2.0-beta.1.
  // A trailing sentence period is allowed, a further version character is not.
  const versionEnd = '(?![0-9A-Za-z+-]|\\.[0-9A-Za-z])';
  const ownVersion = `${escapeRegExp(PACKAGE_NAME)}@${escapeRegExp(version)}${versionEnd}`;

  // Cryptographic and integrity failures are never retried, even when the same
  // output also shows a transient error.
  if (/EINTEGRITY|integrity checksum failed/i.test(log)) return fail('integrity mismatch');
  if (/invalid (registry )?signatures?\b/i.test(log)) return fail('invalid registry signature');
  if (/invalid attestations?\b|attestations? (do|does) not match/i.test(log)) {
    return fail('invalid provenance attestation');
  }

  // This exact version not visible yet: metadata, tarball or attestation endpoint.
  if (/npm error code ETARGET/.test(log) && new RegExp(`No matching version found for ${ownVersion}`).test(log)) {
    return unavailable('version not listed in package metadata yet');
  }
  if (/npm error code E404/.test(log)) {
    const tarball = `/${escapeRegExp(PACKAGE_NAME)}/-/${escapeRegExp(PACKAGE_NAME)}-${escapeRegExp(version)}\\.tgz(?![0-9A-Za-z])`;
    if (new RegExp(tarball).test(log)) return unavailable('tarball not served yet');
    if (new RegExp(`/-/npm/v1/attestations/${ownVersion}`).test(log)) return unavailable('attestations not served yet');
    return fail('404 for a resource other than this version');
  }

  // Registry rate limit and transient network or server errors.
  if (/npm error code E429/.test(log)) {
    const header = /retry-after:\s*(\d+)/i.exec(log);
    return unavailable('registry rate limit', header ? Number(header[1]) * 1000 : undefined);
  }
  if (/npm error code (ETIMEDOUT|ECONNRESET|ECONNREFUSED|EAI_AGAIN|ENOTFOUND|E5\d\d)\b/.test(log)) {
    return unavailable('transient network or server error');
  }

  return fail('unrecognised npm failure');
}

/**
 * Run `attempt(timeoutMs)` until it succeeds, retrying only "unavailable" failures,
 * with exponential backoff capped at maxDelayMs, or exactly the server Retry-After
 * when one is given, all within the absolute deadline `deadlineAt` (or `deadlineMs`
 * from the first call). An attempt that reports `timedOut` or `spawnError` fails.
 * Clock and sleep are injectable.
 */
export async function runWithRetry(label, attempt, classify, {
  now = () => Date.now(),
  sleep = (ms) => new Promise((done) => setTimeout(done, ms)),
  deadlineAt,
  deadlineMs = DEADLINE_MS,
  baseDelayMs = BASE_DELAY_MS,
  maxDelayMs = MAX_DELAY_MS,
  log = console.log,
} = {}) {
  if (deadlineAt === undefined) deadlineAt = now() + deadlineMs;
  let delay = baseDelayMs;
  for (let tries = 1; ; tries++) {
    const remaining = deadlineAt - now();
    if (remaining <= 0) {
      throw new Error(`${label}: deadline reached before attempt ${tries}; verification failed`);
    }
    const result = attempt(remaining);
    if (result.spawnError) throw new Error(`${label}: could not run npm (${result.spawnError}); not retried`);
    if (result.timedOut) throw new Error(`${label}: npm did not finish before the deadline; verification failed`);
    if (result.status === 0) {
      if (now() > deadlineAt) throw new Error(`${label}: succeeded only after the deadline; verification failed`);
      return { tries };
    }
    const verdict = classify(result.output);
    if (verdict.kind === 'fail') throw new Error(`${label}: ${verdict.reason}; not retried`);
    // A server Retry-After is used as given, never capped by the local backoff limit.
    const wait = verdict.retryAfterMs === undefined ? delay : verdict.retryAfterMs;
    if (now() + wait >= deadlineAt) {
      throw new Error(`${label}: still unavailable after ${tries} attempts (${verdict.reason}); verification failed, the next wait of ${Math.round(wait / 1000)}s passes the deadline`);
    }
    log(`${label}: attempt ${tries}: ${verdict.reason}; retrying in ${Math.round(wait / 1000)}s`);
    await sleep(wait);
    delay = Math.min(delay * 2, maxDelayMs);
  }
}

function npm(args, cwd, timeoutMs) {
  const run = spawnSync('npm', args, { cwd, encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL' });
  const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
  process.stdout.write(output);
  const timedOut = run.error?.code === 'ETIMEDOUT' || (run.signal === 'SIGKILL' && run.status === null);
  const spawnError = !timedOut && run.error ? run.error.message : undefined;
  return { status: run.status ?? 1, output, timedOut, spawnError };
}

async function main() {
  const version = process.env.PACKAGE_VERSION;
  if (!version || !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error('PACKAGE_VERSION must be a semver version');
  }
  const deadlineAt = Date.now() + DEADLINE_MS;
  const root = mkdtempSync(join(tmpdir(), 'aps-verify-'));
  try {
    const npmVersion = spawnSync('npm', ['--version'], { encoding: 'utf8' });
    console.log(`verifying ${PACKAGE_NAME}@${version} with npm ${(npmVersion.stdout ?? '').trim() || 'unknown'}, deadline ${new Date(deadlineAt).toISOString()}`);
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'aps-release-verify', private: true }));
    const cache = join(root, '.npm-cache');
    const classify = (output) => classifyNpmFailure(output, version);
    await runWithRetry('npm install', (timeoutMs) => npm(
      ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--prefer-online', '--cache', cache, `${PACKAGE_NAME}@${version}`],
      root, timeoutMs,
    ), classify, { deadlineAt });
    await runWithRetry('npm audit signatures', (timeoutMs) => npm(['audit', 'signatures', '--cache', cache], root, timeoutMs), classify, { deadlineAt });
    console.log(`${PACKAGE_NAME}@${version}: installed from the registry, signatures and attestations verified`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
