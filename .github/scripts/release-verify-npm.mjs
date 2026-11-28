#!/usr/bin/env node

// Post-publish verification through the npm client: install the exact published
// version, then `npm audit signatures`, which checks registry signatures and
// provenance attestations.
//
// Three states are kept apart. Published: npm accepted the package. Available: the
// version, its tarball and its attestations are served. Verified: integrity,
// signatures and provenance check out. Only "not yet available" conditions are
// retried, within a bounded deadline. An integrity, signature or provenance failure
// fails at once, and so does anything this script does not recognise.
//
// The script publishes nothing, so it can be run again against an existing version
// (see .github/workflows/verify-release.yml).

import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
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

/** Classify the output of a failed npm command for this package version. */
export function classifyNpmFailure(log, version) {
  const own = `${PACKAGE_NAME}@${version}`;

  // Cryptographic and integrity failures are never retried.
  if (/EINTEGRITY|integrity checksum failed/i.test(log)) return fail('integrity mismatch');
  if (/invalid (registry )?signatures?\b/i.test(log)) return fail('invalid registry signature');
  if (/invalid attestations?\b|attestations? (do|does) not match/i.test(log)) {
    return fail('invalid provenance attestation');
  }

  // This version not visible yet: metadata, tarball or attestation endpoint.
  if (/npm error code ETARGET/.test(log) && log.includes(`No matching version found for ${own}`)) {
    return unavailable('version not listed in package metadata yet');
  }
  if (/npm error code E404/.test(log)) {
    if (log.includes(`/${PACKAGE_NAME}/-/${PACKAGE_NAME}-${version}.tgz`)) {
      return unavailable('tarball not served yet');
    }
    if (log.includes(`/-/npm/v1/attestations/${own}`)) {
      return unavailable('attestations not served yet');
    }
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
 * Run `attempt` until it succeeds, retrying only "unavailable" failures, with
 * exponential backoff capped at MAX_DELAY_MS and an overall deadline. Clock and
 * sleep are injectable for tests.
 */
export async function runWithRetry(label, attempt, classify, {
  now = () => Date.now(),
  sleep = (ms) => new Promise((done) => setTimeout(done, ms)),
  deadlineMs = DEADLINE_MS,
  baseDelayMs = BASE_DELAY_MS,
  maxDelayMs = MAX_DELAY_MS,
  log = console.log,
} = {}) {
  const start = now();
  let delay = baseDelayMs;
  for (let tries = 1; ; tries++) {
    const result = attempt();
    if (result.status === 0) return { tries };
    const verdict = classify(result.output);
    if (verdict.kind === 'fail') {
      throw new Error(`${label}: ${verdict.reason}; not retried`);
    }
    const wait = Math.min(verdict.retryAfterMs ?? delay, maxDelayMs);
    if (now() - start + wait > deadlineMs) {
      throw new Error(`${label}: still unavailable after ${tries} attempts (${verdict.reason}); verification failed`);
    }
    log(`${label}: attempt ${tries}: ${verdict.reason}; retrying in ${Math.round(wait / 1000)}s`);
    await sleep(wait);
    delay = Math.min(delay * 2, maxDelayMs);
  }
}

function npm(args, cwd) {
  const run = spawnSync('npm', args, { cwd, encoding: 'utf8' });
  const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
  process.stdout.write(output);
  return { status: run.status ?? 1, output };
}

async function main() {
  const version = process.env.PACKAGE_VERSION;
  if (!version || !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error('PACKAGE_VERSION must be a semver version');
  }
  const root = mkdtempSync(join(tmpdir(), 'aps-verify-'));
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'aps-release-verify', private: true }));
  const cache = join(root, '.npm-cache');
  const classify = (output) => classifyNpmFailure(output, version);

  await runWithRetry('npm install', () => npm(
    ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--prefer-online', '--cache', cache, `${PACKAGE_NAME}@${version}`],
    root,
  ), classify);
  await runWithRetry('npm audit signatures', () => npm(['audit', 'signatures', '--cache', cache], root), classify);
  console.log(`${PACKAGE_NAME}@${version}: installed from the registry, signatures and attestations verified`);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
