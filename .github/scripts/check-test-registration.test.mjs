import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { classify, notExecuted } from './check-test-registration.mjs'

const SCRIPT = resolve('.github/scripts/check-test-registration.mjs')

test('an unregistered test file is reported', () => {
  const r = classify(['tests/a.test.ts', 'tests/new.test.ts'], new Set(['tests/a.test.ts']), {})
  assert.deepEqual(r.unregistered, ['tests/new.test.ts'])
})

test('an exclusion needs a reason and must still match something', () => {
  const r = classify(['tests/a.test.ts'], new Set(['tests/a.test.ts']), { 'tests/gone.test.ts': 'no longer exists anywhere', 'tests/b.test.ts': '' })
  assert.deepEqual(r.staleExclusions, ['tests/gone.test.ts', 'tests/b.test.ts'])
  assert.deepEqual(r.emptyReasons, ['tests/b.test.ts'])
})

test('a file both run and excluded is reported', () => {
  const r = classify(['tests/a.test.ts'], new Set(['tests/a.test.ts']), { 'tests/a.test.ts': 'claimed to be excluded' })
  assert.deepEqual(r.excludedButRun, ['tests/a.test.ts'])
})

test('a directory exclusion covers the files under it', () => {
  const r = classify(['packages/p/x.test.ts', 'packages/p/sub/y.test.ts'], new Set(), { 'packages/p/*': 'package tests run elsewhere' })
  assert.deepEqual(r.unregistered, [])
  assert.deepEqual(r.staleExclusions, [])
})

test('a registered file that reported no test case is caught', () => {
  const xml = '<testsuites><testcase name="t" file="/r/tests/a.test.ts"/></testsuites>'
  assert.deepEqual(notExecuted(['tests/a.test.ts', 'tests/b.test.ts'], xml, '/r'), ['tests/b.test.ts'])
})

// Negative control end to end: a throwaway repository with one registered and
// one unregistered test file. The guard must exit 1 and name the unregistered file.
test('negative control: the guard fails on a repository with an unregistered test file', () => {
  const root = mkdtempSync(join(tmpdir(), 'reg-guard-'))
  try {
    const git = (...a) => execFileSync('git', a, { cwd: root, stdio: 'ignore' })
    git('init', '-q')
    mkdirSync(join(root, '.github/workflows'), { recursive: true })
    mkdirSync(join(root, 'tests'))
    writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test tests/registered.test.ts' } }))
    writeFileSync(join(root, '.github/workflows/ci.yml'), 'jobs:\n  t:\n    steps:\n      - run: npm test\n')
    writeFileSync(join(root, '.github/test-registration-exclusions.json'), '{}')
    writeFileSync(join(root, 'tests/registered.test.ts'), "import test from 'node:test'\n")
    writeFileSync(join(root, 'tests/forgotten.test.ts'), "import test from 'node:test'\n")
    git('add', '-A')
    const run = spawnSync(process.execPath, [SCRIPT], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 1, run.stdout + run.stderr)
    assert.match(run.stderr, /not run by CI and not excluded: tests\/forgotten\.test\.ts/)
    assert.doesNotMatch(run.stderr, /registered\.test\.ts/)
    // Registering it makes the same repository pass.
    writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test tests/registered.test.ts tests/forgotten.test.ts' } }))
    const ok = spawnSync(process.execPath, [SCRIPT], { cwd: root, encoding: 'utf8' })
    assert.equal(ok.status, 0, ok.stdout + ok.stderr)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
