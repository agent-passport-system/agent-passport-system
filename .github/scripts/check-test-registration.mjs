#!/usr/bin/env node
// Every tracked test file must be run by a CI workflow or listed, with a reason,
// in .github/test-registration-exclusions.json. A test file that exists but that
// no job runs looks like coverage and is none: the GHSA-249c regression test sat
// outside npm test for a release before anyone noticed.
//
// Registration: a path named in a workflow run line, in a root package.json
// script that a workflow runs (npm test, npm run <name>), or in the test script
// of a package whose directory a workflow runs npm test in.
//
// Each exclusion is { kind, reason } plus, for kind "temporary", an owner and a
// task link. "intentional" means the file is meant to run outside CI. "temporary"
// means coverage is missing or broken and is owed, so it cannot pass as a quiet way
// to keep CI green: it must name who owns the fix and the issue that tracks it.
//
// With --executed <file>, also checks execution: every file named in the root
// test script must appear in that list, which test-files-reporter.mjs writes
// during npm test with one path per test file that reported a test case.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join, posix } from 'node:path'
import { pathToFileURL } from 'node:url'

const TEST_FILE = /\.test\.(ts|mjs|js)$/
const NODE_TEST = /from ['"]node:test['"]|require\(['"]node:test['"]\)/

/** Whitespace tokens of a command line that look like file paths. */
const pathTokens = (text) => text.split(/[\s"'`]+/).filter((t) => !t.startsWith('-') && /\.(ts|mjs|js)$/.test(t))

/** Expand an exclusion key: an exact path, or a directory prefix ending in /*. */
function excluded(file, exclusions) {
  for (const key of Object.keys(exclusions)) {
    if (key.startsWith('$')) continue
    if (key.endsWith('/*') ? file.startsWith(key.slice(0, -1)) : file === key) return key
  }
  return undefined
}

/**
 * Pure classification, so a negative control can run it on synthetic input.
 * @param testFiles tracked test files
 * @param registered set of registered paths
 * @param exclusions { path or dir/*: { kind, reason, owner?, task? } }
 */
export function classify(testFiles, registered, exclusions) {
  const unregistered = []
  const usedKeys = new Set()
  const excludedButRun = []
  for (const f of testFiles) {
    const key = excluded(f, exclusions)
    if (registered.has(f)) {
      if (key && !key.endsWith('/*')) excludedButRun.push(f)
      continue
    }
    if (key) { usedKeys.add(key); continue }
    unregistered.push(f)
  }
  const staleExclusions = Object.keys(exclusions)
    .filter((k) => !k.startsWith('$') && !usedKeys.has(k) && !excludedButRun.includes(k))
  const invalidEntries = Object.entries(exclusions)
    .filter(([k]) => !k.startsWith('$'))
    .map(([k, v]) => ({ key: k, problem: entryProblem(v) }))
    .filter((e) => e.problem)
  return { unregistered, staleExclusions, excludedButRun, invalidEntries }
}

const TASK = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/issues\/\d+$/

/** Why an exclusion entry is not acceptable, or undefined when it is. */
export function entryProblem(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return 'must be an object { kind, reason }'
  if (typeof v.reason !== 'string' || v.reason.trim().length < 10) return 'needs a reason of at least 10 characters'
  if (v.kind === 'intentional') return undefined
  if (v.kind !== 'temporary') return 'kind must be "intentional" or "temporary"'
  if (typeof v.owner !== 'string' || !v.owner.trim()) return 'a temporary exclusion needs an owner'
  if (typeof v.task !== 'string' || !TASK.test(v.task)) return 'a temporary exclusion needs a task link to a GitHub issue'
  return undefined
}

export function collect(root) {
  const tracked = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean)
  const testFiles = tracked.filter((f) => {
    if (TEST_FILE.test(f)) return true
    if (!/\.(ts|mjs|js)$/.test(f) || f.includes('node_modules/')) return false
    try { return NODE_TEST.test(readFileSync(join(root, f), 'utf8')) } catch { return false }
  })
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  const scripts = pkg.scripts ?? {}
  const registered = new Set()
  const wfDir = join(root, '.github/workflows')
  for (const name of readdirSync(wfDir).filter((n) => /\.ya?ml$/.test(n))) {
    const text = readFileSync(join(wfDir, name), 'utf8')
    for (const t of pathTokens(text)) registered.add(posix.normalize(t))
    const runsRootTest = /(^|\s)npm (run )?test(\s|$)/m.test(text)
    if (runsRootTest) for (const t of pathTokens(scripts.test ?? '')) registered.add(t)
    for (const m of text.matchAll(/npm run ([\w:.-]+)/g)) for (const t of pathTokens(scripts[m[1]] ?? '')) registered.add(t)
    for (const m of text.matchAll(/working-directory:\s*(\S+)/g)) {
      const dir = m[1].replace(/['"]/g, '')
      const p = join(root, dir, 'package.json')
      if (!runsRootTest || !existsSync(p)) continue
      const sub = JSON.parse(readFileSync(p, 'utf8')).scripts?.test ?? ''
      for (const t of pathTokens(sub)) registered.add(posix.join(dir, t))
    }
  }
  const exclusions = JSON.parse(readFileSync(join(root, '.github/test-registration-exclusions.json'), 'utf8'))
  return { testFiles, registered, exclusions, rootTestFiles: pathTokens(scripts.test ?? '') }
}

/** Files named in the root test script that are absent from the executed list. */
export function notExecuted(rootTestFiles, executedText, root) {
  const seen = new Set(
    executedText.split('\n').map((l) => l.trim()).filter(Boolean)
      .map((abs) => (abs.startsWith(root + '/') ? abs.slice(root.length + 1) : abs)),
  )
  return rootTestFiles.filter((f) => !seen.has(f))
}

function main() {
  const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim()
  const { testFiles, registered, exclusions, rootTestFiles } = collect(root)
  const r = classify(testFiles, registered, exclusions)
  const problems = []
  for (const f of r.unregistered) problems.push(`not run by CI and not excluded: ${f}`)
  for (const f of r.staleExclusions) problems.push(`exclusion matches no unregistered test file, remove it: ${f}`)
  for (const f of r.excludedButRun) problems.push(`excluded but also run by CI, remove the exclusion: ${f}`)
  for (const e of r.invalidEntries) problems.push(`exclusion ${e.key}: ${e.problem}`)
  const missing = rootTestFiles.filter((f) => !existsSync(join(root, f)))
  for (const f of missing) problems.push(`root test script names a file that does not exist: ${f}`)
  const i = process.argv.indexOf('--executed')
  if (i > 0) {
    const listed = readFileSync(process.argv[i + 1], 'utf8')
    for (const f of notExecuted(rootTestFiles, listed, root)) {
      problems.push(`named in npm test but reported no test case: ${f}`)
    }
  }
  console.log(`test files ${testFiles.length}, run by CI ${testFiles.filter((f) => registered.has(f)).length}, excluded ${testFiles.length - testFiles.filter((f) => registered.has(f)).length - r.unregistered.length}`)
  if (problems.length) {
    console.error(problems.join('\n'))
    process.exit(1)
  }
  const temporary = Object.entries(exclusions).filter(([k, v]) => !k.startsWith('$') && v?.kind === 'temporary')
  for (const [k, v] of temporary) console.log(`temporary exclusion, owed: ${k} (${v.owner}, ${v.task})`)
  console.log('every tracked test file is run by CI or excluded with a reason')
}

const invoked = process.argv[1] ? pathToFileURL(process.argv[1]).href : ''
if (import.meta.url === invoked) main()
