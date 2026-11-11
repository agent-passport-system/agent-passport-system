// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Cases for the document authority gateway and its evidence package. Every case that
// exports a package also runs the offline verifier over it, so a passing case means the
// gateway decided as expected and a third party holding only trusted keys can check it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { AGENT_A, AGENT_B, AUDITOR, COUNSEL, DOCUMENT, PRESS, REPOSITORY, VERSION, createWorld } from './actors.ts'
import type { World } from './actors.ts'
import { createReceiptV1 } from 'agent-passport-system'
import { contentDigest, shareScope } from './document-rules.ts'
import { sha256Hex } from 'aps-example-authority-engine/engine.ts'
import { computePackageId, receiptIndex } from './package-format.ts'
import type { EvidencePackage } from './package-format.ts'
import { reconcile } from './reconcile.ts'
import { documentShareProfile } from './repository.ts'
import { VERIFIER_LIMITS, verifyPackage } from './verify-package.ts'

const here = dirname(fileURLToPath(import.meta.url))
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T
const reId = (p: EvidencePackage): EvidencePackage => ({ ...p, package_id: computePackageId(p) })
const status = (o: { result?: { result: unknown } }) => (o.result?.result as { status?: string } | undefined)?.status
const errorCode = (o: { result?: { result: unknown } }) => (o.result?.result as { error_code?: string } | undefined)?.error_code

function setup(opts?: Parameters<typeof createWorld>[0]) {
  const w = createWorld(opts)
  const b = w.delegate(w.grantToA, AGENT_B, [shareScope(w.share(AUDITOR))])
  return { w, b, chainB: [w.grantToA, b] }
}

function verifyOk(w: World, pkg = w.exportPackage()) {
  const c = verifyPackage(pkg, w.trustedKeys())
  assert.deepEqual(c.errors, [], 'package errors')
  for (const e of c.entries) assert.deepEqual(e.errors, [], `entry ${e.label}`)
  assert.ok(c.ok)
  return pkg
}

function runCli(script: string, args: string[]): { code: number; out: string } {
  try {
    return { code: 0, out: execFileSync(process.execPath, ['--import', 'tsx', join(here, script), ...args], { cwd: here, encoding: 'utf8' }) }
  } catch (e) {
    const err = e as { status: number; stdout: string }
    return { code: err.status, out: err.stdout }
  }
}

test('D1 the six steps, exported and verified in a separate process with trusted keys only', async () => {
  const { w, chainB } = setup()
  const counsel = await w.run('B to outside-counsel', AGENT_B, chainB, w.share(COUNSEL))
  assert.equal(counsel.verdict, 'deny')
  assert.equal(counsel.reason, 'not_in_delegated_scope')
  const ok = await w.run('B to auditor-llp', AGENT_B, chainB, w.share(AUDITOR))
  assert.equal(ok.verdict, 'permit')
  assert.equal(status(ok), 'succeeded')
  assert.deepEqual(w.revokeRoot(), { recorded: true })
  const after = await w.run('B after revocation', AGENT_B, chainB, w.share(AUDITOR))
  assert.equal(after.reason, 'authority_invalid:REVOKED')

  const log = w.repository.exportLog()
  assert.equal(log.length, 1)
  assert.equal(log[0].recipient, AUDITOR)
  assert.equal(log[0].correlation_id, ok.action_ref)

  const pkg = verifyOk(w)
  assert.equal(pkg.entries.length, 3)
  const dir = mkdtempSync(join(tmpdir(), 'aps-doc-'))
  writeFileSync(join(dir, 'pkg.json'), JSON.stringify(pkg))
  writeFileSync(join(dir, 'keys.json'), JSON.stringify(w.trustedKeys()))
  writeFileSync(join(dir, 'log.json'), JSON.stringify(log))
  const v = runCli('verify-package.ts', [join(dir, 'pkg.json'), join(dir, 'keys.json')])
  assert.equal(v.code, 0, v.out)
  assert.match(v.out, /3 of 3 entries verified, 0 package errors/)
  const r = runCli('reconcile.ts', [join(dir, 'pkg.json'), join(dir, 'keys.json'), join(dir, 'log.json')])
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /1 recorded shares, 1 shares in the repository log, 0 discrepancies/)

  // One altered signed field and the separate process refuses it.
  const bad = clone(pkg)
  const e = bad.entries.find(x => x.label === 'B to auditor-llp')!
  ;(e.receipts.result!.result as { status: string }).status = 'failed'
  writeFileSync(join(dir, 'bad.json'), JSON.stringify(reId(bad)))
  const vb = runCli('verify-package.ts', [join(dir, 'bad.json'), join(dir, 'keys.json')])
  assert.equal(vb.code, 1)
  assert.match(vb.out, /INVALID B to auditor-llp/)
})

test('D2 Agent A cannot give Agent B a recipient or document A does not hold', () => {
  const w = createWorld()
  assert.throws(() => w.delegate(w.grantToA, AGENT_B, [shareScope(w.share(PRESS))]), /SCOPE_WIDENING/)
  assert.throws(() => w.delegate(w.grantToA, AGENT_B, ['content:share:*']), /SCOPE_WIDENING/)
  assert.throws(() => w.delegate(w.grantToA, AGENT_B, [`content:share:${REPOSITORY}:${DOCUMENT}:*`]), /SCOPE_WIDENING/)
})

test('D3 authority is bound to the version, the exact bytes and the recipient', async () => {
  const { w, chainB } = setup()
  const v4digest = w.repository.put(REPOSITORY, DOCUMENT, '4', 'Q3 board pack, version 4, with late changes.')
  for (const [label, payload] of [
    ['version 4', w.share(AUDITOR, { version: '4', content_digest: v4digest })],
    ['other bytes', w.share(AUDITOR, { content_digest: contentDigest('something else') })],
    ['press-desk', w.share(PRESS)],
  ] as const) {
    const o = await w.run(label, AGENT_B, chainB, payload)
    assert.equal(o.verdict, 'deny', label)
    assert.equal(o.reason, 'not_in_delegated_scope', label)
  }
  assert.equal(w.repository.exportLog().length, 0)
  verifyOk(w)
})

test('D4 the repository no longer holds the approved bytes: refused before anything is shared', async () => {
  const { w, chainB } = setup()
  w.repository.put(REPOSITORY, DOCUMENT, VERSION, 'Q3 board pack, version 3, quietly edited.')
  const o = await w.run('tampered before request', AGENT_B, chainB, w.share(AUDITOR))
  assert.equal(o.verdict, 'deny')
  assert.equal(o.reason, 'content_digest_mismatch')
  assert.equal(w.repository.exportLog().length, 0)
  verifyOk(w)
})

test('D5 the bytes change between authorization and dispatch: refused at admission', async () => {
  const { w, chainB } = setup()
  const sub = w.request(AGENT_B, chainB, w.share(AUDITOR))
  const a = w.gateway.authorize(sub)
  assert.equal(a.verdict, 'permit')
  w.repository.put(REPOSITORY, DOCUMENT, VERSION, 'Q3 board pack, version 3, edited after approval.')
  const o = await w.gateway.dispatch(a.action_ref!)
  assert.equal(o.dispatched, false)
  assert.equal(status(o), 'failed')
  assert.equal(errorCode(o), 'admission_refused:content_digest_mismatch')
  assert.equal(w.repository.exportLog().length, 0)
  w.records.push({ label: 'tampered after approval', sub, outcome: o })
  verifyOk(w)
})

test('D6 revocation between authorization and dispatch: refused at admission, and the package supports it', async () => {
  const { w, chainB } = setup()
  const sub = w.request(AGENT_B, chainB, w.share(AUDITOR))
  const a = w.gateway.authorize(sub)
  assert.equal(a.verdict, 'permit')
  assert.deepEqual(w.revokeRoot(), { recorded: true })
  const o = await w.gateway.dispatch(a.action_ref!)
  assert.equal(o.dispatched, false)
  assert.equal(errorCode(o), 'admission_refused:authority_invalid:REVOKED')
  assert.equal(w.repository.exportLog().length, 0)
  w.records.push({ label: 'revoked before dispatch', sub, outcome: o })
  const pkg = verifyOk(w)

  // Without the revocation record, the package no longer supports the refusal.
  const stripped = reId({ ...clone(pkg), revocations: [] })
  const c = verifyPackage(stripped, w.trustedKeys())
  assert.ok(c.entries[0].errors.includes('admission_revocation_not_supported_by_package'))
})

test('D7 a replayed request shares once', async () => {
  const { w, chainB } = setup()
  const sub = w.request(AGENT_B, chainB, w.share(AUDITOR))
  const first = await w.gateway.request(sub)
  const second = await w.gateway.request(sub)
  assert.equal(first.verdict, 'permit')
  assert.equal(second.replay, true)
  assert.equal(second.result!.receipt_id, first.result!.receipt_id)
  assert.equal(w.repository.exportLog().length, 1)
})

test('D8 an altered signed field fails verification even when the package id is recomputed', async () => {
  const { w, chainB } = setup()
  await w.run('denied', AGENT_B, chainB, w.share(COUNSEL))
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const pkg = verifyOk(w)

  const reason = clone(pkg)
  reason.entries[0].decision_evidence.decision_context.reason = 'within_delegated_authority'
  reason.entries[0].outcome.reason = 'within_delegated_authority'
  const c1 = verifyPackage(reId(reason), w.trustedKeys())
  assert.ok(c1.entries[0].errors.some(x => x.startsWith('decision_')), c1.entries[0].errors.join())

  const verdict = clone(pkg)
  ;(verdict.entries[0].receipts.decision.result as { verdict: string }).verdict = 'permit'
  const c2 = verifyPackage(reId(verdict), w.trustedKeys())
  assert.ok(c2.entries[0].errors.some(x => x.startsWith('decision_')), c2.entries[0].errors.join())

  const share = clone(pkg)
  share.entries[1].repository_result!.share_id = 'shr_0000000000000000'
  const c3 = verifyPackage(reId(share), w.trustedKeys())
  assert.ok(c3.entries[1].errors.includes('share_id_not_signed_effect'))
})

test('D9 the unsigned index cannot disagree with the signed records', async () => {
  const { w, chainB } = setup()
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const pkg = verifyOk(w)

  const recipient = clone(pkg)
  recipient.entries[0].recipient = PRESS
  assert.ok(verifyPackage(reId(recipient), w.trustedKeys()).entries[0].errors.includes('index_recipient_differs'))

  const doc = clone(pkg)
  doc.entries[0].document.version = '4'
  assert.ok(verifyPackage(reId(doc), w.trustedKeys()).entries[0].errors.includes('index_document_differs'))

  const payload = clone(pkg)
  payload.entries[0].action.payload.recipient = PRESS
  assert.ok(verifyPackage(reId(payload), w.trustedKeys()).entries[0].errors.includes('payload_ref_mismatch'))

  const time = clone(pkg)
  time.entries[0].timestamps.decided_at = '2026-11-11T19:00:00.000Z'
  assert.ok(verifyPackage(reId(time), w.trustedKeys()).entries[0].errors.includes('index_timestamps_differs'))

  // An edit without recomputing the id is caught at the package level.
  assert.ok(verifyPackage(recipient, w.trustedKeys()).errors.includes('package_id_mismatch'))
})

test('D10 key rotation: records under the old and new gateway keys both verify, each only inside its window', async () => {
  const { w, chainB } = setup()
  await w.run('before rotation', AGENT_B, chainB, w.share(AUDITOR))
  assert.equal(w.rotateGatewayKey(), 'key-2')
  await w.run('after rotation', AGENT_A, [w.grantToA], w.share(COUNSEL))
  const pkg = verifyOk(w)
  const gatewayKeys = (i: number) => pkg.entries[i].receipt_index.filter(r => r.role !== 'intent').flatMap(r => r.key_ids)
  assert.deepEqual(gatewayKeys(0), ['key-1', 'key-1'])
  assert.deepEqual(gatewayKeys(1), ['key-2', 'key-2'])

  const withoutNew = w.trustedKeys()
  withoutNew.keys = withoutNew.keys.filter(k => k.key_id !== 'key-2')
  const c1 = verifyPackage(pkg, withoutNew)
  assert.ok(c1.errors.some(x => x.startsWith('key_not_trusted:')))
  assert.ok(c1.entries[0].ok, 'old records still verify')
  assert.equal(c1.entries[1].ok, false)

  // A verifier told key-1 retired earlier refuses what key-1 signed after that.
  const early = w.trustedKeys()
  const k1 = early.keys.find(k => k.key_id === 'key-1' && k.signer === pkg.producer)!
  k1.valid_until = pkg.entries[0].timestamps.requested_at
  const c2 = verifyPackage(pkg, early)
  assert.equal(c2.entries[0].ok, false)
  assert.ok(c2.entries[1].ok)
})

test('D11 the repository log is reconciled both ways', async () => {
  const { w, chainB } = setup()
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const pkg = verifyOk(w)
  assert.deepEqual(reconcile(pkg, w.repository.exportLog()), [])

  // A share made in the repository without going through the gateway.
  w.repository.share({ ...w.share(PRESS), correlation_id: 'manual' })
  const f1 = reconcile(pkg, w.repository.exportLog())
  assert.deepEqual(f1.map(f => f.code), ['repository_share_without_aps_permit'])

  // A share the gateway recorded that the repository has no record of.
  assert.deepEqual(reconcile(pkg, []).map(f => f.code), ['recorded_share_not_in_repository_log'])
})

test('D12 the repository call throws: outcome unknown, reported as such', async () => {
  const { w, chainB } = setup({ execute: async () => { throw new Error('connection reset') } })
  const o = await w.run('unknown', AGENT_B, chainB, w.share(AUDITOR))
  assert.equal(o.verdict, 'permit')
  assert.equal(status(o), 'unknown')
  const pkg = verifyOk(w)
  assert.equal(pkg.entries[0].repository_result, null)
  assert.deepEqual(reconcile(pkg, []).map(f => f.code), ['unknown_outcome_no_share_in_log'])
})

test('D13 the package id is stable and the export time is outside it', async () => {
  const { w, chainB } = setup()
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const a = w.exportPackage()
  w.clock.advance(60_000)
  const b = w.exportPackage()
  assert.notEqual(a.exported_at, b.exported_at)
  assert.equal(a.package_id, b.package_id)
})

test('D14 a root the verifier does not trust fails every permit', async () => {
  const { w, chainB } = setup()
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const pkg = verifyOk(w)
  const noRoot = { ...w.trustedKeys(), roots: [] }
  const c = verifyPackage(pkg, noRoot)
  assert.ok(c.entries[0].errors.some(x => x.startsWith('permit_chain_invalid')), c.entries[0].errors.join())
})

test('D15 the verifier and reconciler load no gateway, actor, repository or export code', () => {
  const runtimeImports = (file: string): string[] =>
    [...readFileSync(join(here, file), 'utf8').matchAll(/^import (?!type )[^\n]*from '([^']+)'/gm)].map(m => m[1])
  const allowed = new Set(['node:fs', 'node:crypto', 'agent-passport-system', './document-rules.ts', './package-format.ts', './trust.ts', './verify-package.ts'])
  for (const file of ['verify-package.ts', 'reconcile.ts', 'package-format.ts', 'document-rules.ts', 'trust.ts']) {
    for (const spec of runtimeImports(file)) assert.ok(allowed.has(spec), `${file} imports ${spec}`)
  }
})

test('D16 a gateway with a policy bug signs a permit beyond scope: the offline verifier refuses it', async () => {
  // This gateway checks every request as if the recipient were the auditor.
  const { w, chainB } = setup({ scopeOf: p => shareScope({ ...p, recipient: AUDITOR }) })
  const o = await w.run('buggy permit to press-desk', AGENT_B, chainB, w.share(PRESS))
  assert.equal(o.verdict, 'permit', 'the buggy gateway permits')
  assert.equal(w.repository.exportLog()[0].recipient, PRESS)
  const c = verifyPackage(w.exportPackage(), w.trustedKeys())
  assert.equal(c.entries[0].ok, false)
  assert.ok(c.entries[0].errors.includes('permit_not_in_delegated_scope'), c.entries[0].errors.join())
  assert.ok(c.entries[0].errors.includes('permit_scope_required_mismatch'))
})

test('D17 a backdated record signed with a retired key: accepted as signer-asserted, refused once the key is marked compromised, unless anchored', async () => {
  const { w, chainB } = setup()
  // Before rotation: an approved share whose bytes change before dispatch, so it fails.
  const sub = w.request(AGENT_B, chainB, w.share(AUDITOR))
  const a = w.gateway.authorize(sub)
  w.repository.put(REPOSITORY, DOCUMENT, VERSION, 'Q3 board pack, version 3, edited after approval.')
  const failed = await w.gateway.dispatch(a.action_ref!)
  assert.equal(status(failed), 'failed')
  w.records.push({ label: 'failed share', sub, outcome: failed })
  const original = verifyOk(w)
  const anchoredAt = w.clock.now()
  const rotatedAt = (w.rotateGatewayKey(), w.clock.now())

  // After rotation, someone holding the retired key-1 replaces the failed result with a
  // succeeded one, dated inside key-1's old window, and rebuilds the index.
  const forged = clone(original)
  const e = forged.entries[0]
  const fakeShare = 'shr_forged000000000'
  e.receipts.result = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: forged.producer,
    subject_agent: e.receipts.decision.subject_agent, action_ref: e.entry_id, delegation_ref: e.receipts.decision.delegation_ref,
    decision_ref: e.receipts.decision.decision_ref, issued_at: e.receipts.result!.issued_at, evidence_refs: [],
    result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: sha256Hex(fakeShare), error_code: null } as never,
    prev: e.receipts.decision.receipt_id,
  }, [{ signer: forged.producer, key_id: 'key-1', private_key: w.leakedKey(forged.producer, 'key-1') }])
  e.outcome.result_status = 'succeeded'
  e.repository_result = { system: w.repository.system, share_id: fakeShare }
  e.receipt_index = receiptIndex(e.receipts)
  const forgedPkg = reId(forged)

  // With key-1 only retired, signatures cannot tell the forgery apart. The verifier accepts
  // it and says the times are the signers' own.
  // The genuine package, exported before the rotation, still verifies after it.
  assert.ok(verifyPackage(original, w.trustedKeys()).ok)
  const retired = verifyPackage(forgedPkg, w.trustedKeys())
  assert.ok(retired.ok, JSON.stringify([retired.errors, retired.entries.map(x => x.errors)]))
  assert.deepEqual(retired.time_basis, { kind: 'signer_asserted' })
  // The repository's own log shows no such share.
  assert.deepEqual(reconcile(forgedPkg, w.repository.exportLog()).map(f => f.code), ['recorded_share_not_in_repository_log'])

  // Once the trust source marks key-1 compromised at rotation, nothing it signed is
  // accepted without independent time evidence, the genuine package included.
  const compromised = w.trustedKeys()
  compromised.keys.find(k => k.signer === forged.producer && k.key_id === 'key-1')!.compromised_at = rotatedAt
  const c1 = verifyPackage(forgedPkg, compromised)
  assert.equal(c1.ok, false)
  assert.ok(c1.errors.some(x => x.startsWith('key_compromised_without_prior_anchor:')))
  assert.equal(verifyPackage(original, compromised).ok, false)

  // An anchor recorded after the compromise is no evidence the record came first.
  compromised.anchors = [{ package_id: original.package_id, recorded_at: w.clock.advance(1000), recorded_by: 'content-system' }]
  assert.equal(verifyPackage(original, compromised).ok, false)

  // A simulated trusted anchor says the genuine package existed before the compromise.
  // It restores the genuine package and does nothing for the forgery, whose id differs.
  // The anchor is a plain trusted entry, so this tests the verifier's policy, not an
  // authenticated content-system record.
  compromised.anchors = [{ package_id: original.package_id, recorded_at: anchoredAt, recorded_by: 'content-system' }]
  const genuine = verifyPackage(original, compromised)
  assert.ok(genuine.ok, JSON.stringify(genuine.errors))
  assert.equal(genuine.time_basis.kind, 'anchored')
  assert.equal(verifyPackage(forgedPkg, compromised).ok, false)
})

test('D18 the bytes change while the share is running: the repository refuses, nothing is shared', async () => {
  const holder: { w?: World } = {}
  const { w, chainB } = setup({
    execute: async call => {
      holder.w!.repository.put(REPOSITORY, DOCUMENT, VERSION, 'Q3 board pack, version 3, swapped during the share.')
      return documentShareProfile(holder.w!.repository).execute(call)
    },
  })
  holder.w = w
  const o = await w.run('swapped during share', AGENT_B, chainB, w.share(AUDITOR))
  assert.equal(o.verdict, 'permit')
  assert.equal(o.dispatched, true)
  assert.equal(status(o), 'failed')
  assert.equal(errorCode(o), 'content_digest_mismatch')
  assert.equal(w.repository.exportLog().length, 0)
  const pkg = verifyOk(w)
  assert.deepEqual(reconcile(pkg, w.repository.exportLog()), [])
})

test('D19 completeness is not established: a package with an entry removed still verifies, the repository log shows the gap', async () => {
  const { w, chainB } = setup()
  await w.run('denied', AGENT_B, chainB, w.share(COUNSEL))
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const pkg = verifyOk(w)

  const smaller = reId({ ...clone(pkg), entries: pkg.entries.filter(e => e.label !== 'shared') })
  const c = verifyPackage(smaller, w.trustedKeys())
  assert.ok(c.ok, 'a smaller valid package is accepted, and the verifier does not claim completeness')
  assert.match(VERIFIER_LIMITS, /every action/)
  assert.deepEqual(reconcile(smaller, w.repository.exportLog()).map(f => f.code), ['repository_share_without_aps_permit'])

  // The same entry twice is refused.
  const doubled = reId({ ...clone(pkg), entries: [...pkg.entries, pkg.entries[1]] })
  assert.ok(verifyPackage(doubled, w.trustedKeys()).errors.some(x => x.startsWith('duplicate_entry:')))
})

test('D20 an anchor dated before a record in the package is refused, and does not rescue a compromised key', async () => {
  const { w, chainB } = setup()
  await w.run('shared', AGENT_B, chainB, w.share(AUDITOR))
  const pkg = verifyOk(w)
  const firstRecord = pkg.entries[0].timestamps.requested_at
  const tooEarly = new Date(Date.parse(firstRecord) - 1).toISOString()

  // Key not compromised: the inconsistent anchor alone makes the package fail.
  const trusted = { ...w.trustedKeys(), anchors: [{ package_id: pkg.package_id, recorded_at: tooEarly, recorded_by: 'content-system' }] }
  const c1 = verifyPackage(pkg, trusted)
  assert.equal(c1.ok, false)
  assert.ok(c1.errors.includes('records_dated_after_anchor'))

  // Key compromised later: the early anchor does not make the key's records acceptable.
  const cutoff = w.clock.advance(10_000)
  trusted.keys.find(k => k.signer === pkg.producer && k.key_id === 'key-1')!.compromised_at = cutoff
  const c2 = verifyPackage(pkg, trusted)
  assert.equal(c2.ok, false)
  assert.ok(c2.errors.includes('records_dated_after_anchor'))
  assert.equal(c2.entries[0].ok, false, 'records dated after the anchor are not covered by it')

  // An anchor at or after the last record and before the cutoff is consistent.
  trusted.anchors = [{ package_id: pkg.package_id, recorded_at: new Date(Date.parse(cutoff) - 1).toISOString(), recorded_by: 'content-system' }]
  const c3 = verifyPackage(pkg, trusted)
  assert.ok(c3.ok, JSON.stringify([c3.errors, c3.entries.map(e => e.errors)]))
})

test('D0 the installed engine is the current ../authority-engine/engine.ts', () => {
  // npm install does not refresh a copied local package. A stale copy would test old code.
  const source = readFileSync(new URL('../authority-engine/engine.ts', import.meta.url), 'utf8')
  const installed = readFileSync(new URL('./node_modules/aps-example-authority-engine/engine.ts', import.meta.url), 'utf8')
  assert.ok(source === installed, 'node_modules has an old copy of the engine. Run npm ci in this folder.')
})
