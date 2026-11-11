// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Offline check of an exported evidence package, with keys the verifier trusts and
// nothing else. It never contacts or imports the gateway.
//
//   node --import tsx verify-package.ts out/evidence-package.json out/trusted-keys.json
//
// Package checks: the profile is known, package_id recomputes, every key the package
// names matches a trusted key exactly, every revocation the package carries verifies
// against the delegation it names.
//
// Entry checks, for every exported action:
//   - the action reference recomputes from the request and payload, and is the entry id
//   - the agent's intent is signed by the agent under a trusted key valid at its time
//   - the gateway's decision is signed by the gateway, its decision_ref binds the exported
//     authority state, policy input, context and output, and it follows the intent
//   - the result, when present, is signed by the gateway, binds the same decision and
//     follows it, and a reported share id hashes to the signed effect_ref
//   - every index field (document, recipient, outcome, chain, receipt index, timestamps)
//     equals what the signed content says
//   - for a permit: the delegation chain in the package verifies at decision time under
//     trusted keys and a trusted root, the leaf is the agent's, and it covers the scope
//     recomputed from the signed payload
//   - for a refusal citing revocation: the package holds a verified revocation that took
//     effect at or before that time
//
// Record times. Every timestamp in the package is asserted by the party that signed it.
// A valid signature under a retired key shows the key signed the record, not when. Unless
// the trusted input holds an anchor for this package, time_basis is "signer_asserted". An
// anchor is trusted evidence that the package existed by a time. It does not establish
// when each record was signed or when a key was first compromised. A key the trusted file
// marks compromised is refused unless the package is anchored before the declared cutoff,
// and an anchored package with a record dated after its anchor is refused.
//
// What this does not establish: that the package holds every action the gateway decided
// (a package with an entry removed and its id recomputed still verifies), that an approval
// was used exactly once, or that the repository performed a share. reconcile.ts compares
// the package with the repository's own log, which is only as complete and truthful as
// that log. It also does not show that no revocation existed which the package does not
// carry, or that the gateway's clock was right.

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import {
  canonicalizeJCS, computeActionRefV2, computePayloadRefV1, scopeGrantCovers,
  verifyAuthorityDelegationChain, verifyAuthorityRevocation, verifyReceiptV1, verifyReceiptWithDecisionV1,
} from 'agent-passport-system'
import type { AuthorityDelegationV1 } from 'agent-passport-system'
import { DOCUMENT_SHARE_ACTION_TYPE, shareScope, shareTarget, validateSharePayload } from './document-rules.ts'
import { EVIDENCE_PACKAGE_PROFILE, computePackageId, receiptIndex } from './package-format.ts'
import type { EvidenceEntry, EvidencePackage } from './package-format.ts'
import { beforeCompromise, keyFingerprint, receiptKeyResolver, verificationKeyResolver } from './trust.ts'
import type { TrustedKeys } from './trust.ts'

export interface EntryCheck { entry_id: string; label: string; ok: boolean; errors: string[] }
export interface PackageCheck {
  ok: boolean
  package_id: string
  /** "anchored" when the verifier holds a content-system record of this package from before
   *  the stated time, otherwise "signer_asserted". */
  time_basis: { kind: 'anchored'; recorded_at: string; recorded_by: string } | { kind: 'signer_asserted' }
  errors: string[]
  entries: EntryCheck[]
}

export const VERIFIER_LIMITS =
  'Not established: that this package holds every action, that an approval was used exactly once, ' +
  'or that the repository performed a share.'

const same = (a: unknown, b: unknown): boolean => {
  try {
    return canonicalizeJCS(JSON.parse(JSON.stringify(a ?? null))) === canonicalizeJCS(JSON.parse(JSON.stringify(b ?? null)))
  } catch {
    return false
  }
}
const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')

export function verifyPackage(pkg: EvidencePackage, trusted: TrustedKeys): PackageCheck {
  const errors: string[] = []
  if (pkg?.profile !== EVIDENCE_PACKAGE_PROFILE) errors.push('package_profile_unknown')
  let packageId = ''
  try {
    packageId = computePackageId(pkg)
  } catch {
    errors.push('package_not_canonicalizable')
  }
  if (pkg.package_id !== packageId) errors.push('package_id_mismatch')

  // An anchor counts only for the id recomputed from the content, never the claimed one.
  const anchor = (trusted.anchors ?? [])
    .filter(a => packageId !== '' && a.package_id === packageId && Number.isFinite(Date.parse(a.recorded_at)))
    .sort((a, b) => Date.parse(a.recorded_at) - Date.parse(b.recorded_at))[0]
  const time_basis: PackageCheck['time_basis'] = anchor
    ? { kind: 'anchored', recorded_at: anchor.recorded_at, recorded_by: anchor.recorded_by }
    : { kind: 'signer_asserted' }
  const resolveReceipt = receiptKeyResolver(trusted.keys, anchor?.recorded_at)
  const resolveMethod = verificationKeyResolver(trusted.keys, anchor?.recorded_at)

  // A record dated after the anchor states a time that conflicts with the anchor's
  // evidence that the package already existed. Refuse the conflict.
  if (anchor) {
    const at = Date.parse(anchor.recorded_at)
    const times: string[] = []
    for (const e of pkg.entries ?? []) {
      for (const r of [e.receipts?.intent, e.receipts?.decision, e.receipts?.result]) if (r) times.push(r.issued_at)
    }
    for (const d of pkg.delegations ?? []) times.push(d.issued_at)
    for (const r of (pkg.revocations ?? []) as { revoked_at?: string }[]) if (r?.revoked_at) times.push(r.revoked_at)
    if (times.some(t => !(Date.parse(t) <= at))) errors.push('records_dated_after_anchor')
  }

  const seen = new Set<string>()
  for (const e of pkg.entries ?? []) {
    if (seen.has(e.entry_id)) errors.push(`duplicate_entry:${e.entry_id}`)
    seen.add(e.entry_id)
  }

  for (const k of pkg.key_resolution ?? []) {
    const name = `${k.signer}#${k.key_id}`
    if (k.fingerprint !== keyFingerprint(k.public_key)) errors.push(`key_fingerprint_mismatch:${name}`)
    const t = trusted.keys.find(x => x.signer === k.signer && x.key_id === k.key_id)
    // The windows in the package are what the producer knew at export. A key retired
    // later legitimately differs, so only the trusted windows are used.
    if (!t || t.public_key !== k.public_key) errors.push(`key_not_trusted:${name}`)
    else if (!beforeCompromise(t, t.valid_from, anchor?.recorded_at)) errors.push(`key_compromised_without_prior_anchor:${name}`)
  }

  const byId = new Map<string, AuthorityDelegationV1>()
  for (const d of pkg.delegations ?? []) byId.set(d.delegation_id, d)

  // delegation_id -> earliest revoked_at among verified revocations.
  const revokedAt = new Map<string, string>()
  for (const r of (pkg.revocations ?? []) as { delegation_id?: string; revoked_at?: string }[]) {
    const target = typeof r?.delegation_id === 'string' ? byId.get(r.delegation_id) : undefined
    if (!target) { errors.push('revocation_target_missing'); continue }
    const v = verifyAuthorityRevocation(r, target, { resolveVerificationKey: resolveMethod })
    if (!v.valid) { errors.push(`revocation_${v.state}:${v.failures.map(f => f.code).join(',')}`); continue }
    const prior = revokedAt.get(target.delegation_id)
    if (!prior || Date.parse(r.revoked_at!) < Date.parse(prior)) revokedAt.set(target.delegation_id, r.revoked_at!)
  }
  const revokedBy = (id: string, at: string): boolean => {
    const t = revokedAt.get(id)
    return t !== undefined && Date.parse(t) <= Date.parse(at)
  }

  const entries = (pkg.entries ?? []).map(e => verifyEntry(e, pkg, trusted, resolveReceipt, resolveMethod, byId, revokedBy))
  return { ok: errors.length === 0 && entries.every(e => e.ok), package_id: pkg.package_id, time_basis, errors, entries }
}

function verifyEntry(
  e: EvidenceEntry, pkg: EvidencePackage, trusted: TrustedKeys,
  resolveReceipt: ReturnType<typeof receiptKeyResolver>, resolveMethod: ReturnType<typeof verificationKeyResolver>,
  byId: Map<string, AuthorityDelegationV1>, revokedBy: (id: string, at: string) => boolean,
): EntryCheck {
  const errors: string[] = []
  const gateway = pkg.producer
  const { input, payload } = e.action ?? ({} as EvidenceEntry['action'])
  const { intent, decision, result } = e.receipts ?? ({} as EvidenceEntry['receipts'])
  const ev = e.decision_evidence

  // The action.
  let actionRef = ''
  try {
    if (computePayloadRefV1(payload as never) !== input.payload_ref) errors.push('payload_ref_mismatch')
    actionRef = computeActionRefV2(input)
  } catch {
    errors.push('action_ref_input_invalid')
  }
  if (e.entry_id !== actionRef) errors.push('entry_id_not_action_ref')
  for (const [name, r] of [['intent', intent], ['decision', decision], ['result', result]] as const) {
    if (r && r.action_ref !== actionRef) errors.push(`${name}_action_ref_mismatch`)
  }

  // Signatures, under trusted keys valid at each record's own time.
  const iv = verifyReceiptV1(intent, resolveReceipt, { expectedReceiptType: 'aps:action-intent:v1' })
  if (iv.status !== 'valid') errors.push(`intent_${iv.status}`)
  if (intent?.issuer !== input?.agent_id || intent?.subject_agent !== input?.agent_id) errors.push('intent_not_from_agent')

  if (decision?.issuer !== gateway) errors.push('decision_not_from_producer')
  const dv = verifyReceiptWithDecisionV1(decision, ev as never, resolveReceipt, {
    expectedReceiptType: 'aps:policy-decision:v1', boundaryIdentity: gateway,
  })
  if (dv.status !== 'valid') errors.push(`decision_${dv.status}`, ...dv.errors)
  if (decision?.prev !== intent?.receipt_id) errors.push('decision_does_not_follow_intent')

  const verdict = (decision?.result as { verdict?: string } | undefined)?.verdict
  const status = (result?.result as { status?: string } | undefined)?.status ?? null
  if (result) {
    if (result.issuer !== gateway) errors.push('result_not_from_producer')
    const rv = verifyReceiptWithDecisionV1(result, ev as never, resolveReceipt, {
      expectedReceiptType: 'aps:action-result:v1', boundaryIdentity: gateway, predecessor: decision,
    })
    if (rv.status !== 'valid') errors.push(`result_${rv.status}`, ...rv.errors)
    if (verdict !== 'permit') errors.push('result_without_permit')
  }

  // The repository's reported share id, bound to the signed effect_ref.
  const effectRef = (result?.result as { effect_ref?: string | null } | undefined)?.effect_ref ?? null
  if (status === 'succeeded') {
    if (!e.repository_result) errors.push('repository_result_missing')
    else if (sha256Hex(e.repository_result.share_id) !== effectRef) errors.push('share_id_not_signed_effect')
  } else if (e.repository_result !== null) {
    errors.push('repository_result_without_success')
  }

  // Index fields equal signed content.
  const payloadInvalid = validateSharePayload(payload)
  if (payloadInvalid) errors.push(`payload_${payloadInvalid}`)
  else {
    const { repository, document_id, version, content_digest } = payload
    if (!same(e.document, { repository, document_id, version, content_digest })) errors.push('index_document_differs')
    if (e.recipient !== payload.recipient) errors.push('index_recipient_differs')
  }
  if (!same(e.outcome, { verdict, reason: ev?.decision_context?.reason, result_status: status })) errors.push('index_outcome_differs')
  if (!same(e.delegation_chain, ev?.authority_state?.chain)) errors.push('index_chain_differs')
  if (!same(e.receipt_index, receiptIndex({ intent, decision, result: result ?? null }))) errors.push('index_receipts_differs')
  const decidedAt = ev?.decision_context?.decided_at
  if (!same(e.timestamps, { requested_at: input?.issued_at, decided_at: decision?.issued_at, result_observed_at: result?.issued_at ?? null })) {
    errors.push('index_timestamps_differs')
  }
  if (decidedAt !== decision?.issued_at) errors.push('decided_at_not_decision_time')

  // Authority, re-derived from the package for what it permitted or refused for revocation.
  const chain = (e.delegation_chain ?? []).map(id => byId.get(id))
  const reason = ev?.decision_context?.reason ?? ''
  const errorCode = (result?.result as { error_code?: string | null } | undefined)?.error_code ?? ''
  if (chain.some(d => d === undefined)) {
    if (verdict === 'permit' || reason.includes('REVOKED')) errors.push('delegation_missing_from_package')
  } else if (decidedAt) {
    const full = chain as AuthorityDelegationV1[]
    const at = (t: string) => verifyAuthorityDelegationChain(full, {
      now: t,
      resolveVerificationKey: resolveMethod,
      trustRoot: root => trusted.roots.includes(root.issuer) && root.verification_method.startsWith(root.issuer + '#'),
      resolveRevocation: d => (revokedBy(d.delegation_id, t) ? 'revoked' : 'active'),
    })
    const revokedAtTime = (t: string) => at(t).failures.some(f => f.code === 'REVOKED')
    if (verdict === 'permit') {
      const av = at(decidedAt)
      if (av.state !== 'valid') errors.push(`permit_chain_${av.state}:${[...new Set(av.failures.map(f => f.code))].join(',')}`)
      const leaf = full.at(-1)!
      if (leaf.subject !== input.agent_id) errors.push('permit_leaf_not_agent')
      if (intent.delegation_ref !== leaf.delegation_id) errors.push('permit_intent_delegation_ref_mismatch')
      if (!payloadInvalid) {
        if (input.action_type !== DOCUMENT_SHARE_ACTION_TYPE || input.target !== shareTarget(payload)) errors.push('permit_target_mismatch')
        const scope = shareScope(payload)
        if (input.scope_required.length !== 1 || input.scope_required[0] !== scope) errors.push('permit_scope_required_mismatch')
        if (!leaf.authority.scope.grants.some(g => scopeGrantCovers(g, scope))) errors.push('permit_not_in_delegated_scope')
      }
    }
    if (reason.includes('REVOKED') && !revokedAtTime(decidedAt)) errors.push('revocation_claim_not_supported_by_package')
    if (result && errorCode.includes('REVOKED') && !revokedAtTime(result.issued_at)) {
      errors.push('admission_revocation_not_supported_by_package')
    }
  }

  return { entry_id: e.entry_id, label: e.label, ok: errors.length === 0, errors }
}

function main(packagePath: string, keysPath: string): number {
  const pkg = JSON.parse(readFileSync(packagePath, 'utf8')) as EvidencePackage
  const trusted = JSON.parse(readFileSync(keysPath, 'utf8')) as TrustedKeys
  const c = verifyPackage(pkg, trusted)
  console.log(`package ${c.package_id}`)
  for (const err of c.errors) console.log(`PACKAGE ERROR ${err}`)
  for (const e of c.entries) console.log(`${e.ok ? 'VALID  ' : 'INVALID'} ${e.label}${e.ok ? '' : ' :: ' + e.errors.join(', ')}`)
  const good = c.entries.filter(e => e.ok).length
  console.log(`${good} of ${c.entries.length} entries verified, ${c.errors.length} package errors`)
  console.log(c.time_basis.kind === 'anchored'
    ? `Record times: trusted evidence from ${c.time_basis.recorded_by} that this package existed by ${c.time_basis.recorded_at}. Not evidence of when each record was signed.`
    : 'Record times: as asserted by their signers. No independent anchor was supplied.')
  console.log(VERIFIER_LIMITS)
  return c.ok ? 0 : 1
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [p, k] = process.argv.slice(2)
  if (!p || !k) {
    console.error('usage: verify-package.ts <evidence-package.json> <trusted-keys.json>')
    process.exit(2)
  }
  process.exit(main(p, k))
}
