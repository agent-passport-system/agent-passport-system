// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Build a portable evidence package from the gateway's outcomes. Signed records are copied
// as they are. Nothing here signs anything.

import type { AuthorityDelegationV1 } from 'agent-passport-system'
import type { Outcome, Submission } from 'aps-example-authority-engine/engine.ts'
import type { DocumentSharePayload } from './document-rules.ts'
import { EVIDENCE_PACKAGE_PROFILE, computePackageId, receiptIndex } from './package-format.ts'
import type { EvidenceEntry, EvidencePackage } from './package-format.ts'
import { keyFingerprint } from './trust.ts'
import type { KeyEntry } from './trust.ts'

const plain = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T

export interface ExportInput {
  producer: string
  exportedAt: string
  repositorySystem: string
  /** Every key the producer knows, public part only. */
  keys: readonly KeyEntry[]
  delegations: readonly AuthorityDelegationV1[]
  revocations: readonly unknown[]
  records: readonly { label: string; sub: Submission<DocumentSharePayload>; outcome: Outcome }[]
}

export function buildEvidencePackage(x: ExportInput): EvidencePackage {
  const entries: EvidenceEntry[] = []
  for (const { label, sub, outcome } of x.records) {
    // A request refused before its intent verified has no signed decision to export.
    if (!outcome.decision || !outcome.evidence || outcome.action_ref === null) continue
    const result = outcome.result ?? null
    const status = (result?.result as { status?: EvidenceEntry['outcome']['result_status'] } | undefined)?.status ?? null
    const receipts = { intent: sub.intent, decision: outcome.decision, result }
    const p = sub.payload
    entries.push(plain({
      entry_id: outcome.action_ref,
      label,
      action: { input: sub.input, payload: p },
      document: { repository: p.repository, document_id: p.document_id, version: p.version, content_digest: p.content_digest },
      recipient: p.recipient,
      outcome: { verdict: outcome.verdict, reason: outcome.reason, result_status: status },
      delegation_chain: outcome.evidence.authority_state.chain,
      receipts,
      receipt_index: receiptIndex(receipts),
      decision_evidence: outcome.evidence,
      timestamps: {
        requested_at: sub.input.issued_at,
        decided_at: outcome.evidence.decision_context.decided_at,
        result_observed_at: result?.issued_at ?? null,
      },
      repository_result: status === 'succeeded' && outcome.effect_id
        ? { system: x.repositorySystem, share_id: outcome.effect_id }
        : null,
    }))
  }

  // Only the keys that actually signed something in this package.
  const used = new Set<string>()
  const mark = (signer: string, keyId: string) => used.add(`${signer}\u0000${keyId}`)
  for (const e of entries) {
    for (const r of [e.receipts.intent, e.receipts.decision, e.receipts.result]) {
      for (const s of r?.signatures ?? []) mark(s.signer, s.key_id)
    }
  }
  for (const d of x.delegations) mark(d.issuer, d.verification_method.slice(d.issuer.length + 1))
  for (const r of x.revocations as { revoker: string; verification_method: string }[]) {
    mark(r.revoker, r.verification_method.slice(r.revoker.length + 1))
  }
  const key_resolution = x.keys
    .filter(k => used.has(`${k.signer}\u0000${k.key_id}`))
    .map(k => ({ ...k, fingerprint: keyFingerprint(k.public_key) }))

  const body: Omit<EvidencePackage, 'package_id' | 'exported_at'> = {
    profile: EVIDENCE_PACKAGE_PROFILE,
    producer: x.producer,
    key_resolution: plain(key_resolution),
    delegations: plain([...x.delegations]),
    revocations: plain([...x.revocations]),
    entries,
  }
  return { ...body, package_id: computePackageId(body), exported_at: x.exportedAt }
}
