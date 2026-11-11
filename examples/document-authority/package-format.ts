// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The portable evidence package: its types, its id and its receipt index.
//
// The package carries the original signed records unchanged and an unsigned index over
// them. Every index field is something the verifier recomputes from signed content and
// rejects on disagreement, so the index can help a content system file and search the
// package without being trusted. package_id names the package and detects accidental
// change. It is not a signature.

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from 'agent-passport-system'
import type { ActionReferenceInputV2, AuthorityDelegationV1, ReceiptV1 } from 'agent-passport-system'
import type { DecisionEvidence } from 'aps-example-authority-engine/engine.ts'
import type { DocumentSharePayload } from './document-rules.ts'
import type { KeyEntry } from './trust.ts'

export const EVIDENCE_PACKAGE_PROFILE = 'aps-example-evidence-package-v0'

export interface ReceiptIndexEntry {
  role: 'intent' | 'decision' | 'result'
  receipt_id: string
  receipt_type: string
  issuer: string
  key_ids: string[]
  issued_at: string
}

export interface EvidenceEntry {
  /** The action reference. Stable: the same request always gets the same id. */
  entry_id: string
  label: string
  action: { input: ActionReferenceInputV2; payload: DocumentSharePayload }
  /** Index: the exact document version the action concerned. */
  document: { repository: string; document_id: string; version: string; content_digest: string }
  recipient: string
  outcome: { verdict: 'permit' | 'deny'; reason: string; result_status: 'succeeded' | 'failed' | 'unknown' | null }
  /** Delegation ids from the root grant to the acting agent. */
  delegation_chain: string[]
  receipts: { intent: ReceiptV1; decision: ReceiptV1; result: ReceiptV1 | null }
  receipt_index: ReceiptIndexEntry[]
  decision_evidence: DecisionEvidence
  /** requested_at: the agent's signed request time. decided_at: the gateway's decision.
   *  result_observed_at: when the gateway recorded what the repository reported. None of
   *  these is the repository's own time of the share, which is in its own log. */
  timestamps: { requested_at: string; decided_at: string; result_observed_at: string | null }
  /** What the repository reported to the gateway. The result record signs SHA-256 of
   *  share_id as effect_ref. Whether the share happened is reconcile.ts's question. */
  repository_result: { system: string; share_id: string } | null
}

export interface EvidencePackage {
  profile: typeof EVIDENCE_PACKAGE_PROFILE
  /** 'sha256:' over JCS of every member except package_id and exported_at. */
  package_id: string
  exported_at: string
  producer: string
  /** Which key signed what, with the windows the producer knew at export. The verifier
   *  checks each key against its own trusted keys and uses only the trusted windows. */
  key_resolution: (KeyEntry & { fingerprint: string })[]
  delegations: AuthorityDelegationV1[]
  /** Signed revocations the producer recorded. */
  revocations: unknown[]
  entries: EvidenceEntry[]
}

const plain = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T

/** The receipt index, derived from the receipts themselves. */
export function receiptIndex(receipts: EvidenceEntry['receipts']): ReceiptIndexEntry[] {
  const rows: [ReceiptIndexEntry['role'], ReceiptV1 | null][] = [
    ['intent', receipts.intent], ['decision', receipts.decision], ['result', receipts.result],
  ]
  return rows.filter((r): r is [ReceiptIndexEntry['role'], ReceiptV1] => r[1] !== null).map(([role, r]) => ({
    role, receipt_id: r.receipt_id, receipt_type: r.receipt_type, issuer: r.issuer,
    key_ids: r.signatures.map(s => s.key_id), issued_at: r.issued_at,
  }))
}

/** package_id over everything except package_id and exported_at. */
export function computePackageId(pkg: Omit<EvidencePackage, 'package_id' | 'exported_at'>): string {
  const { profile, producer, key_resolution, delegations, revocations, entries } = pkg
  const body = canonicalizeJCS(plain({ profile, producer, key_resolution, delegations, revocations, entries }) as never)
  return 'sha256:' + createHash('sha256').update(body, 'utf8').digest('hex')
}
