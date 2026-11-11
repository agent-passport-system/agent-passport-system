// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Compare a verified evidence package with the content repository's own share log.
//
//   node --import tsx reconcile.ts out/evidence-package.json out/trusted-keys.json out/repository-log.json
//
// The evidence package says what the gateway authorized and what the repository reported
// back to it. The repository's log says what the repository did. This checks the two
// agree, in both directions:
//   - every share the gateway recorded as succeeded is in the repository log, for the
//     same document version, digest and recipient, under the same correlation id
//   - every share in the repository log has a matching APS permit and succeeded result.
//     A share with none is a share that did not go through this gateway.
// An outcome the gateway recorded as unknown is reported, with whatever the log shows.
//
// The repository log is evidence from a different system, so how far it can be trusted
// is a property of that system and how the log was obtained, not of APS.

import { readFileSync } from 'node:fs'
import type { EvidencePackage } from './package-format.ts'
import type { ShareLogEntry } from './repository.ts'
import type { TrustedKeys } from './trust.ts'
import { verifyPackage } from './verify-package.ts'

export interface Finding { kind: 'error' | 'note'; code: string; ref: string }

export function reconcile(pkg: EvidencePackage, log: readonly ShareLogEntry[]): Finding[] {
  const findings: Finding[] = []
  const byShare = new Map(log.map(s => [s.share_id, s]))
  const matched = new Set<string>()

  for (const e of pkg.entries) {
    const p = e.action.payload
    if (e.outcome.result_status === 'succeeded' && e.repository_result) {
      const s = byShare.get(e.repository_result.share_id)
      if (!s) { findings.push({ kind: 'error', code: 'recorded_share_not_in_repository_log', ref: e.entry_id }); continue }
      matched.add(s.share_id)
      const fieldsMatch = s.repository === p.repository && s.document_id === p.document_id && s.version === p.version &&
        s.content_digest === p.content_digest && s.recipient === p.recipient
      if (!fieldsMatch) findings.push({ kind: 'error', code: 'repository_share_differs_from_authorized_action', ref: e.entry_id })
      if (s.correlation_id !== e.entry_id) findings.push({ kind: 'error', code: 'repository_correlation_id_differs', ref: e.entry_id })
    } else if (e.outcome.result_status === 'unknown') {
      const s = log.find(x => x.correlation_id === e.entry_id)
      if (s) matched.add(s.share_id)
      findings.push({ kind: 'note', code: s ? 'unknown_outcome_repository_shows_share' : 'unknown_outcome_no_share_in_log', ref: e.entry_id })
    }
  }
  for (const s of log) {
    if (!matched.has(s.share_id)) findings.push({ kind: 'error', code: 'repository_share_without_aps_permit', ref: s.share_id })
  }
  return findings
}

function main(packagePath: string, keysPath: string, logPath: string): number {
  const pkg = JSON.parse(readFileSync(packagePath, 'utf8')) as EvidencePackage
  const trusted = JSON.parse(readFileSync(keysPath, 'utf8')) as TrustedKeys
  const log = JSON.parse(readFileSync(logPath, 'utf8')) as ShareLogEntry[]
  const v = verifyPackage(pkg, trusted)
  if (!v.ok) {
    console.log('evidence package did not verify; run verify-package.ts for details')
    return 1
  }
  const findings = reconcile(pkg, log)
  for (const f of findings) console.log(`${f.kind.toUpperCase().padEnd(5)} ${f.code} ${f.ref}`)
  const errors = findings.filter(f => f.kind === 'error').length
  const recorded = pkg.entries.filter(e => e.outcome.result_status === 'succeeded').length
  console.log(`${recorded} recorded shares, ${log.length} shares in the repository log, ${errors} discrepancies`)
  return errors === 0 ? 0 : 1
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [p, k, l] = process.argv.slice(2)
  if (!p || !k || !l) {
    console.error('usage: reconcile.ts <evidence-package.json> <trusted-keys.json> <repository-log.json>')
    process.exit(2)
  }
  process.exit(main(p, k, l))
}
