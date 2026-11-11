// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The walkthrough. Prints each step, then writes three files to out/:
//   evidence-package.json  the portable evidence package
//   trusted-keys.json      the public keys a verifier is given separately
//   repository-log.json    the repository's own share log
// Check them with `npm run verify` and `npm run reconcile`, which read only those files.

import { mkdirSync, writeFileSync } from 'node:fs'
import { AGENT_A, AGENT_B, AUDITOR, COUNSEL, PRESS, createWorld } from './actors.ts'
import { shareScope } from './document-rules.ts'
import type { Outcome } from 'aps-example-authority-engine/engine.ts'

const w = createWorld()
const line = (step: string, outcome: string) => console.log(`${step.padEnd(58)} ${outcome}`)
const show = (o: Outcome) => o.verdict === 'permit'
  ? `SHARED (${(o.result!.result as { status: string }).status})`
  : `REFUSED: ${o.reason}`

console.log('1. A person allows Agent A, for one hour, to share version 3 of the Q3 board pack')
console.log(`   (sha256 ${w.digest.slice(7, 19)}...) with ${AUDITOR} or ${COUNSEL}, and nobody else.\n`)

try {
  w.delegate(w.grantToA, AGENT_B, [shareScope(w.share(PRESS))])
} catch (e) {
  line('2. Agent A tries to let Agent B share it with press-desk', `REFUSED at issue: ${(e as Error).message.match(/\(([A-Z_]+)\)/)?.[1]}`)
}
const b = w.delegate(w.grantToA, AGENT_B, [shareScope(w.share(AUDITOR))])
line('2. Agent A lets Agent B share it with auditor-llp only', 'ISSUED')
const chainB = [w.grantToA, b]

line('3. Agent B tries outside-counsel (A may, B may not)', show(await w.run('B to outside-counsel', AGENT_B, chainB, w.share(COUNSEL))))
line('3. Agent B tries press-desk', show(await w.run('B to press-desk', AGENT_B, chainB, w.share(PRESS))))
line('3. Agent B tries version 4 for auditor-llp', show(await w.run('B, version 4', AGENT_B, chainB, w.share(AUDITOR, { version: '4' }))))

line('4. Agent B shares version 3 with auditor-llp', show(await w.run('B to auditor-llp', AGENT_B, chainB, w.share(AUDITOR))))
line('   Agent A shares version 3 with outside-counsel', show(await w.run('A to outside-counsel', AGENT_A, [w.grantToA], w.share(COUNSEL))))

line('   The gateway rotates its signing key', `now signing with ${w.rotateGatewayKey()}`)
const rev = w.revokeRoot()
line('5. The person withdraws Agent A\'s permission', rev.recorded ? 'RECORDED' : `NOT RECORDED: ${rev.reason}`)
line('5. Agent B tries auditor-llp again', show(await w.run('B to auditor-llp after revocation', AGENT_B, chainB, w.share(AUDITOR))))

const pkg = w.exportPackage()
const log = w.repository.exportLog()
console.log(`\nShares in the repository's own log: ${log.length}.`)

mkdirSync('out', { recursive: true })
writeFileSync('out/evidence-package.json', JSON.stringify(pkg, null, 2) + '\n')
writeFileSync('out/trusted-keys.json', JSON.stringify(w.trustedKeys(), null, 2) + '\n')
writeFileSync('out/repository-log.json', JSON.stringify(log, null, 2) + '\n')
console.log(`6. Exported ${pkg.entries.length} entries as ${pkg.package_id.slice(0, 19)}... to out/evidence-package.json.`)
console.log('   Check them offline with: npm run verify && npm run reconcile')
