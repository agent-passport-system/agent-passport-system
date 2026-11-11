// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The walkthrough. Prints each step and writes every signed record to out/ so that
// `npm run verify` can check them with public keys only.

import { mkdirSync, writeFileSync } from 'node:fs'
import { AGENT_A, AGENT_B, GATEWAY, createWorld, usd } from './actors.ts'
import type { PaymentOutcome, PaymentSubmission } from './gateway.ts'
import type { RecordBundle } from './verify.ts'

const dollars = (cents: string) => `$${(Number(cents) / 100).toFixed(2)}`
const w = createWorld()
const bundles: RecordBundle[] = []

function keep(label: string, sub: PaymentSubmission, o: PaymentOutcome): void {
  if (o.decision && o.evidence) {
    bundles.push({ label, input: sub.input, payload: sub.payload, intent: sub.intent,
      decision: o.decision, evidence: o.evidence, result: o.result })
  }
}

function line(step: string, outcome: string): void {
  console.log(`${step.padEnd(52)} ${outcome}`)
}

async function pay(label: string, agent: string, chain: Parameters<typeof w.request>[1], cents: number): Promise<PaymentOutcome> {
  const sub = w.request(agent, chain, usd(cents))
  const o = await w.gateway.pay(sub)
  keep(label, sub, o)
  line(label, o.verdict === 'permit' ? `PAID (${(o.result!.result as { status: string }).status})` : `DENIED: ${o.reason}`)
  return o
}

console.log('A person gives Agent A permission to spend $100 at acme-books, USD only, for one hour.\n')

try {
  w.delegate(w.grantToA, AGENT_B, '15000')
} catch (e) {
  line('Agent A tries to give Agent B $150', `REFUSED at issue: ${(e as Error).message.match(/\(([A-Z_]+)\)/)?.[1]}`)
}
const b = w.delegate(w.grantToA, AGENT_B, '3000')
line('Agent A gives Agent B $30', 'ISSUED')
const chainB = [w.grantToA, b]

await pay('Agent B spends $40', AGENT_B, chainB, 4000)
await pay('Agent B spends $20', AGENT_B, chainB, 2000)

const s1 = w.request(AGENT_B, chainB, usd(800))
const s2 = w.request(AGENT_B, chainB, usd(800))
const [o1, o2] = await Promise.all([w.gateway.pay(s1), w.gateway.pay(s2)])
keep('Agent B sends two $8 payments at once (first)', s1, o1)
keep('Agent B sends two $8 payments at once (second)', s2, o2)
line('Agent B sends two $8 payments at once, $10 left',
  [o1, o2].map(o => (o.verdict === 'permit' ? 'one PAID' : `one DENIED: ${o.reason}`)).join(', '))

await pay('Agent A spends $75 (B already spent $28 of the $100)', AGENT_A, [w.grantToA], 7500)

const rev = w.revokeRoot()
line('The person revokes Agent A\'s permission', rev.recorded ? 'RECORDED' : `NOT RECORDED: ${rev.reason}`)
await pay('Agent B tries to spend $5', AGENT_B, chainB, 500)

const ba = w.gateway.budget(w.grantToA)!
const bb = w.gateway.budget(b)!
console.log(`\nSpent under the person's $100 grant: ${dollars(ba.committed)}. Under Agent B's $30: ${dollars(bb.committed)}.`)
console.log(`Charges the mock payment executor received: ${w.charges.length}.`)

mkdirSync('out', { recursive: true })
writeFileSync('out/receipts.json', JSON.stringify({ gateway: GATEWAY, bundles }, null, 2) + '\n')
writeFileSync('out/public-keys.json', JSON.stringify(w.publicKeys(), null, 2) + '\n')
console.log(`\nWrote ${bundles.length} signed record bundles to out/receipts.json. Check them with: npm run verify`)
