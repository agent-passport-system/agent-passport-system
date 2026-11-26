// J01 offline test fixture for the bounded refund sandbox
// (aeoess/agent-governance-vocabulary#193, contract refund-sandbox-contract/review-2026-10-23,
// section 3). Shared profile constants and helpers for producer.ts, verify.ts and
// adversarial.ts. Written for this fixture, not SDK code.
//
// TEST FIXTURE ONLY. Every key here is derived from a stated test seed. Anyone holding the
// seed can sign as these test identities, which is the point: the bundle is reproducible
// byte for byte. Nothing here connects to a payment system.
import { createHash } from 'node:crypto'
import { publicKeyFromPrivate } from '../../../dist/src/index.js'

export const CONTRACT_REVISION = 'review-2026-10-23'
export const SDK_TAG = 'v8.0.1'
export const SDK_COMMIT = '56e7b293c6cce232eff0b2891ddf7af85bfe01e3'

// Section 3 profile values. Proposed test-profile choices, not general APS requirements.
export const ACTION_TYPE = 'refund'
export const SCOPE_REQUIRED = ['payments:refund'] as const
export const SUBJECT = 'did:example:refund-worker'
export const BOUNDARY = 'did:example:refund-approval-boundary'
export const refundTarget = (paymentId: string): string =>
  `https://payments.operator.example/v1/payments/${paymentId}/refunds`
export const PAYMENT_ID_PATTERN = /^[A-Za-z0-9_-]+$/

// The exact refund tuple, as the bytes Fabio's request writes it. Member order is the
// request's, not JCS order; payload_ref is computed over JCS and does not depend on it.
export const PAYLOAD_BYTES = '{"payment_id":"pay_A","amount_minor":4000,"currency":"EUR"}'

export const INPUT_FILES = [
  'inputs/aps-intent.json',
  'inputs/aps-approval.json',
  'inputs/aps-action.json',
  'inputs/aps-payload.json',
  'inputs/decision-evidence.json',
  'trust/aps-consumption.json',
] as const

export const BOUNDARY_KEY_ID = 'j01-test-boundary-k1'
export const WORKER_KEY_ID = 'j01-test-worker-k1'

export const sha256Hex = (data: string | Uint8Array): string =>
  createHash('sha256').update(data).digest('hex')
export const fileRef = (bytes: Uint8Array): string => 'sha256:' + sha256Hex(bytes)

/** Test key derivation. Ed25519 accepts any 32-byte seed as a private key, so the private
 *  key is SHA-256 over a tagged seed and role. Same seed, same keys, same signatures
 *  (Ed25519 signing is deterministic), same bundle bytes. */
export const KEY_DERIVATION = 'sha256("APS-J01-193-TEST-KEY-V1" || 0x00 || seed || 0x00 || role), Ed25519 private seed'
export function deriveTestKey(seed: string, role: 'approval-boundary' | 'acting-agent'): { privateKey: string; publicKey: string } {
  const privateKey = sha256Hex(`APS-J01-193-TEST-KEY-V1\0${seed}\0${role}`)
  return { privateKey, publicKey: publicKeyFromPrivate(privateKey) }
}
export function deriveNonce(seed: string, runLabel: string): string {
  return sha256Hex(`APS-J01-193-TEST-NONCE-V1\0${seed}\0${runLabel}`).slice(0, 32)
}

const UTC_MS_00_59 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d\.\d{3}Z$/

/** Exact UTC milliseconds, YYYY-MM-DDTHH:MM:SS.sssZ, seconds 00 to 59. Second 60 is refused
 *  outright here (handoff S12): the SDK admits a conforming leap second, this fixture never
 *  emits or accepts one. Returns epoch milliseconds, or throws. */
export function parseUtcMs(value: unknown, name: string): number {
  if (typeof value !== 'string' || !UTC_MS_00_59.test(value)) {
    throw new Error(`${name}: expected YYYY-MM-DDTHH:MM:SS.sssZ with seconds 00-59, got ${JSON.stringify(value)}`)
  }
  const ms = Date.parse(value)
  if (Number.isNaN(ms) || new Date(ms).toISOString() !== value) throw new Error(`${name}: not a calendar instant: ${value}`)
  return ms
}

/** Closed refund argument schema of section 3. Returns a list of violations, empty when the
 *  object conforms. */
export function refundSchemaViolations(p: unknown): string[] {
  const out: string[] = []
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return ['payload is not a JSON object']
  const o = p as Record<string, unknown>
  const keys = Object.keys(o).sort()
  if (keys.join(',') !== 'amount_minor,currency,payment_id') out.push(`members must be exactly payment_id, amount_minor, currency; got ${keys.join(',')}`)
  if (typeof o.payment_id !== 'string' || !PAYMENT_ID_PATTERN.test(o.payment_id)) out.push('payment_id must match [A-Za-z0-9_-]+')
  if (typeof o.amount_minor !== 'number' || !Number.isSafeInteger(o.amount_minor) || o.amount_minor <= 0) out.push('amount_minor must be a positive safe integer')
  if (o.currency !== 'EUR') out.push('currency must be exactly "EUR"')
  return out
}

/** Minimal argv parser: --name value pairs only. */
export function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) throw new Error(`unexpected argument ${a}`)
    const v = argv[i + 1]
    if (v === undefined || v.startsWith('--')) throw new Error(`missing value for ${a}`)
    out[a.slice(2)] = v
    i++
  }
  return out
}
