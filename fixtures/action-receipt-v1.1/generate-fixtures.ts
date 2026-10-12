// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic generator for the legacy Action Receipt v1.1 vector family.
//
//   npx tsx fixtures/action-receipt-v1.1/generate-fixtures.ts
//
// Scope. This is the PRE-DRAFT surface: the `Delegation` of createDelegation /
// subDelegate / verifyDelegation and the `ActionReceipt` of createReceipt /
// verifyReceipt in src/core/delegation.ts, described by docs/SPEC-v1.1.md. The
// surface is deprecated and frozen (README, "Two delegation records ship").
// These vectors record what individual SDK functions return at the pinned
// commit, so a third party can compare against what this SDK emits. They say
// nothing about the draft path (AuthorityDelegationV1, receipt-core v1), and no
// case establishes that an action was authorized.
//
// Determinism. createDelegation and createReceipt read a clock and a random
// source (uuid, Date). The records here are assembled with the same
// write-boundary primitives those functions use, canonicalizeForWrite + sign,
// over fixed identifiers and timestamps. Ed25519 seeds are sha256 of published
// labels. verifyDelegation compares against Date.now(), so every SDK call here
// runs with Date.now() fixed at VERIFICATION_INSTANT, and the instant is written
// into the vector file. Values that createDelegation and createReceipt take from
// new Date() or a uuid are never written into the file.
//
// Outcomes are OBSERVED from verifyDelegation, verifyReceipt, subDelegate and
// createReceipt. Each case declares what it expects and the generator refuses to
// write the file when a function disagrees.
//
// What each function checks, at the pinned commit (a static description of the
// code, not a trace of the checks a given call reached):
//   verifyReceipt: the signature under the supplied key, and version "1.1".
//   verifyDelegation: one record alone. Signature under delegatedBy, expiresAt
//     and notBefore against the clock, currentDepth > maxDepth when maxDepth is
//     present, revocation evidence when supplied (default policy fail_open).
//     The parent is not consulted.
//   createReceipt: verifyDelegation on the supplied delegation, the action's
//     scope against that delegation's scope, its spend against the remaining
//     budget. The supplied delegationChain is copied into the receipt, not
//     validated.
//   subDelegate, in code order: the proposed child against the parent (depth,
//     scope, derivation_rights when supplied, spend unit, spend), the parent
//     expiresAt against the clock, then verifyDelegation on the parent.
// Neither verifyReceipt nor createReceipt validates the receipt's chain. A
// relying party needs a separate chain check.

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { publicKeyFromPrivate, sign } from '../../src/crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from '../../src/core/canonical.js'
import {
  createDelegation,
  createReceipt,
  subDelegate,
  verifyDelegation,
  verifyReceipt,
} from '../../src/core/delegation.js'
import type { ActionReceipt, Delegation, DelegationStatus } from '../../src/types/passport.js'

const SDK_COMMIT = 'c31d94aad86713ae9b2e4cbc811deeab4b5d91ed'
const SDK_RELEASE = 'main after the v7.2.1 tag (git describe: v7.2.1-14-gc31d94a), unreleased'
const GENERATED_AT = '2026-10-10'

// ── the frozen clock ──────────────────────────────────────────────────────────
const VERIFICATION_INSTANT = '2026-10-10T12:00:00.000Z'
const VERIFICATION_MS = Date.parse(VERIFICATION_INSTANT)
const ONE_MS_AFTER_INSTANT = new Date(VERIFICATION_MS + 1).toISOString()

/** Run fn with Date.now() returning VERIFICATION_MS, then restore it. */
function atVerificationInstant<T>(fn: () => T): T {
  const real = Date.now
  Date.now = () => VERIFICATION_MS
  try {
    return fn()
  } finally {
    Date.now = real
  }
}

// ── keys ──────────────────────────────────────────────────────────────────────
const SEED_LABEL_PREFIX = 'agent-passport-system:action-receipt-vector:'
function seedFromLabel(label: string): string {
  return createHash('sha256').update(SEED_LABEL_PREFIX + label, 'utf8').digest('hex')
}
const KEY_LABELS = ['principal-key', 'agent-key', 'subagent-key', 'other-key'] as const
type KeyLabel = (typeof KEY_LABELS)[number]
const PRIVATE = Object.fromEntries(KEY_LABELS.map(l => [l, seedFromLabel(l)])) as Record<KeyLabel, string>
const PUBLIC = Object.fromEntries(KEY_LABELS.map(l => [l, publicKeyFromPrivate(PRIVATE[l])])) as Record<KeyLabel, string>

// ── fixed values ──────────────────────────────────────────────────────────────
const CREATED_AT = '2026-10-01T00:00:00.000Z'
const NOT_BEFORE = '2026-10-01T00:00:00.000Z'
const EXPIRES_AT = '2027-10-01T00:00:00.000Z'
const EXPIRED_AT = '2026-10-02T00:00:00.000Z'
const RECEIPT_AT = '2026-10-10T11:00:00.000Z'

type Rec = Record<string, unknown>
const asMutable = (v: unknown): Rec => JSON.parse(JSON.stringify(v)) as Rec

/** Exactly the bytes createDelegation signs: canonicalizeForWrite of the unsigned record. */
function mintDelegation(fields: Omit<Delegation, 'signature'>, privateKey: string): Delegation {
  return { ...fields, signature: sign(canonicalizeForWrite(fields), privateKey) }
}
/** Exactly the bytes createReceipt signs. */
function mintReceipt(fields: Omit<ActionReceipt, 'signature'>, privateKey: string): ActionReceipt {
  return { ...fields, signature: sign(canonicalizeForWrite(fields), privateKey) }
}
function stripSig(d: Delegation): Omit<Delegation, 'signature'> {
  const { signature: _s, ...rest } = d
  return rest
}
function stripSigR(r: ActionReceipt): Omit<ActionReceipt, 'signature'> {
  const { signature: _s, ...rest } = r
  return rest
}

// ── what each function examined, written into every case ─────────────────────
const NATURE = 'Static description of the function at the pinned commit. Not a trace of the checks reached by this call: a refusal can happen before later listed checks run.'
const SCOPE_VERIFY_DELEGATION = {
  function: 'verifyDelegation',
  nature: NATURE,
  checks: [
    'Ed25519 signature under delegatedBy over the canonical record without signature',
    'expiresAt against the verification instant (expired only when expiresAt < instant)',
    'notBefore against the verification instant (not yet valid only when notBefore > instant)',
    'currentDepth > maxDepth, only when maxDepth is present',
    'revocation evidence when the caller supplies it (none is supplied in this family, and the default policy is fail_open)',
  ],
  not_checked: [
    'the parent delegation',
    'scope, spend and depth against the parent',
    'that delegatedBy holds any authority',
  ],
  establishes_authorization: false,
}
const SCOPE_VERIFY_RECEIPT = {
  function: 'verifyReceipt',
  nature: NATURE,
  checks: [
    'Ed25519 signature under the supplied agent key over the canonical receipt without signature',
    'version equals "1.1"',
  ],
  not_checked: [
    'the delegation named by delegationId',
    'delegationChain',
    'action.scopeUsed against any delegation scope',
    'action.spend against any budget',
    'revocation',
  ],
  establishes_authorization: false,
}
const CHECKS_SUBDELEGATE = [
  'parent currentDepth + 1 within parent maxDepth',
  'every child scope covered by a parent scope (pre-draft scopeCovers rule)',
  'derivation_rights against the parent, when the caller supplies them',
  'child spend unit equal to the parent unit',
  'child spendLimit within the parent remaining budget',
  'parent expiresAt after the clock',
  'verifyDelegation on the parent',
]
const CHECKS_CREATE_RECEIPT = [
  'verifyDelegation on the supplied delegation',
  'action.scopeUsed covered by that delegation scope',
  'action.spend within that delegation remaining budget',
]
const NOT_CHECKED_CREATE_RECEIPT = ['delegationChain, which is copied into the receipt as supplied']

// ── records ───────────────────────────────────────────────────────────────────
// Root: principal -> agent, one hop of sub-delegation allowed, 500 USD budget.
const root = mintDelegation({
  delegationId: 'del_vector_root',
  delegatedTo: PUBLIC['agent-key'],
  delegatedBy: PUBLIC['principal-key'],
  scope: ['commerce:checkout', 'data:read'],
  expiresAt: EXPIRES_AT,
  spendLimit: 500,
  spentAmount: 0,
  maxDepth: 1,
  currentDepth: 0,
  createdAt: CREATED_AT,
  notBefore: NOT_BEFORE,
}, PRIVATE['principal-key'])

// Child: agent -> subagent, narrower scope and budget, depth 1 of 1.
const child = mintDelegation({
  delegationId: 'del_vector_child',
  delegatedTo: PUBLIC['subagent-key'],
  delegatedBy: PUBLIC['agent-key'],
  scope: ['data:read'],
  expiresAt: EXPIRES_AT,
  spendLimit: 100,
  spentAmount: 0,
  spendLimitUnit: 'currency',
  maxDepth: 1,
  currentDepth: 1,
  createdAt: CREATED_AT,
  notBefore: NOT_BEFORE,
}, PRIVATE['agent-key'])

// The child subDelegate mints from the root with the same options. The assembled
// child must have the same members, with equal values apart from delegationId
// (a uuid), createdAt (new Date()), expiresAt (subDelegate caps it at clock + 24h)
// and the signature over them.
const CLOCK_OR_RANDOM_MEMBERS = ['delegationId', 'createdAt', 'expiresAt', 'signature']
const childBySubDelegate = asMutable(atVerificationInstant(() => subDelegate({
  parentDelegation: root,
  delegatedTo: PUBLIC['subagent-key'],
  scope: ['data:read'],
  spendLimit: 100,
  privateKey: PRIVATE['agent-key'],
})))
{
  const assembled = child as unknown as Rec
  const minted = Object.keys(childBySubDelegate).sort()
  const ours = Object.keys(assembled).sort()
  if (JSON.stringify(minted) !== JSON.stringify(ours)) {
    throw new Error(`child members differ from subDelegate's: minted ${JSON.stringify(minted)}, assembled ${JSON.stringify(ours)}`)
  }
  for (const key of minted) {
    if (CLOCK_OR_RANDOM_MEMBERS.includes(key)) continue
    if (JSON.stringify(childBySubDelegate[key]) !== JSON.stringify(assembled[key])) {
      throw new Error(`child.${key}: assembled ${JSON.stringify(assembled[key])}, subDelegate minted ${JSON.stringify(childBySubDelegate[key])}`)
    }
  }
}

// The writer side of max_depth: createDelegation writes 1 when the caller omits it.
const written = atVerificationInstant(() => createDelegation({
  delegatedBy: PUBLIC['principal-key'], delegatedTo: PUBLIC['agent-key'], scope: ['data:read'],
  expiresAt: EXPIRES_AT, privateKey: PRIVATE['principal-key'],
}))
if (written.maxDepth !== 1) throw new Error(`createDelegation without maxDepth wrote ${written.maxDepth}, expected 1`)

const receipt = mintReceipt({
  receiptId: 'rcpt_vector_0001',
  version: '1.1',
  timestamp: RECEIPT_AT,
  agentId: PUBLIC['agent-key'],
  delegationId: root.delegationId,
  action: { type: 'api_call', target: 'shop.example', method: 'POST /checkout', scopeUsed: 'commerce:checkout', spend: { amount: 120, currency: 'USD' } },
  result: { status: 'success', summary: 'order placed' },
  delegationChain: [PUBLIC['principal-key'], PUBLIC['agent-key']],
}, PRIVATE['agent-key'])

const receiptUnderChild = mintReceipt({
  receiptId: 'rcpt_vector_0002',
  version: '1.1',
  timestamp: RECEIPT_AT,
  agentId: PUBLIC['subagent-key'],
  delegationId: child.delegationId,
  action: { type: 'api_call', target: 'db.example', scopeUsed: 'data:read' },
  result: { status: 'success', summary: 'rows read' },
  delegationChain: [PUBLIC['principal-key'], PUBLIC['agent-key'], PUBLIC['subagent-key']],
}, PRIVATE['subagent-key'])

// ── negative and boundary delegations ─────────────────────────────────────────
const rootExpired = mintDelegation({ ...stripSig(root), delegationId: 'del_vector_expired', expiresAt: EXPIRED_AT }, PRIVATE['principal-key'])
const rootExpiresAtInstant = mintDelegation({ ...stripSig(root), delegationId: 'del_vector_expires_at_instant', expiresAt: VERIFICATION_INSTANT }, PRIVATE['principal-key'])
const rootNotYetValid = mintDelegation({ ...stripSig(root), delegationId: 'del_vector_not_yet_valid', notBefore: ONE_MS_AFTER_INSTANT }, PRIVATE['principal-key'])
const rootNotBeforeAtInstant = mintDelegation({ ...stripSig(root), delegationId: 'del_vector_not_before_at_instant', notBefore: VERIFICATION_INSTANT }, PRIVATE['principal-key'])
const rootOtherSigner: Rec = { ...stripSig(root), delegationId: 'del_vector_other_signer' }
rootOtherSigner.signature = sign(canonicalizeForWrite(rootOtherSigner), PRIVATE['other-key'])
const childDepthExceeded = mintDelegation({ ...stripSig(child), delegationId: 'del_vector_depth2', currentDepth: 2 }, PRIVATE['agent-key'])
// A grandchild under the child, as an issuer that ignored the depth limit would mint it.
const grandchild = mintDelegation({ ...stripSig(child), delegationId: 'del_vector_grandchild', delegatedBy: PUBLIC['subagent-key'], delegatedTo: PUBLIC['other-key'], spendLimit: 50, currentDepth: 2 }, PRIVATE['subagent-key'])
const childWidened = mintDelegation({ ...stripSig(child), delegationId: 'del_vector_widened', scope: ['data:read', 'admin:*'] }, PRIVATE['agent-key'])
const childOverBudget = mintDelegation({ ...stripSig(child), delegationId: 'del_vector_overbudget', spendLimit: 900 }, PRIVATE['agent-key'])
// Signed without maxDepth, at currentDepth 64. A reader that applied any small
// default ceiling at verification would report depthExceeded here.
const noMaxDepth: Rec = {
  delegationId: 'del_vector_no_max_depth', delegatedTo: PUBLIC['subagent-key'], delegatedBy: PUBLIC['agent-key'],
  scope: ['data:read'], expiresAt: EXPIRES_AT, currentDepth: 64, createdAt: CREATED_AT, notBefore: NOT_BEFORE,
}
noMaxDepth.signature = sign(canonicalizeForWrite(noMaxDepth), PRIVATE['agent-key'])

// ── negative and boundary receipts ────────────────────────────────────────────
const receiptTampered = asMutable(receipt)
;(receiptTampered.action as Rec).spend = { amount: 12000, currency: 'USD' }

const receiptOtherSigner = asMutable(receipt)
receiptOtherSigner.signature = sign(canonicalizeForWrite(stripSigR(receipt)), PRIVATE['other-key'])

// Re-signed by the agent, so the signature is valid and only the version gate fails.
const receiptVersion10 = mintReceipt({ ...stripSigR(receipt), receiptId: 'rcpt_vector_0005', version: '1.0' }, PRIVATE['agent-key'])

// The SPEC-v1.1.md section 1.1 spelling of the same receipt, minted signature kept.
const receiptSnakeCase: Rec = {
  receipt_id: receipt.receiptId, version: receipt.version, timestamp: receipt.timestamp,
  agent_id: receipt.agentId, delegation_id: receipt.delegationId,
  action: { type: receipt.action.type, target: receipt.action.target, method: receipt.action.method, scope_used: receipt.action.scopeUsed, spend: receipt.action.spend },
  result: receipt.result, delegation_chain: receipt.delegationChain, signature: receipt.signature,
}

const scopeNotDelegatedAction: ActionReceipt['action'] = { type: 'api_call', target: 'shop.example', scopeUsed: 'admin:delete' }
const receiptScopeNotDelegated = mintReceipt({ ...stripSigR(receipt), receiptId: 'rcpt_vector_0003', action: scopeNotDelegatedAction }, PRIVATE['agent-key'])

const overBudgetAction: ActionReceipt['action'] = { ...receipt.action, spend: { amount: 900, currency: 'USD' } }
const receiptOverBudget = mintReceipt({ ...stripSigR(receipt), receiptId: 'rcpt_vector_0004', action: overBudgetAction }, PRIVATE['agent-key'])

// A chain whose first entry is a key that delegated nothing in this family.
const unrelatedChain = [PUBLIC['other-key'], PUBLIC['agent-key']]
const receiptUnrelatedChain = mintReceipt({ ...stripSigR(receipt), receiptId: 'rcpt_vector_0006', delegationChain: unrelatedChain }, PRIVATE['agent-key'])

// A receipt under the expired delegation, signed by the agent.
const receiptUnderExpired = mintReceipt({ ...stripSigR(receipt), receiptId: 'rcpt_vector_0007', delegationId: rootExpired.delegationId }, PRIVATE['agent-key'])

// ── issuance, with its inputs written into the file ───────────────────────────
const DELEGATIONS_BY_ID: Record<string, Rec> = Object.fromEntries(
  [root, child, rootExpired, rootOtherSigner].map(d => [String((d as Rec).delegationId), d as unknown as Rec]),
)

interface SubDelegateInputs { parent: string; delegatedTo: string; scope: string[]; spendLimit: number; signer_key: KeyLabel }
interface CreateReceiptInputs { delegation: string; agentId: string; action: ActionReceipt['action']; result: ActionReceipt['result']; delegationChain: string[]; signer_key: KeyLabel }

interface IssuanceOutcome {
  function: 'subDelegate' | 'createReceipt'
  inputs: SubDelegateInputs | CreateReceiptInputs
  accepted: boolean
  error: string | null
  checks: string[]
  not_checked?: string[]
  output_compared?: string
}

function runSubDelegate(inputs: SubDelegateInputs): Rec {
  return subDelegate({
    parentDelegation: DELEGATIONS_BY_ID[inputs.parent] as unknown as Delegation,
    delegatedTo: inputs.delegatedTo, scope: inputs.scope, spendLimit: inputs.spendLimit,
    privateKey: PRIVATE[inputs.signer_key],
  }) as unknown as Rec
}
function runCreateReceipt(inputs: CreateReceiptInputs): Rec {
  return createReceipt({
    agentId: inputs.agentId, delegationId: inputs.delegation,
    delegation: DELEGATIONS_BY_ID[inputs.delegation] as unknown as Delegation,
    action: inputs.action, result: inputs.result, delegationChain: inputs.delegationChain,
    privateKey: PRIVATE[inputs.signer_key],
  }) as unknown as Rec
}

/** Members createReceipt takes from its inputs. The rest come from the clock, a uuid or the signature. */
const RECEIPT_MEMBERS_FROM_INPUTS = ['version', 'agentId', 'delegationId', 'action', 'result', 'delegationChain']

function issueSubDelegate(inputs: SubDelegateInputs): IssuanceOutcome {
  const base = { function: 'subDelegate' as const, inputs, checks: CHECKS_SUBDELEGATE }
  try {
    atVerificationInstant(() => runSubDelegate(inputs))
    return { ...base, accepted: true, error: null }
  } catch (e) {
    return { ...base, accepted: false, error: (e as Error).message }
  }
}
function issueCreateReceipt(inputs: CreateReceiptInputs, expected: Rec): IssuanceOutcome {
  const base = { function: 'createReceipt' as const, inputs, checks: CHECKS_CREATE_RECEIPT, not_checked: NOT_CHECKED_CREATE_RECEIPT }
  let out: Rec
  try {
    out = JSON.parse(JSON.stringify(atVerificationInstant(() => runCreateReceipt(inputs)))) as Rec
  } catch (e) {
    return { ...base, accepted: false, error: (e as Error).message }
  }
  // The receipt createReceipt returned must carry the case record's members
  // under the same names and values, apart from receiptId, timestamp and
  // signature. This is what pins that the chain is copied as supplied and that
  // the member names are camelCase.
  const outKeys = Object.keys(out).sort()
  const expKeys = Object.keys(expected).sort()
  if (JSON.stringify(outKeys) !== JSON.stringify(expKeys)) throw new Error(`createReceipt members ${JSON.stringify(outKeys)} differ from the record ${JSON.stringify(expKeys)}`)
  for (const key of RECEIPT_MEMBERS_FROM_INPUTS) {
    if (JSON.stringify(out[key]) !== JSON.stringify(expected[key])) throw new Error(`createReceipt ${key}: ${JSON.stringify(out[key])} differs from the record ${JSON.stringify(expected[key])}`)
  }
  return { ...base, accepted: true, error: null, output_compared: `members and names equal to the case record, values equal for ${RECEIPT_MEMBERS_FROM_INPUTS.join(', ')}` }
}

const subInputs = (parent: string, delegatedTo: string, scope: string[], spendLimit: number, signer_key: KeyLabel): SubDelegateInputs =>
  ({ parent, delegatedTo, scope, spendLimit, signer_key })
const rcptInputs = (delegation: string, action: ActionReceipt['action'], delegationChain: string[]): CreateReceiptInputs =>
  ({ delegation, agentId: PUBLIC['agent-key'], action, result: receipt.result, delegationChain, signer_key: 'agent-key' })

// ── delegation cases ──────────────────────────────────────────────────────────
interface DelegationCase {
  name: string
  description: string
  record: Rec
  expect_valid: boolean
  issuance?: IssuanceOutcome
  expect_issuance_accepted?: boolean
  sdk_observation?: string
}

const NOT_AUTH = 'This valid result is the function\'s result, not an authorization result.'

const delegationCases: DelegationCase[] = [
  { name: 'valid-root-delegation', description: 'principal -> agent, maxDepth 1, currentDepth 0, 500 USD.', record: asMutable(root), expect_valid: true },
  {
    name: 'valid-child-delegation',
    description: `agent -> subagent, scope and budget narrower than the root, currentDepth 1 of maxDepth 1. Has the same members as the child subDelegate mints from the root, with equal values apart from ${CLOCK_OR_RANDOM_MEMBERS.join(', ')} (checked at generation). The record itself is assembled and signed separately.`,
    record: asMutable(child), expect_valid: true,
    issuance: issueSubDelegate(subInputs('del_vector_root', PUBLIC['subagent-key'], ['data:read'], 100, 'agent-key')), expect_issuance_accepted: true,
  },
  {
    name: 'delegation-expired',
    description: `Same as the root with expiresAt ${EXPIRED_AT}, re-signed by the principal. Signature valid, record expired at the verification instant.`,
    record: asMutable(rootExpired), expect_valid: false,
  },
  {
    name: 'delegation-expires-at-verification-instant',
    description: `Same as the root with expiresAt equal to the verification instant (${VERIFICATION_INSTANT}), re-signed by the principal.`,
    record: asMutable(rootExpiresAtInstant), expect_valid: true,
    sdk_observation: 'verifyDelegation reports a record as expired only when expiresAt < the verification instant, so the instant itself is still inside the window. Recorded as the SDK output at the pinned commit. The passport 2.0 interval in draft-04 section 3.1 is exclusive at expires_at.',
  },
  {
    name: 'delegation-not-yet-valid',
    description: `Same as the root with notBefore one millisecond after the verification instant (${ONE_MS_AFTER_INSTANT}), re-signed by the principal.`,
    record: asMutable(rootNotYetValid), expect_valid: false,
  },
  {
    name: 'delegation-not-before-at-verification-instant',
    description: `Same as the root with notBefore equal to the verification instant, re-signed by the principal. verifyDelegation reports not yet valid only when notBefore > the instant.`,
    record: asMutable(rootNotBeforeAtInstant), expect_valid: true,
  },
  {
    name: 'delegation-signed-by-other-key',
    description: 'Body identical to the root, signed with other-key. delegatedBy still names the principal, so the signature check fails. subDelegate from it is refused because the parent does not verify.',
    record: rootOtherSigner, expect_valid: false,
    issuance: issueSubDelegate(subInputs('del_vector_other_signer', PUBLIC['subagent-key'], ['data:read'], 100, 'agent-key')), expect_issuance_accepted: false,
  },
  {
    name: 'delegation-depth-exceeded',
    description: 'The child with currentDepth 2 and maxDepth 1, re-signed by the agent. verifyDelegation reports depthExceeded.',
    record: asMutable(childDepthExceeded), expect_valid: false,
  },
  {
    name: 'delegation-grandchild-beyond-depth',
    description: 'subagent -> other-key under the child, currentDepth 2, maxDepth 1, signed by the subagent. verifyDelegation reports depthExceeded. subDelegate from the child refuses to mint it because the child is already at its depth limit.',
    record: asMutable(grandchild), expect_valid: false,
    issuance: issueSubDelegate(subInputs('del_vector_child', PUBLIC['other-key'], ['data:read'], 50, 'subagent-key')), expect_issuance_accepted: false,
  },
  {
    name: 'delegation-scope-wider-than-parent',
    description: `The child with scope [data:read, admin:*], re-signed by the agent. verifyDelegation accepts the record on its own because it does not consult the parent. subDelegate refuses to mint it. ${NOT_AUTH}`,
    record: asMutable(childWidened), expect_valid: true,
    issuance: issueSubDelegate(subInputs('del_vector_root', PUBLIC['subagent-key'], ['data:read', 'admin:*'], 100, 'agent-key')), expect_issuance_accepted: false,
  },
  {
    name: 'delegation-spend-wider-than-parent',
    description: `The child with spendLimit 900 against a parent of 500, re-signed by the agent. verifyDelegation accepts the record on its own, subDelegate refuses. ${NOT_AUTH}`,
    record: asMutable(childOverBudget), expect_valid: true,
    issuance: issueSubDelegate(subInputs('del_vector_root', PUBLIC['subagent-key'], ['data:read'], 900, 'agent-key')), expect_issuance_accepted: false,
  },
  {
    name: 'delegation-without-max-depth-at-depth-64',
    description: `A record signed without maxDepth, at currentDepth 64. verifyDelegation applies no depth ceiling when maxDepth is absent. createDelegation writes maxDepth 1 when its caller omits the field (checked at generation and in the test), so the writer default and the reader behaviour differ. ${NOT_AUTH}`,
    record: noMaxDepth, expect_valid: true,
  },
]

const delegationsOut = delegationCases.map(item => {
  const status: DelegationStatus = atVerificationInstant(() => verifyDelegation(item.record as unknown as Delegation))
  if (status.valid !== item.expect_valid) throw new Error(`${item.name}: expected valid ${item.expect_valid}, verifyDelegation returned ${status.valid} (${status.errors.join(', ')})`)
  if (item.issuance && item.issuance.accepted !== item.expect_issuance_accepted) throw new Error(`${item.name}: issuance expected accepted ${item.expect_issuance_accepted}, got ${item.issuance.accepted} (${item.issuance.error})`)
  return {
    name: item.name,
    description: item.description,
    record: item.record,
    verification_scope: SCOPE_VERIFY_DELEGATION,
    verification: JSON.parse(JSON.stringify(status)) as Rec,
    ...(item.issuance ? { issuance: item.issuance } : {}),
    ...(item.sdk_observation ? { sdk_observation: item.sdk_observation } : {}),
  }
})

// ── receipt cases ─────────────────────────────────────────────────────────────
interface ReceiptCase {
  name: string
  description: string
  record: Rec
  verify_with_key: KeyLabel
  expect_valid: boolean
  expect_errors?: string[]
  issuance?: IssuanceOutcome
  expect_issuance_accepted?: boolean
}

const receiptCases: ReceiptCase[] = [
  {
    name: 'valid-receipt-under-root',
    description: 'Agent executes commerce:checkout for 120 USD under the root delegation and signs the receipt. verifyReceipt with the agent key. createReceipt accepts the same inputs, and the receipt it returns carries the same members, names and input values as this record.',
    record: asMutable(receipt), verify_with_key: 'agent-key', expect_valid: true,
    issuance: issueCreateReceipt(rcptInputs('del_vector_root', receipt.action, receipt.delegationChain), asMutable(receipt)), expect_issuance_accepted: true,
  },
  { name: 'valid-receipt-under-child', description: 'Subagent executes data:read under the child delegation. Three-entry delegationChain.', record: asMutable(receiptUnderChild), verify_with_key: 'subagent-key', expect_valid: true },
  { name: 'receipt-tampered-spend', description: 'action.spend.amount changed from 120 to 12000 after signing. The signature no longer covers the bytes.', record: receiptTampered, verify_with_key: 'agent-key', expect_valid: false, expect_errors: ['Invalid receipt signature'] },
  { name: 'receipt-signed-by-other-key', description: 'Body identical to the valid receipt, signed with other-key, verified with the agent key.', record: receiptOtherSigner, verify_with_key: 'agent-key', expect_valid: false, expect_errors: ['Invalid receipt signature'] },
  { name: 'receipt-version-1.0', description: 'version 1.0, re-signed by the agent, so the signature is valid and only the version gate fails.', record: asMutable(receiptVersion10), verify_with_key: 'agent-key', expect_valid: false, expect_errors: ['Unsupported receipt version'] },
  { name: 'receipt-snake-case-spelling', description: 'The valid receipt re-spelled with the member names of the docs/SPEC-v1.1.md section 1.1 example (receipt_id, agent_id, delegation_id, scope_used, delegation_chain), with the signature minted over the camelCase record kept. Member names are inside the canonical bytes, so renaming them without re-signing invalidates the signature. verifyReceipt checks signature and version, not member names, so this case does not show that snake_case is rejected as such. The camelCase names are pinned by the createReceipt output comparison on valid-receipt-under-root.', record: receiptSnakeCase, verify_with_key: 'agent-key', expect_valid: false, expect_errors: ['Invalid receipt signature'] },
  {
    name: 'receipt-scope-not-delegated',
    description: `A receipt for admin:delete under the root, signed by the agent. verifyReceipt returns valid because it checks signature and version only. createReceipt refuses to mint it. ${NOT_AUTH}`,
    record: asMutable(receiptScopeNotDelegated), verify_with_key: 'agent-key', expect_valid: true,
    issuance: issueCreateReceipt(rcptInputs('del_vector_root', scopeNotDelegatedAction, receipt.delegationChain), asMutable(receiptScopeNotDelegated)), expect_issuance_accepted: false,
  },
  {
    name: 'receipt-spend-over-budget',
    description: `A receipt spending 900 USD under a 500 USD delegation, signed by the agent. verifyReceipt returns valid, createReceipt refuses. ${NOT_AUTH}`,
    record: asMutable(receiptOverBudget), verify_with_key: 'agent-key', expect_valid: true,
    issuance: issueCreateReceipt(rcptInputs('del_vector_root', overBudgetAction, receipt.delegationChain), asMutable(receiptOverBudget)), expect_issuance_accepted: false,
  },
  {
    name: 'receipt-under-expired-delegation',
    description: `A receipt naming the expired delegation, signed by the agent. verifyReceipt returns valid because it does not look at the delegation. createReceipt refuses because the supplied delegation does not verify. ${NOT_AUTH}`,
    record: asMutable(receiptUnderExpired), verify_with_key: 'agent-key', expect_valid: true,
    issuance: issueCreateReceipt(rcptInputs('del_vector_expired', receipt.action, receipt.delegationChain), asMutable(receiptUnderExpired)), expect_issuance_accepted: false,
  },
  {
    name: 'receipt-chain-not-validated',
    description: `The valid receipt with delegationChain starting at other-key, a key that delegated nothing here, re-signed by the agent. verifyReceipt returns valid. createReceipt accepts the same chain and the receipt it returns carries that chain unchanged, because neither function validates delegationChain. ${NOT_AUTH}`,
    record: asMutable(receiptUnrelatedChain), verify_with_key: 'agent-key', expect_valid: true,
    issuance: issueCreateReceipt(rcptInputs('del_vector_root', receipt.action, unrelatedChain), asMutable(receiptUnrelatedChain)), expect_issuance_accepted: true,
  },
]

const receiptsOut = receiptCases.map(item => {
  const status = atVerificationInstant(() => verifyReceipt(item.record as unknown as ActionReceipt, PUBLIC[item.verify_with_key]))
  if (status.valid !== item.expect_valid) throw new Error(`${item.name}: expected valid ${item.expect_valid}, verifyReceipt returned ${status.valid} (${status.errors.join(', ')})`)
  if (item.expect_errors && JSON.stringify(status.errors) !== JSON.stringify(item.expect_errors)) throw new Error(`${item.name}: expected errors ${JSON.stringify(item.expect_errors)}, got ${JSON.stringify(status.errors)}`)
  if (item.issuance && item.issuance.accepted !== item.expect_issuance_accepted) throw new Error(`${item.name}: issuance expected accepted ${item.expect_issuance_accepted}, got ${item.issuance.accepted} (${item.issuance.error})`)
  return {
    name: item.name,
    description: item.description,
    record: item.record,
    verify_with_key: item.verify_with_key,
    verification_scope: SCOPE_VERIFY_RECEIPT,
    verification: status,
    ...(item.issuance ? { issuance: item.issuance } : {}),
  }
})

// ── preimages ─────────────────────────────────────────────────────────────────
const hex = (v: string): string => Buffer.from(v, 'utf8').toString('hex')
function preimage(record: Rec): { signature_preimage_hex: string; signature_preimage_text: string } {
  const { signature: _s, ...unsigned } = record
  const text = canonicalize(unsigned)
  return { signature_preimage_hex: hex(text), signature_preimage_text: text }
}

const out = {
  family: 'action-receipt',
  version: 'v1.1',
  status: 'Legacy, pre-draft, frozen. Not on the draft-pidlisnyi-aps path. The draft-path records are AuthorityDelegationV1 (aps:authority-delegation:v1) and receipt-core v1.',
  spec: 'docs/SPEC-v1.1.md, as implemented in the TypeScript src/core/delegation.ts and typed in src/types/passport.ts. Where the document and this implementation differ, these vectors record the implementation, and the document carries a dated errata section listing the differences. Neither the vectors nor the errata change the requirements of the document, and other implementations may differ.',
  module: 'src/core/delegation.ts (createDelegation, subDelegate, verifyDelegation, createReceipt, verifyReceipt), src/core/canonical.ts',
  generated_at: GENERATED_AT,
  sdk_reference: {
    repository: 'aeoess/agent-passport-system',
    release: SDK_RELEASE,
    commit: SDK_COMMIT,
    note: 'Every verification and issuance value was produced by the TypeScript reference implementation at this commit. The delegation, canonicalization, crypto and type sources are unchanged between the v7.2.1 tag and this commit. The vector files are added on top of that commit.',
  },
  verification_instant: VERIFICATION_INSTANT,
  how_to_read: 'Each case records what one SDK function returned for one record. `verification_scope` names the function that produced `verification` and lists, as a static description of that function, what it checks and does not check. It is not a trace of the checks a given call reached. `issuance`, where present, records the inputs given to subDelegate or createReceipt and whether they were accepted. For an accepted createReceipt call the returned receipt was compared with the case record. A `valid: true` here is one function\'s result. No case establishes that an action was authorized, and establishes_authorization is false on every case.',
  wire_shape: {
    note: 'The TypeScript SDK at the pinned commit emits and signs camelCase member names: receiptId, agentId, delegationId, action.scopeUsed, delegationChain on a receipt, delegationId, delegatedTo, delegatedBy, scope, expiresAt, spendLimit, spentAmount, maxDepth, currentDepth, createdAt, notBefore on a delegation, and when set, scopeInterpretation, spendLimitUnit, credentialCheckPolicy, and derivation_rights and observation_policy in snake_case. The docs/SPEC-v1.1.md section 1.1 and 3.2 examples use other names and shapes. Renaming the members of a signed record without re-signing invalidates its signature (receipt-snake-case-spelling).',
    canonicalization: 'APS canonical JSON (src/core/canonical.ts, docs/CANONICAL-SPEC.md): keys sorted by UTF-16 code units, members whose value is null or undefined omitted, array nulls preserved, no whitespace. Not RFC 8785, since the null omission rule differs.',
    signature: 'Ed25519 over the UTF-8 bytes of the canonical form of the record without its signature member. No domain tag. Raw 64-byte signature as 128 lowercase hex. Keys are raw 32-byte Ed25519 public keys as 64 lowercase hex.',
    receipt_signer: 'the executing agent. verifyReceipt takes the agent public key as a parameter and does not resolve it from the receipt.',
    delegation_signer: 'delegatedBy. verifyDelegation reads the key from the record.',
  },
  what_each_function_checks: {
    verifyReceipt: 'the signature under the supplied key and that version is 1.1.',
    verifyDelegation: 'one record alone: signature under delegatedBy, expiresAt and notBefore against the clock, currentDepth > maxDepth when maxDepth is present, revocation evidence when supplied. The default revocation policy is fail_open, so with no evidence it returns valid. The parent is not consulted.',
    createReceipt: 'the supplied delegation (verifyDelegation), the action scope against that delegation, the spend against its remaining budget. It copies the supplied delegationChain into the receipt without validating it.',
    subDelegate: 'the proposed child against the parent (depth, scope, spend unit, spend), the parent expiry, then the parent itself (verifyDelegation), in that order.',
    summary: 'Neither verifyReceipt nor createReceipt validates the receipt chain. A relying party needs a separate chain check.',
    max_depth: 'createDelegation writes maxDepth 1 when the caller omits it. verifyDelegation applies no depth ceiling to a signed record without maxDepth. The writer default and the reader behaviour are not equivalent. Other implementations differ here, see the errata.',
  },
  determinism: `Records are assembled with canonicalizeForWrite + sign, the write-boundary primitives createDelegation and createReceipt use, over fixed identifiers and timestamps. Keys are sha256 of "${SEED_LABEL_PREFIX}<label>". Every SDK call runs with Date.now() fixed at verification_instant. Values the SDK takes from new Date() or a uuid are compared only where they are excluded by name, and never written into the file. Two generator runs are byte identical.`,
  keys: KEY_LABELS.map(label => ({ label, seed_label: SEED_LABEL_PREFIX + label, seed_derivation: 'sha256(utf8(seed_label)), the 32 bytes ARE the Ed25519 seed', private_key_hex: PRIVATE[label], public_key_hex: PUBLIC[label] })),
  preimages: {
    'valid-root-delegation': preimage(asMutable(root)),
    'valid-child-delegation': preimage(asMutable(child)),
    'valid-receipt-under-root': preimage(asMutable(receipt)),
    'valid-receipt-under-child': preimage(asMutable(receiptUnderChild)),
  },
  delegation_cases: delegationsOut,
  receipt_cases: receiptsOut,
  not_covered: [
    'Revocation. verifyDelegation takes cached revocation state as an option and the SDK holds no registry. The gateway DelegationStore does live checks. No revocation case is pinned here.',
    'Chain verification as one operation. The legacy surface verifies records one at a time (store.validateChain lives in the gateway).',
    'The draft path: AuthorityDelegationV1, authority revocation, receipt-core v1. Those have their own families and wire formats.',
    'previousReceiptHash, witnessSignature, sequenceNumber and the other optional receipt members. None is set here.',
  ],
}

const dir = dirname(fileURLToPath(import.meta.url))
const path = join(dir, 'action-receipt-vectors-v1.1.json')
writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
process.stdout.write(`wrote ${delegationsOut.length} delegation cases + ${receiptsOut.length} receipt cases -> ${path}\n`)
