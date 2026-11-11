// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Test setup: keys with validity windows, the repository holding one board pack, the
// person's grant, sub-delegation, signed share requests, revocation and key rotation.
// Nothing here is gateway logic. Every key is generated fresh for each run.

import { randomBytes } from 'node:crypto'
import {
  computeActionRefV2, computePayloadRefV1, createActionReferenceInputV2, createReceiptV1, generateKeyPair,
  issueAuthorityDelegation, issueAuthorityRevocation, issueSubAuthorityDelegation,
} from 'agent-passport-system'
import type { AuthorityDelegationBodyV1, AuthorityDelegationV1 } from 'agent-passport-system'
import { AuthorityGateway } from 'aps-example-authority-engine/engine.ts'
import type { ActionProfile, Outcome, Submission } from 'aps-example-authority-engine/engine.ts'
import { DOCUMENT_SHARE_ACTION_TYPE, shareScope, shareTarget } from './document-rules.ts'
import type { DocumentSharePayload } from './document-rules.ts'
import { MockContentRepository, documentShareProfile } from './repository.ts'
import { buildEvidencePackage } from './export.ts'
import type { EvidencePackage } from './package-format.ts'
import { receiptKeyResolver, verificationKeyResolver } from './trust.ts'
import type { KeyEntry, TrustedKeys } from './trust.ts'

export const PERSON = 'did:example:person'
export const AGENT_A = 'did:example:agent-a'
export const AGENT_B = 'did:example:agent-b'
export const GATEWAY = 'did:example:content-gateway'
export const REPOSITORY = 'board-room'
export const DOCUMENT = 'q3-board-pack'
export const VERSION = '3'
export const AUDITOR = 'auditor-llp'
export const COUNSEL = 'outside-counsel'
export const PRESS = 'press-desk'
export const BOARD_PACK_V3 = 'Q3 board pack, version 3. Revenue, risks, audit committee minutes.'

const AUTHORITY_DELEGATION_RECORD_TYPE = 'aps:authority-delegation:v1' as const
const AUTHORITY_DELEGATION_VERSION = '1.0' as const
const SCOPE_PROFILE_V1 = 'aps-hierarchical-v1' as const
const REPUTATION_PROFILE_V1 = 'aps-score-0-100-v1' as const
const VALUES_PROFILE_V1 = 'aps-values-identifiers-v1' as const
const REVERSIBILITY_PROFILE_V1 = 'aps-tci-v1' as const

const hex16 = (): string => randomBytes(16).toString('hex')

export class TestClock {
  private t: number
  constructor(start = '2026-11-11T20:00:00.000Z') { this.t = Date.parse(start) }
  now = (): string => new Date(this.t).toISOString()
  advance(ms: number): string { this.t += ms; return this.now() }
}

export interface Recorded { label: string; sub: Submission<DocumentSharePayload>; outcome: Outcome }

export interface World {
  clock: TestClock
  repository: MockContentRepository
  gateway: AuthorityGateway<DocumentSharePayload>
  /** Public key registry, as an operator would publish it. */
  keys: KeyEntry[]
  digest: string
  grantToA: AuthorityDelegationV1
  delegations: AuthorityDelegationV1[]
  revocations: unknown[]
  records: Recorded[]
  share: (recipient: string, over?: Partial<DocumentSharePayload>) => DocumentSharePayload
  delegate: (parent: AuthorityDelegationV1, subject: string, grants: string[]) => AuthorityDelegationV1
  request: (agent: string, chain: AuthorityDelegationV1[], payload: DocumentSharePayload, opts?: { nonce?: string }) => Submission<DocumentSharePayload>
  /** Request, run through the gateway and keep for export. */
  run: (label: string, agent: string, chain: AuthorityDelegationV1[], payload: DocumentSharePayload) => Promise<Outcome>
  revokeRoot: () => { recorded: boolean; reason?: string }
  /** Retire the gateway's current key and start signing with a new one. */
  rotateGatewayKey: () => string
  trustedKeys: () => TrustedKeys
  exportPackage: () => EvidencePackage
  /** Test only: a private key, to model an attacker who obtained it. */
  leakedKey: (signer: string, keyId: string) => string
}

export function authorityBody(
  issuer: string, subject: string, parentId: string | null, issuedAt: string, notAfter: string, grants: string[], depth: number,
): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parentId,
    issuer, subject,
    verification_method: `${issuer}#key-1`,
    issued_at: issuedAt,
    nonce: hex16(),
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: [...grants].sort() },
      spend: { mode: 'unbounded' },
      depth: { remaining: depth },
      time: { not_before: issuedAt, not_after: notAfter },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 100 },
      values: { profile: VALUES_PROFILE_V1, required: [] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'irreversible' },
    },
  }
}

/**
 * The scenario: a person allows Agent A, for one hour, to share version 3 of the Q3 board
 * pack (those exact bytes) with the auditor or with outside counsel, and nobody else.
 */
export function createWorld(opts: {
  execute?: ActionProfile<DocumentSharePayload>['execute']
  /** Replace the scope rule in both the gateway and the agents, to model a gateway with a
   *  policy bug. Only the D16 case uses it. */
  scopeOf?: (p: DocumentSharePayload) => string
} = {}): World {
  const scopeOf = opts.scopeOf ?? shareScope
  const clock = new TestClock()
  const epoch = new Date(Date.parse(clock.now()) - 86_400_000).toISOString()
  const priv: Record<string, Record<string, string>> = {}
  const keys: KeyEntry[] = []
  const addKey = (signer: string, keyId: string, from: string): void => {
    const kp = generateKeyPair()
    ;(priv[signer] ??= {})[keyId] = kp.privateKey
    keys.push({ signer, key_id: keyId, algorithm: 'ed25519', public_key: kp.publicKey, valid_from: from, valid_until: null })
  }
  for (const id of [PERSON, AGENT_A, AGENT_B, GATEWAY]) addKey(id, 'key-1', epoch)
  let gatewayKeyId = 'key-1'

  const resolveVerificationKey = verificationKeyResolver(keys)
  const resolveReceiptKey = receiptKeyResolver(keys)

  const repository = new MockContentRepository(clock.now)
  const digest = repository.put(REPOSITORY, DOCUMENT, VERSION, BOARD_PACK_V3)

  const gateway = new AuthorityGateway({ ...documentShareProfile(repository, { execute: opts.execute }), scope: scopeOf }, {
    id: GATEWAY,
    signingKey: () => ({ keyId: gatewayKeyId, privateKey: priv[GATEWAY][gatewayKeyId] }),
    resolveReceiptKey, resolveVerificationKey,
    trustRoot: root => root.issuer === PERSON && root.verification_method === `${PERSON}#key-1`,
    now: clock.now,
  })

  const share: World['share'] = (recipient, over = {}) => ({
    repository: REPOSITORY, document_id: DOCUMENT, version: VERSION, content_digest: digest, recipient, ...over,
  })

  const issuedAt = clock.now()
  const oneHour = new Date(Date.parse(issuedAt) + 3_600_000).toISOString()
  const grantToA = issueAuthorityDelegation(
    authorityBody(PERSON, AGENT_A, null, issuedAt, oneHour, [shareScope(share(AUDITOR)), shareScope(share(COUNSEL))], 1),
    priv[PERSON]['key-1'],
  )
  gateway.enroll([grantToA])
  const delegations: AuthorityDelegationV1[] = [grantToA]
  const revocations: unknown[] = []
  const records: Recorded[] = []

  const delegate: World['delegate'] = (parent, subject, grants) => {
    const at = clock.advance(1)
    const child = issueSubAuthorityDelegation(
      parent,
      authorityBody(parent.subject, subject, parent.delegation_id, at, parent.authority.time.not_after, grants,
        Math.max(0, parent.authority.depth.remaining - 1)),
      priv[parent.subject]['key-1'],
      { now: at, resolveVerificationKey, resolveRevocation: () => 'active' },
    )
    gateway.enroll([child])
    delegations.push(child)
    return child
  }

  const request: World['request'] = (agent, chain, payload, ro = {}) => {
    const at = clock.advance(1)
    const input = createActionReferenceInputV2({
      agent_id: agent, action_type: DOCUMENT_SHARE_ACTION_TYPE, target: shareTarget(payload),
      payload_ref: computePayloadRefV1(payload as never), scope_required: [scopeOf(payload)],
      issued_at: at, nonce: ro.nonce ?? hex16(),
    })
    const intent = createReceiptV1({
      profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1', issuer: agent, subject_agent: agent,
      action_ref: computeActionRefV2(input), delegation_ref: chain.at(-1)!.delegation_id, issued_at: at,
      evidence_refs: [], result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
    }, [{ signer: agent, key_id: 'key-1', private_key: priv[agent]['key-1'] }])
    return { input, payload, intent, chain }
  }

  const run: World['run'] = async (label, agent, chain, payload) => {
    const sub = request(agent, chain, payload)
    const outcome = await gateway.request(sub)
    records.push({ label, sub, outcome })
    return outcome
  }

  const revokeRoot: World['revokeRoot'] = () => {
    const at = clock.advance(1)
    const revocation = issueAuthorityRevocation(grantToA, {
      now: at, revoker: PERSON, verification_method: `${PERSON}#key-1`, reason_code: 'person_withdrew_consent', nonce: hex16(),
    }, priv[PERSON]['key-1'])
    const r = gateway.revoke(grantToA, revocation)
    if (r.recorded) revocations.push(revocation)
    return r
  }

  const rotateGatewayKey: World['rotateGatewayKey'] = () => {
    const at = clock.advance(1)
    const current = keys.find(k => k.signer === GATEWAY && k.key_id === gatewayKeyId)!
    current.valid_until = at
    const next = `key-${Number(gatewayKeyId.split('-')[1]) + 1}`
    addKey(GATEWAY, next, at)
    gatewayKeyId = next
    return next
  }

  const trustedKeys: World['trustedKeys'] = () => ({
    profile: 'aps-example-trusted-keys-v0', roots: [PERSON], keys: keys.map(k => ({ ...k })),
  })

  const exportPackage: World['exportPackage'] = () => buildEvidencePackage({
    producer: GATEWAY, exportedAt: clock.now(), repositorySystem: repository.system,
    keys, delegations, revocations, records,
  })

  return {
    clock, repository, gateway, keys, digest, grantToA, delegations, revocations, records,
    share, delegate, request, run, revokeRoot, rotateGatewayKey, trustedKeys, exportPackage,
    leakedKey: (signer, keyId) => priv[signer][keyId],
  }
}
