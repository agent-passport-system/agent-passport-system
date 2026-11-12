import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { CompactSign, exportJWK, generateKeyPair, type JSONWebKeySet } from 'jose'
import { authorizeAction, trustedIssuer, verifyGovernanceAttestation, type GovernanceAttestation, type TrustedIssuer } from './verify.ts'

const ISS = 'https://gateway.example'
const NOW = Date.parse('2026-11-11T18:00:00.000Z')
const HASH = 'a'.repeat(64)
let gatewayKey: CryptoKey, attackerKey: CryptoKey, attackerJwks: JSONWebKeySet, trusted: TrustedIssuer

const claim = (over: Record<string, unknown> = {}, ac: Record<string, unknown> = {}) => ({
  signal_type: 'governance_attestation', iss: ISS, gateway_id: 'gateway.example', policy_version: 'floor-v1.2.0',
  attestation_grade: 1, evaluation_timestamp: '2026-11-11T17:59:00.000Z', expires_at: '2026-11-11T18:04:00.000Z',
  delegation_chain_hash: HASH,
  active_constraints: { scopes: ['data:read', 'commerce:checkout'], spend_limit: 5, spend_used: 1, spend_currency: 'USD', ...ac },
  ...over,
})
const sign = (payload: unknown, key = gatewayKey, header: Record<string, unknown> = {}) =>
  new CompactSign(new TextEncoder().encode(typeof payload === 'string' ? payload : JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'EdDSA', kid: 'gateway-v1', typ: 'JWT', ...header }).sign(key)
const verify = (jws: string, extra: Record<string, unknown> = {}) => verifyGovernanceAttestation(jws, { trusted, now: NOW, ...extra })
const reason = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason) as string

before(async () => {
  const g = await generateKeyPair('EdDSA', { extractable: true })
  const a = await generateKeyPair('EdDSA', { extractable: true })
  gatewayKey = g.privateKey
  attackerKey = a.privateKey
  trusted = trustedIssuer(ISS, { keys: [{ ...(await exportJWK(g.publicKey)), kid: 'gateway-v1', alg: 'EdDSA' }] })
  attackerJwks = { keys: [{ ...(await exportJWK(a.publicKey)), kid: 'gateway-v1', alg: 'EdDSA' }] }
})

describe('trust comes from the caller, not the envelope', () => {
  it('a claim signed by the trusted gateway verifies', async () => {
    assert.equal(reason(await verify(await sign(claim()))), 'ok')
  })
  it('an attacker key with the same kid and the trusted iss is refused', async () => {
    assert.match(reason(await verify(await sign(claim(), attackerKey))), /signature not verified/)
  })
  it('the attacker JWKS verifies the attacker claim only when a caller wrongly trusts it', async () => {
    const jws = await sign(claim(), attackerKey)
    const wrong = await verifyGovernanceAttestation(jws, { trusted: trustedIssuer(ISS, attackerJwks), now: NOW })
    assert.equal(wrong.ok, true, 'this is the old snippet failure: trusting the keys the envelope names')
    assert.equal((await verify(jws)).ok, false)
  })
  it('the trusted key with another iss is refused', async () => {
    assert.match(reason(await verify(await sign(claim({ iss: 'https://evil.example' })))), /not the trusted issuer/)
  })
  it('an unsigned token is refused', async () => {
    const b64 = (s: string) => Buffer.from(s).toString('base64url')
    assert.equal((await verify(`${b64('{"alg":"none"}')}.${b64(JSON.stringify(claim()))}.`)).ok, false)
  })
})

describe('the claim must match the corrected schema', () => {
  const cases: Array<[string, unknown, RegExp]> = [
    ['missing iss', (() => { const c: any = claim(); delete c.iss; return c })(), /iss missing/],
    ['missing spend_limit', (() => { const c: any = claim(); delete c.active_constraints.spend_limit; return c })(), /spend_limit/],
    ['an extra top-level property', claim({ sub: 'agent' }), /sub not allowed/],
    ['an extra constraint', claim({}, { spend_unit: 'x' }), /spend_unit not allowed/],
    ['a bad chain hash', claim({ delegation_chain_hash: 'XYZ' }), /delegation_chain_hash/],
    ['a grade out of range', claim({ attestation_grade: 4 }), /attestation_grade/],
    ['a string amount', claim({}, { spend_used: '1' }), /spend_used/],
    ['a negative limit', claim({}, { spend_limit: -1 }), /spend_limit/],
    ['payload not JSON', 'not json', /not JSON/],
  ]
  for (const [label, payload, re] of cases) {
    it(`refuses ${label}`, async () => { assert.match(reason(await verify(await sign(payload))), re) })
  }
  it('accepts millisecond timestamps and spend_limit null', async () => {
    assert.equal(reason(await verify(await sign(claim({}, { spend_limit: null })))), 'ok')
  })
})

describe('freshness', () => {
  it('refuses a claim evaluated more than maxAge ago', async () => {
    assert.match(reason(await verify(await sign(claim({ evaluation_timestamp: '2026-11-11T17:54:00.000Z', expires_at: undefined })))), /stale/)
  })
  it('refuses a claim evaluated in the future beyond the skew', async () => {
    assert.match(reason(await verify(await sign(claim({ evaluation_timestamp: '2026-11-11T18:01:01.000Z', expires_at: '2026-11-11T18:06:00.000Z' })))), /future/)
  })
  it('refuses an unparseable expires_at, which the old snippet let through', async () => {
    assert.match(reason(await verify(await sign(claim({ expires_at: 'soon' })))), /bad expires_at/)
  })
  it('refuses at the exact expiry instant', async () => {
    assert.match(reason(await verify(await sign(claim({ expires_at: '2026-11-11T18:00:00.000Z' })))), /expired/)
  })
  it('refuses expires_at before evaluation_timestamp', async () => {
    assert.match(reason(await verify(await sign(claim({ expires_at: '2026-11-11T17:58:00.000Z' })))), /before evaluation_timestamp/)
  })
})

describe('binding to an expected chain', () => {
  it('refuses a claim for another chain', async () => {
    assert.match(reason(await verify(await sign(claim()), { expectedChainHash: 'b'.repeat(64) })), /not the expected chain/)
  })
  it('accepts the expected chain', async () => {
    assert.equal(reason(await verify(await sign(claim()), { expectedChainHash: HASH })), 'ok')
  })
})

describe('authorizing an action against a verified claim', () => {
  const verified = async (over: Record<string, unknown> = {}, ac: Record<string, unknown> = {}) => {
    const r = await verify(await sign(claim(over, ac)))
    assert.equal(r.ok, true, reason(r))
    return (r as { value: GovernanceAttestation }).value
  }
  it('no delegation is a valid claim and authorizes nothing', async () => {
    const c = await verified({}, { scopes: [], spend_limit: null, spend_used: 0, spend_currency: undefined })
    assert.match(reason(authorizeAction(c, { scope: 'data:read' }, { now: NOW })), /no active delegation/)
  })
  it('permits an in-scope action with no spend, refuses another scope', async () => {
    const c = await verified()
    assert.equal(reason(authorizeAction(c, { scope: 'data:read' }, { now: NOW })), 'ok')
    assert.match(reason(authorizeAction(c, { scope: 'admin:write' }, { now: NOW })), /not granted/)
  })
  it('checks the spend amount, so a fully used budget authorizes no further spend', async () => {
    const c = await verified({}, { spend_used: 5 })
    assert.match(reason(authorizeAction(c, { scope: 'commerce:checkout', amount: 1, currency: 'USD' }, { now: NOW })), /exceed spend_limit/)
    assert.equal(reason(authorizeAction(c, { scope: 'commerce:checkout', amount: 0 }, { now: NOW })), 'ok')
  })
  it('refuses a spend when the claim states no currency or another one', async () => {
    const none = await verified({}, { spend_currency: undefined })
    assert.match(reason(authorizeAction(none, { scope: 'commerce:checkout', amount: 1, currency: 'USD' }, { now: NOW })), /states no currency/)
    const usd = await verified()
    assert.match(reason(authorizeAction(usd, { scope: 'commerce:checkout', amount: 1, currency: 'XNO' }, { now: NOW })), /currency does not match/)
  })
  it('null spend_limit with granted scopes means no cap', async () => {
    const c = await verified({}, { spend_limit: null, spend_used: 1000 })
    assert.equal(reason(authorizeAction(c, { scope: 'commerce:checkout', amount: 50, currency: 'USD' }, { now: NOW })), 'ok')
  })
  it('refuses after the delegation expiry even while the attestation is fresh', async () => {
    const c = await verified({}, { expires_at: '2026-11-11T17:59:30.000Z' })
    assert.match(reason(authorizeAction(c, { scope: 'data:read' }, { now: NOW })), /delegation expired/)
  })
  it('enforces max_depth for a further delegation', async () => {
    const c = await verified({}, { max_depth: 2, current_depth: 2 })
    assert.equal(reason(authorizeAction(c, { scope: 'data:read' }, { now: NOW })), 'ok')
    assert.match(reason(authorizeAction(c, { scope: 'data:read', subDelegate: true }, { now: NOW })), /exceed max_depth/)
  })
  it('refuses when tool_restrictions are present, since v0.1 gives no rule to apply them', async () => {
    const c = await verified({}, { tool_restrictions: ['delete:*'] })
    assert.match(reason(authorizeAction(c, { scope: 'data:read' }, { now: NOW })), /tool_restrictions/)
  })
})

describe('the spec embeds this file', () => {
  it('§4 of governance-attestation-schema.md carries verify.ts verbatim', () => {
    const spec = readFileSync(new URL('../../specs/governance-attestation-schema.md', import.meta.url), 'utf8')
    const m = spec.match(/<!-- verify\.ts begin -->\n```ts\n([\s\S]*?)```\n<!-- verify\.ts end -->/)
    assert.ok(m, 'the §4 code block markers are present')
    assert.equal(m![1], readFileSync(new URL('./verify.ts', import.meta.url), 'utf8'))
  })
})
