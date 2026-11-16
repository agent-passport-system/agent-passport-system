// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { didKeyFromPublicKey } from '../src/v2/identity-binding/did-aps.js'
import {
  APS_A2A_IDENTITY_EXTENSION,
  attachApsIdentityExtensionV1,
  signA2AAgentCardV1,
  verifyApsA2AAgentCardV1,
} from '../src/profiles/a2a/identity-v1.js'
import {
  APS_MCP_AUTHORIZATION_META,
  APS_MCP_RECEIPT_META,
  ApsMcpAuthorizationError,
  createApsMcpToolCallMiddleware,
  issueApsMcpAuthorizationV1,
} from '../src/profiles/mcp/authorization-v1.js'

describe('A2A APS identity extension', () => {
  it('uses native Agent Card extensions and JWS signatures', async () => {
    const agent = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const kid = `${agentId}#${agentId.slice('did:key:'.length)}`
    const passportBytes = Buffer.from('{"passport":"v2"}', 'utf8')
    const base = {
      name: 'Checkout Agent',
      description: 'Runs governed checkout actions',
      supportedInterfaces: [{ url: 'https://agent.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
      version: '1.0.0',
      capabilities: { streaming: false },
      defaultInputModes: ['application/json'],
      defaultOutputModes: ['application/json'],
      skills: [],
    }
    const extended = attachApsIdentityExtensionV1(base, {
      agent_id: agentId,
      passport_uri: 'https://agent.example/.well-known/aps-passport.json',
      passport_sha256: createHash('sha256').update(passportBytes).digest('hex'),
      issued_at: '2026-07-16T00:00:00.000Z',
      expires_at: '2026-07-19T00:00:00.000Z',
    })
    assert.equal((extended.capabilities.extensions![0] as Record<string, unknown>).uri, APS_A2A_IDENTITY_EXTENSION)
    const signed = signA2AAgentCardV1(extended, agent.privateKey, kid)
    const verified = await verifyApsA2AAgentCardV1(signed, {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      resolve_artifact: async () => passportBytes,
    })
    assert.equal(verified.state, 'valid')
    assert.equal(verified.card_signature, 'verified')
    assert.equal(verified.passport, 'resolved')

    const tampered = { ...signed, name: 'Refund Agent' }
    assert.equal((await verifyApsA2AAgentCardV1(tampered, {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      resolve_artifact: async () => passportBytes,
    })).state, 'invalid')
  })
})

describe('A2A 1.0 section 8.4.1 signing input', () => {
  function fixture() {
    const agent = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const kid = `${agentId}#${agentId.slice('did:key:'.length)}`
    const passportBytes = Buffer.from('{"passport":"v2"}', 'utf8')
    const params = {
      agent_id: agentId,
      passport_uri: 'https://agent.example/.well-known/aps-passport.json',
      passport_sha256: createHash('sha256').update(passportBytes).digest('hex'),
      issued_at: '2026-07-16T00:00:00.000Z',
      expires_at: '2026-07-19T00:00:00.000Z',
    }
    const base = {
      name: 'Checkout Agent',
      description: 'Runs governed checkout actions',
      supportedInterfaces: [{ url: 'https://agent.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
      version: '1.0.0',
      capabilities: { streaming: false },
      defaultInputModes: ['application/json'],
      defaultOutputModes: ['application/json'],
      skills: [],
    }
    const options = {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved' as const, public_key_hex: agent.publicKey }),
      resolve_artifact: async () => passportBytes,
    }
    return { agent, kid, params, base, options }
  }

  it('writes required only when true', () => {
    const { params, base } = fixture()
    const off = attachApsIdentityExtensionV1(base, params)
    const on = attachApsIdentityExtensionV1(base, params, true)
    assert.equal('required' in (off.capabilities.extensions![0] as Record<string, unknown>), false)
    assert.equal((on.capabilities.extensions![0] as Record<string, unknown>).required, true)
  })

  it('omits implicit defaults, so a verifier that removes them still verifies', async () => {
    const { agent, kid, params, base, options } = fixture()
    const extended = attachApsIdentityExtensionV1(base, params)
    const other = { uri: 'https://example.org/ext', description: 'other', required: false }
    const card = {
      ...extended,
      supportedInterfaces: [{ ...base.supportedInterfaces[0], tenant: '' }],
      capabilities: { ...extended.capabilities, extensions: [...extended.capabilities.extensions!, other] },
    }
    const signed = signA2AAgentCardV1(card, agent.privateKey, kid)
    const served = await verifyApsA2AAgentCardV1(signed, options)
    assert.equal(served.state, 'valid')
    assert.equal(served.payload_form, 'a2a_1_0')
    const stripped = structuredClone(signed) as typeof signed
    delete (stripped.supportedInterfaces as Record<string, unknown>[])[0].tenant
    delete (stripped.capabilities.extensions![1] as Record<string, unknown>).required
    const again = await verifyApsA2AAgentCardV1(stripped, options)
    assert.equal(again.state, 'valid')
    assert.equal(again.payload_form, 'a2a_1_0')
  })

  it('keeps a selected oneof member even when its message is empty', async () => {
    const { agent, kid, params, base, options } = fixture()
    const card = {
      ...attachApsIdentityExtensionV1(base, params),
      securitySchemes: { mtls: { mtlsSecurityScheme: {} } },
    }
    const signed = signA2AAgentCardV1(card, agent.privateKey, kid)
    assert.equal((await verifyApsA2AAgentCardV1(signed, options)).state, 'valid')
    const { securitySchemes: _dropped, ...withoutScheme } = signed
    const result = await verifyApsA2AAgentCardV1(withoutScheme, options)
    assert.equal(result.state, 'invalid')
    assert.equal(result.code, 'A2A_SIGNATURE_INVALID')
  })

  it('keeps unknown __proto__ JSON members bound at top level and in nested messages', async () => {
    const { a2aCardSigningObjectV1 } = await import('../src/profiles/a2a/card-presence.js')
    for (const location of ['top', 'capabilities']) {
      const { agent, kid, params, base, options } = fixture()
      const card = attachApsIdentityExtensionV1({ ...base, skills: [{ id: 's', name: 's', description: 's', tags: ['t'] }] }, params)
      const target = location === 'top' ? card : card.capabilities
      Object.defineProperty(target, '__proto__', { value: { marker: 'original' }, enumerable: true, writable: true, configurable: true })
      const signingObject = a2aCardSigningObjectV1(card)
      const normalized = location === 'top' ? signingObject : signingObject.capabilities as Record<string, unknown>
      assert.equal(Object.hasOwn(normalized, '__proto__'), true)
      const signed = signA2AAgentCardV1(card, agent.privateKey, kid)
      assert.equal((await verifyApsA2AAgentCardV1(signed, options)).state, 'valid')
      const mutated = JSON.parse(JSON.stringify(signed))
      const changed = location === 'top' ? mutated : mutated.capabilities
      changed.__proto__.marker = 'changed'
      assert.equal((await verifyApsA2AAgentCardV1(mutated, options)).code, 'A2A_SIGNATURE_INVALID')
    }
  })

  it('prefers a current-form signature regardless of signature order', async () => {
    const { canonicalizeJCS, canonicalizeJCSForWrite } = await import('../src/core/canonical-jcs.js')
    const { sign } = await import('../src/crypto/keys.js')
    const { agent, kid, params, base, options } = fixture()
    const card = attachApsIdentityExtensionV1(base, params)
    ;(card.capabilities.extensions![0] as Record<string, unknown>).required = false
    const current = signA2AAgentCardV1(card, agent.privateKey, kid).signatures![0]
    const protectedB64 = Buffer.from(canonicalizeJCSForWrite({ alg: 'EdDSA', kid, typ: 'JOSE' }), 'utf8').toString('base64url')
    const payloadB64 = Buffer.from(canonicalizeJCS(card), 'utf8').toString('base64url')
    const legacy = { protected: protectedB64, signature: Buffer.from(sign(`${protectedB64}.${payloadB64}`, agent.privateKey), 'hex').toString('base64url') }
    for (const signatures of [[legacy, current], [current, legacy]]) {
      const verified = await verifyApsA2AAgentCardV1({ ...card, signatures }, options)
      assert.equal(verified.state, 'valid')
      assert.equal(verified.payload_form, 'a2a_1_0')
    }
  })

  it('keeps malformed defaults distinct from declared A2A field defaults', async () => {
    const { agent, kid, params, base, options } = fixture()
    for (const field of ['tenant', 'required', 'securityRequirements', 'securitySchemes']) {
      const card = attachApsIdentityExtensionV1(base, params)
      const target: Record<string, unknown> = field === 'tenant'
        ? card.supportedInterfaces[0]
        : field === 'required' ? card.capabilities.extensions![0] as Record<string, unknown> : card
      const defaultValue = field === 'tenant' ? '' : field === 'required' ? false : field === 'securitySchemes' ? {} : []
      target[field] = defaultValue
      const signed = signA2AAgentCardV1(card, agent.privateKey, kid)
      assert.equal((await verifyApsA2AAgentCardV1(signed, options)).state, 'valid')
      const replacements = field === 'tenant' ? [false, 0] : field === 'required' ? ['', 0] : field === 'securitySchemes' ? [[]] : [{}]
      for (const replacement of replacements) {
        const changed = JSON.parse(JSON.stringify(signed))
        const changedTarget = field === 'tenant' ? changed.supportedInterfaces[0]
          : field === 'required' ? changed.capabilities.extensions[0] : changed
        changedTarget[field] = replacement
        assert.equal((await verifyApsA2AAgentCardV1(changed, options)).code, 'A2A_SIGNATURE_INVALID')
      }
    }
  })

  it('omits empty OAuth scope maps while preserving populated maps and malformed lists', async () => {
    const { a2aCardSigningObjectV1 } = await import('../src/profiles/a2a/card-presence.js')
    for (const flow of ['implicit', 'password']) {
      for (const scopes of [{}, { read: 'Read access' }, []]) {
        const input = { securitySchemes: { oauth: { oauth2SecurityScheme: { flows: { [flow]: { scopes } } } } } }
        const output = a2aCardSigningObjectV1(input) as typeof input
        const normalized = output.securitySchemes.oauth.oauth2SecurityScheme.flows[flow]
        assert.equal(Object.hasOwn(normalized, 'scopes'), Array.isArray(scopes) || Object.keys(scopes).length > 0)
        if (Object.hasOwn(normalized, 'scopes')) assert.deepEqual(normalized.scopes, scopes)
      }
    }
  })

  it('keeps a verified legacy signature when another key lookup fails', async () => {
    const { canonicalizeJCS, canonicalizeJCSForWrite } = await import('../src/core/canonical-jcs.js')
    const { sign } = await import('../src/crypto/keys.js')
    const { agent, kid, params, base, options } = fixture()
    const card = attachApsIdentityExtensionV1(base, params)
    ;(card.capabilities.extensions![0] as Record<string, unknown>).required = false
    const protectedB64 = Buffer.from(canonicalizeJCSForWrite({ alg: 'EdDSA', kid, typ: 'JOSE' }), 'utf8').toString('base64url')
    const payloadB64 = Buffer.from(canonicalizeJCS(card), 'utf8').toString('base64url')
    const legacy = { protected: protectedB64, signature: Buffer.from(sign(`${protectedB64}.${payloadB64}`, agent.privateKey), 'hex').toString('base64url') }
    const unavailable = {
      protected: Buffer.from(canonicalizeJCSForWrite({ alg: 'EdDSA', kid: `${params.agent_id}#unavailable`, typ: 'JOSE' }), 'utf8').toString('base64url'),
      signature: legacy.signature,
    }
    for (const asyncFailure of [false, true]) {
      const resolve_key = ({ verification_method }: { verification_method: string }) => {
        if (verification_method === kid) return options.resolve_key()
        if (asyncFailure) return Promise.reject(new Error('network failed'))
        throw new Error('network failed')
      }
      for (const signatures of [[legacy, unavailable], [unavailable, legacy]]) {
        const verified = await verifyApsA2AAgentCardV1({ ...card, signatures }, { ...options, resolve_key })
        assert.equal(verified.state, 'valid')
        assert.equal(verified.payload_form, 'legacy_as_served')
      }
      const unresolved = await verifyApsA2AAgentCardV1({ ...card, signatures: [unavailable] }, { ...options, resolve_key })
      assert.equal(unresolved.state, 'indeterminate')
      assert.equal(unresolved.code, 'A2A_SIGNING_KEY_UNREACHABLE')
    }
  })

  it('still verifies a card signed over the served form by earlier releases', async () => {
    const { agent, kid, params, base, options } = fixture()
    const { canonicalizeJCS, canonicalizeJCSForWrite } = await import('../src/core/canonical-jcs.js')
    const { sign } = await import('../src/crypto/keys.js')
    const extended = attachApsIdentityExtensionV1(base, params)
    const legacyCard = {
      ...extended,
      capabilities: {
        ...extended.capabilities,
        extensions: [{ ...(extended.capabilities.extensions![0] as Record<string, unknown>), required: false }],
      },
    }
    const protectedB64 = Buffer.from(canonicalizeJCSForWrite({ alg: 'EdDSA', kid, typ: 'JOSE' }), 'utf8').toString('base64url')
    const payloadB64 = Buffer.from(canonicalizeJCS(legacyCard), 'utf8').toString('base64url')
    const signature = Buffer.from(sign(`${protectedB64}.${payloadB64}`, agent.privateKey), 'hex').toString('base64url')
    const signed = { ...legacyCard, signatures: [{ protected: protectedB64, signature }] }
    const result = await verifyApsA2AAgentCardV1(signed, options)
    assert.equal(result.state, 'valid')
    assert.equal(result.payload_form, 'legacy_as_served')
    const changed = { ...signed, name: 'Refund Agent' }
    assert.equal((await verifyApsA2AAgentCardV1(changed, options)).state, 'invalid')
  })
})

describe('MCP aps-mcp-1 pre-dispatch middleware', () => {
  function setup() {
    const agent = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const authorization = issueApsMcpAuthorizationV1({
      agent_id: agentId,
      verification_method: `${agentId}#${agentId.slice('did:key:'.length)}`,
      delegation_ref: 'sha256:' + 'aa'.repeat(32),
      mcp_server: 'https://mcp.example',
      tool_name: 'checkout',
      arguments: { cart_id: 'cart-1' },
      scope_required: ['commerce:checkout'],
      spend: { unit: 'iso4217:USD:minor', amount: '5000' },
      nonce: '22'.repeat(16),
      issued_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2027-01-01T00:00:00.000Z',
      private_key_hex: agent.privateKey,
    })
    const request = {
      method: 'tools/call' as const,
      params: {
        name: 'checkout',
        arguments: { cart_id: 'cart-1' },
        _meta: { [APS_MCP_AUTHORIZATION_META]: authorization },
      },
    }
    return { agent, authorization, request }
  }

  it('denies before dispatch when transport authentication is absent', async () => {
    const { agent, request } = setup()
    let dispatched = false
    const middleware = createApsMcpToolCallMiddleware({
      mcp_server: 'https://mcp.example',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      consume_action_ref: () => true,
      evaluate_authority: () => ({ state: 'permit', code: 'OK' }),
      emit_receipt: () => ({ receipt_id: 'r1' }),
    })
    await assert.rejects(
      () => middleware(request, { transport_authenticated: false }, async () => {
        dispatched = true
        return { content: [] }
      }),
      (error: unknown) => error instanceof ApsMcpAuthorizationError && error.code === 'MCP_TRANSPORT_UNAUTHENTICATED',
    )
    assert.equal(dispatched, false)
  })

  it('authorizes, dispatches once, returns a receipt, and rejects replay', async () => {
    const { agent, request } = setup()
    const seen = new Set<string>()
    let dispatches = 0
    const middleware = createApsMcpToolCallMiddleware({
      mcp_server: 'https://mcp.example',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      consume_action_ref: (ref) => seen.has(ref) ? false : (seen.add(ref), true),
      evaluate_authority: () => ({ state: 'permit', code: 'OK', decision_ref: 'bb'.repeat(32) }),
      emit_receipt: (authorization) => ({ action_ref: authorization.action_ref }),
    })
    const response = await middleware(request, { transport_authenticated: true }, async () => {
      dispatches++
      return { content: [{ type: 'text', text: 'ok' }] }
    })
    assert.equal(dispatches, 1)
    assert.ok(response._meta?.[APS_MCP_RECEIPT_META])
    await assert.rejects(
      () => middleware(request, { transport_authenticated: true }, async () => {
        dispatches++
        return { content: [] }
      }),
      (error: unknown) => error instanceof ApsMcpAuthorizationError && error.code === 'MCP_ACTION_REPLAY',
    )
    assert.equal(dispatches, 1)
  })
})
