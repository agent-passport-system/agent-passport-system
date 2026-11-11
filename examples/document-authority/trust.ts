// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Public keys with validity windows. A key resolves for a record only when the record's
// own timestamp falls inside the key's window, so records signed before a rotation keep
// verifying after it, and a retired key cannot sign records dated after its retirement.
//
// The verifier builds its resolvers from a trusted key file it was given separately. It
// never resolves a key from the evidence package itself.

import { createHash } from 'node:crypto'

export interface KeyEntry {
  signer: string
  key_id: string
  algorithm: 'ed25519'
  /** Public key as lowercase hex, as agent-passport-system generateKeyPair() returns it. */
  public_key: string
  /** Inclusive. */
  valid_from: string
  /** Exclusive. null while the key is current. */
  valid_until: string | null
}

export interface TrustedKeys {
  profile: 'aps-example-trusted-keys-v0'
  /** Issuers whose root delegations the verifier accepts. */
  roots: string[]
  keys: KeyEntry[]
}

/** "sha256:" and the SHA-256 of the raw public key bytes. */
export const keyFingerprint = (publicKeyHex: string): string =>
  'sha256:' + createHash('sha256').update(Buffer.from(publicKeyHex, 'hex')).digest('hex')

/** The one key for signer and key_id whose window contains `at`, otherwise undefined. */
export function keyAt(keys: readonly KeyEntry[], signer: string, keyId: string, at: string): string | undefined {
  const t = Date.parse(at)
  if (!Number.isFinite(t)) return undefined
  const hits = keys.filter(k =>
    k.signer === signer && k.key_id === keyId &&
    Date.parse(k.valid_from) <= t && (k.valid_until === null || t < Date.parse(k.valid_until)))
  return hits.length === 1 ? hits[0].public_key : undefined
}

/** Resolver for receipt signatures: (signer, key_id, issued_at). */
export const receiptKeyResolver = (keys: readonly KeyEntry[]) =>
  (signer: string, keyId: string, issuedAt: string): string | undefined => keyAt(keys, signer, keyId, issuedAt)

/** Resolver for delegation and revocation verification methods of the form "<issuer>#<key_id>". */
export const verificationKeyResolver = (keys: readonly KeyEntry[]) =>
  (issuer: string, method: string, issuedAt: string): string | null => {
    if (!method.startsWith(issuer + '#')) return null
    return keyAt(keys, issuer, method.slice(issuer.length + 1), issuedAt) ?? null
  }
