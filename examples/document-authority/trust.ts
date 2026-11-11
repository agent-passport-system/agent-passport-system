// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Public keys with validity windows, and the independent time evidence a verifier may hold.
//
// A key resolves for a record only when the record's own timestamp falls inside the key's
// window. That timestamp is asserted by the signer. A valid signature therefore shows that
// the key signed the record, not that it signed it at the stated time. Whoever holds a
// retired key can still sign a record dated inside its old window.
//
// Two inputs, both supplied to the verifier separately from the package, change that:
//   - compromised_at on a trusted key. From then on the key's signatures are refused,
//     whatever date the record states, unless independent evidence shows the record
//     existed before the compromise.
//   - anchors, a content system's own record of when it stored a package, by package_id.
//     A package anchored before a key's compromised_at was signed before the compromise.
//
// The verifier never resolves a key or an anchor from the evidence package itself.

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
  /** Set by the verifier's own trust source when the private key is known to be exposed. */
  compromised_at?: string
}

/** A content system's record that it stored the package with this id at this time. */
export interface PackageAnchor {
  package_id: string
  recorded_at: string
  recorded_by: string
}

export interface TrustedKeys {
  profile: 'aps-example-trusted-keys-v0'
  /** Issuers whose root delegations the verifier accepts. */
  roots: string[]
  keys: KeyEntry[]
  anchors?: PackageAnchor[]
}

/** "sha256:" and the SHA-256 of the raw public key bytes. */
export const keyFingerprint = (publicKeyHex: string): string =>
  'sha256:' + createHash('sha256').update(Buffer.from(publicKeyHex, 'hex')).digest('hex')

/** True when a compromised key may still be accepted for a record dated `at` in a
 *  package anchored at `anchoredAt`. */
export function beforeCompromise(k: KeyEntry, at: string, anchoredAt?: string): boolean {
  if (k.compromised_at === undefined) return true
  const c = Date.parse(k.compromised_at)
  const a = anchoredAt === undefined ? NaN : Date.parse(anchoredAt)
  return Number.isFinite(c) && Number.isFinite(a) && a < c && Date.parse(at) < c
}

/** The one key for signer and key_id whose window contains `at`, otherwise undefined. */
export function keyAt(
  keys: readonly KeyEntry[], signer: string, keyId: string, at: string, anchoredAt?: string,
): string | undefined {
  const t = Date.parse(at)
  if (!Number.isFinite(t)) return undefined
  const hits = keys.filter(k =>
    k.signer === signer && k.key_id === keyId &&
    Date.parse(k.valid_from) <= t && (k.valid_until === null || t < Date.parse(k.valid_until)))
  if (hits.length !== 1 || !beforeCompromise(hits[0], at, anchoredAt)) return undefined
  return hits[0].public_key
}

/** Resolver for receipt signatures: (signer, key_id, issued_at). */
export const receiptKeyResolver = (keys: readonly KeyEntry[], anchoredAt?: string) =>
  (signer: string, keyId: string, issuedAt: string): string | undefined => keyAt(keys, signer, keyId, issuedAt, anchoredAt)

/** Resolver for delegation and revocation verification methods of the form "<issuer>#<key_id>". */
export const verificationKeyResolver = (keys: readonly KeyEntry[], anchoredAt?: string) =>
  (issuer: string, method: string, issuedAt: string): string | null => {
    if (!method.startsWith(issuer + '#')) return null
    return keyAt(keys, issuer, method.slice(issuer.length + 1), issuedAt, anchoredAt) ?? null
  }
