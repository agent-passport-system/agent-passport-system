// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// How the identity-binding verifiers classify a historical key resolution that did not
// produce usable key material. Draft-04 section 3.5 maps an unsupported identifier scheme
// to unsupported, and a key or subject that is not found, an ambiguous answer,
// structurally malformed key material and transport unreachability each to
// indeterminate, under distinct outcome names. Section 3.4 routes the agent's own
// retired-key case through the ambiguous outcome. The same mapping is applied here to
// the agent's own key and to the principal's key: in none of these branches was a
// signature checked against an established key, so nothing was learned about key
// authority. The delegation and revocation verifiers in src/v2 already map the issuer's
// key the same way.

import type { HistoricalKeyResolutionResult, IdentityVerificationState } from './types.js'

const KEY_HEX = /^[0-9a-fA-F]{64}$/

export interface ResolutionFailure {
  state: Extract<IdentityVerificationState, 'indeterminate' | 'unsupported'>
  /** Suffix for the caller's code prefix, for example `NOT_FOUND` in `PASSPORT_KEY_NOT_FOUND`. */
  outcome: 'NOT_FOUND' | 'AMBIGUOUS' | 'MALFORMED' | 'UNREACHABLE' | 'UNSUPPORTED' | 'RESOLUTION_FAILED'
}

/** Null when the resolver returned a usable 32-byte Ed25519 key as hex. Callers compare it lowercased. */
export function classifyResolution(resolution: HistoricalKeyResolutionResult | unknown): ResolutionFailure | null {
  const value = resolution as Partial<HistoricalKeyResolutionResult> | null | undefined
  const state = value && typeof value === 'object' ? value.state : undefined
  switch (state) {
    case 'resolved':
      return typeof value!.public_key_hex === 'string' && KEY_HEX.test(value!.public_key_hex)
        ? null
        : { state: 'indeterminate', outcome: 'MALFORMED' }
    case 'unsupported':
      return { state: 'unsupported', outcome: 'UNSUPPORTED' }
    case 'not_found':
      return { state: 'indeterminate', outcome: 'NOT_FOUND' }
    case 'ambiguous':
      return { state: 'indeterminate', outcome: 'AMBIGUOUS' }
    case 'malformed':
      return { state: 'indeterminate', outcome: 'MALFORMED' }
    case 'unreachable':
      return { state: 'indeterminate', outcome: 'UNREACHABLE' }
    default:
      return { state: 'indeterminate', outcome: 'RESOLUTION_FAILED' }
  }
}
