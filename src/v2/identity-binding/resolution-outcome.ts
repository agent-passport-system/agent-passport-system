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

import type { IdentityVerificationState } from './types.js'

const KEY_HEX = /^[0-9a-fA-F]{64}$/
const STATES = new Set(['resolved', 'not_found', 'ambiguous', 'malformed', 'unreachable', 'unsupported'])

export interface ResolutionFailure {
  state: Extract<IdentityVerificationState, 'indeterminate' | 'unsupported'>
  /** Suffix for the caller's code prefix, for example `NOT_FOUND` in `PASSPORT_KEY_NOT_FOUND`. */
  outcome: 'NOT_FOUND' | 'AMBIGUOUS' | 'MALFORMED' | 'UNREACHABLE' | 'UNSUPPORTED' | 'RESOLUTION_FAILED'
}

/** Either the usable key, lowercased, or the failure to report. Computed once per answer. */
export type ClassifiedResolution =
  | { ok: true; public_key_hex: string }
  | { ok: false; failure: ResolutionFailure }

/**
 * Read a resolver answer once and classify it. Only own data properties are read, so a
 * getter is never invoked and cannot throw or answer differently on a second read. An
 * answer that is not a plain object, carries an accessor or a state outside the contract,
 * or cannot be inspected at all, is RESOLUTION_FAILED. Callers use the returned key and
 * never read the original answer again.
 */
export function classifyResolution(resolution: unknown): ClassifiedResolution {
  let state: unknown
  let key: unknown
  try {
    if (resolution === null || typeof resolution !== 'object' || Array.isArray(resolution)) return failed()
    const stateDescriptor = Object.getOwnPropertyDescriptor(resolution, 'state')
    const keyDescriptor = Object.getOwnPropertyDescriptor(resolution, 'public_key_hex')
    if (!stateDescriptor || !('value' in stateDescriptor)) return failed()
    if (keyDescriptor && !('value' in keyDescriptor)) return failed()
    state = stateDescriptor.value
    key = keyDescriptor?.value
  } catch {
    // A proxy trap can throw from getOwnPropertyDescriptor.
    return failed()
  }
  if (typeof state !== 'string' || !STATES.has(state)) return failed()
  switch (state) {
    case 'resolved':
      return typeof key === 'string' && KEY_HEX.test(key)
        ? { ok: true, public_key_hex: key.toLowerCase() }
        : { ok: false, failure: { state: 'indeterminate', outcome: 'MALFORMED' } }
    case 'unsupported':
      return { ok: false, failure: { state: 'unsupported', outcome: 'UNSUPPORTED' } }
    case 'not_found':
      return { ok: false, failure: { state: 'indeterminate', outcome: 'NOT_FOUND' } }
    case 'ambiguous':
      return { ok: false, failure: { state: 'indeterminate', outcome: 'AMBIGUOUS' } }
    case 'malformed':
      return { ok: false, failure: { state: 'indeterminate', outcome: 'MALFORMED' } }
    default:
      return { ok: false, failure: { state: 'indeterminate', outcome: 'UNREACHABLE' } }
  }
}

function failed(): ClassifiedResolution {
  return { ok: false, failure: { state: 'indeterminate', outcome: 'RESOLUTION_FAILED' } }
}
