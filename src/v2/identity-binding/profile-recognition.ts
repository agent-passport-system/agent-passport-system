// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import type { IdentityVerificationResult } from './types.js'

/**
 * Profile recognition before the schema, the rule draft-04 states for the delegation and
 * revocation record families, shared by verifyPassportV2 and verifyPrincipalBindingV1.
 *
 * A string record_type other than the family's is unsupported whatever else the object
 * carries. With the recognised record_type, a string version other than the implemented one
 * is unsupported. An unsupported record is not judged against the schema and never reaches
 * the key resolver.
 *
 * Everything else returns null and goes to the family's schema check, which reports it
 * malformed: a value that is not a plain JSON object, a missing or non-string record_type,
 * the recognised record_type with a missing or non-string version, and a broken shape. Both
 * discriminators are read here once each, as own data properties, and an accessor on either
 * is reported before the schema check reads them again, so an accessor never answers
 * differently here and in the schema check. An accessor record_type is malformed. version
 * is read only when record_type is the recognised one, so an accessor version is malformed
 * only then, and an unknown record_type is unsupported whatever version holds.
 */
export function unrecognisedProfile(
  value: unknown,
  profile: { record_type: string; version: string; code_prefix: string },
): IdentityVerificationResult | null {
  const malformed: IdentityVerificationResult = {
    state: 'invalid', code: `${profile.code_prefix}_MALFORMED`, proof_of_possession: false, key_authority: 'rejected',
  }
  // A proxy can throw from its prototype or descriptor trap. That object is not a plain
  // JSON object, so it is malformed, as the schema check would report it, and never an
  // exception out of the verifier.
  try {
    return recognise(value, profile, malformed)
  } catch {
    return malformed
  }
}

function recognise(
  value: unknown,
  profile: { record_type: string; version: string; code_prefix: string },
  malformed: IdentityVerificationResult,
): IdentityVerificationResult | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return null
  const recordType = ownData(value, 'record_type')
  if (recordType === ACCESSOR) return malformed
  if (typeof recordType !== 'string') return null
  if (recordType !== profile.record_type) {
    return { state: 'unsupported', code: `${profile.code_prefix}_UNSUPPORTED_RECORD_TYPE`, proof_of_possession: false, key_authority: 'unresolved' }
  }
  const version = ownData(value, 'version')
  if (version === ACCESSOR) return malformed
  if (typeof version !== 'string') return null
  if (version !== profile.version) {
    return { state: 'unsupported', code: `${profile.code_prefix}_UNSUPPORTED_VERSION`, proof_of_possession: false, key_authority: 'unresolved' }
  }
  return null
}

const ACCESSOR = Symbol('accessor')

/** The value of an own data property, undefined when absent, ACCESSOR for a getter or setter. */
function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key)
  if (!descriptor) return undefined
  return 'value' in descriptor ? descriptor.value : ACCESSOR
}
