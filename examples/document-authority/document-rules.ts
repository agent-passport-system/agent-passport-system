// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The document share action, as pure functions. The gateway and the offline verifier both
// use these, so the verifier recomputes the target and scope from the signed payload
// instead of trusting either from the package.
//
// CANDIDATE PROFILE TEXT. draft-pidlisnyi-aps-04 section 5.1 says a profile defines its
// target string. For action_type "document.share" this example uses
//   "https://content.example/repositories/" + repository + "/documents/" + document_id
//     + "/versions/" + version + "/shares"
// and the scope grant
//   "content:share:" + repository + ":" + document_id + ":v" + version + ":"
//     + content_digest + ":" + recipient
// No published profile defines either. The grant names the exact bytes (content_digest)
// and the exact recipient, so authority given for one version of a document cannot be
// used for a later version with different content, or for anyone else.

import { createHash } from 'node:crypto'

export const DOCUMENT_SHARE_ACTION_TYPE = 'document.share'
export const DOCUMENT_SHARE_PROFILE = 'aps-example-document-share-v0'

export interface DocumentSharePayload {
  repository: string
  document_id: string
  /** Version number as a canonical decimal string. */
  version: string
  /** "sha256-" followed by 64 lowercase hex characters, over the version's bytes. */
  content_digest: string
  recipient: string
}

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/
const VERSION = /^[1-9][0-9]{0,8}$/
const DIGEST = /^sha256-[0-9a-f]{64}$/
const FIELDS = ['content_digest', 'document_id', 'recipient', 'repository', 'version'] as const

export const contentDigest = (bytes: string | Uint8Array): string =>
  'sha256-' + createHash('sha256').update(bytes).digest('hex')

export const shareTarget = (p: DocumentSharePayload): string =>
  `https://content.example/repositories/${p.repository}/documents/${p.document_id}/versions/${p.version}/shares`

export const shareScope = (p: DocumentSharePayload): string =>
  `content:share:${p.repository}:${p.document_id}:v${p.version}:${p.content_digest}:${p.recipient}`

/** null when the payload is a well-formed share request, otherwise the refusal reason. */
export function validateSharePayload(x: unknown): string | null {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) return 'payload_not_object'
  const keys = Object.keys(x).sort()
  if (keys.length !== FIELDS.length || keys.some((k, i) => k !== FIELDS[i])) return 'payload_fields_invalid'
  const p = x as Record<string, unknown>
  if (typeof p.repository !== 'string' || !SLUG.test(p.repository)) return 'repository_invalid'
  if (typeof p.document_id !== 'string' || !SLUG.test(p.document_id)) return 'document_id_invalid'
  if (typeof p.version !== 'string' || !VERSION.test(p.version)) return 'version_invalid'
  if (typeof p.content_digest !== 'string' || !DIGEST.test(p.content_digest)) return 'content_digest_invalid'
  if (typeof p.recipient !== 'string' || !SLUG.test(p.recipient)) return 'recipient_invalid'
  return null
}
