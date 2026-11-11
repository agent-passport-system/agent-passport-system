// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// A mock content repository and the document share profile that drives it.
//
// The repository keeps its own share log, separate from anything APS signs. That log
// stands in for a content platform's own audit record. reconcile.ts compares the two, so
// that "the gateway says the repository reported a share" and "the repository has a
// record of the share" are checked as separate facts.

import { randomBytes } from 'node:crypto'
import type { ActionProfile } from './engine.ts'
import {
  DOCUMENT_SHARE_ACTION_TYPE, DOCUMENT_SHARE_PROFILE, contentDigest, shareScope, shareTarget, validateSharePayload,
} from './document-rules.ts'
import type { DocumentSharePayload } from './document-rules.ts'

export interface ShareLogEntry {
  share_id: string
  repository: string
  document_id: string
  version: string
  content_digest: string
  recipient: string
  /** The caller's correlation identifier. The gateway passes the action_ref. */
  correlation_id: string
  shared_at: string
}

export class MockContentRepository {
  readonly system = 'mock-content-repository'
  private readonly store = new Map<string, Uint8Array>()
  private readonly log: ShareLogEntry[] = []
  private readonly now: () => string

  constructor(now: () => string) { this.now = now }

  private static key(repository: string, documentId: string, version: string): string {
    return `${repository}\u0000${documentId}\u0000${version}`
  }

  /** Store a version and return its content digest. Calling it again for the same
   *  version replaces the bytes, which is how the tests model a tampered repository. */
  put(repository: string, documentId: string, version: string, content: string): string {
    const bytes = new TextEncoder().encode(content)
    this.store.set(MockContentRepository.key(repository, documentId, version), bytes)
    return contentDigest(bytes)
  }

  digestOf(repository: string, documentId: string, version: string): string | null {
    const bytes = this.store.get(MockContentRepository.key(repository, documentId, version))
    return bytes ? contentDigest(bytes) : null
  }

  /** Share one version with one recipient. The repository checks the stored bytes still
   *  match the digest it was asked to share, independently of the gateway. */
  share(req: DocumentSharePayload & { correlation_id: string }): { ok: true; share_id: string } | { ok: false; error_code: string } {
    const digest = this.digestOf(req.repository, req.document_id, req.version)
    if (digest === null) return { ok: false, error_code: 'document_version_not_found' }
    if (digest !== req.content_digest) return { ok: false, error_code: 'content_digest_mismatch' }
    const share_id = `shr_${randomBytes(8).toString('hex')}`
    this.log.push({
      share_id, repository: req.repository, document_id: req.document_id, version: req.version,
      content_digest: req.content_digest, recipient: req.recipient, correlation_id: req.correlation_id, shared_at: this.now(),
    })
    return { ok: true, share_id }
  }

  /** The repository's own record of every share, as an operator would export it. */
  exportLog(): ShareLogEntry[] {
    return this.log.map(e => ({ ...e }))
  }
}

export interface ShareProfileOptions {
  /** Replace the repository call, for failure tests. */
  execute?: ActionProfile<DocumentSharePayload>['execute']
}

export function documentShareProfile(repo: MockContentRepository, opts: ShareProfileOptions = {}): ActionProfile<DocumentSharePayload> {
  return {
    id: DOCUMENT_SHARE_PROFILE,
    actionType: DOCUMENT_SHARE_ACTION_TYPE,
    validate: validateSharePayload,
    target: shareTarget,
    scope: shareScope,
    check: p => {
      const digest = repo.digestOf(p.repository, p.document_id, p.version)
      if (digest === null) return 'document_version_not_found'
      return digest === p.content_digest ? null : 'content_digest_mismatch'
    },
    policyInput: p => ({ ...p }),
    execute: opts.execute ?? (async ({ action_ref, payload }) => {
      const r = repo.share({ ...payload, correlation_id: action_ref })
      return r.ok ? { status: 'succeeded', effect_id: r.share_id } : { status: 'failed', error_code: r.error_code }
    }),
  }
}
