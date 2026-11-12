// Reference verifier for governance_attestation draft v0.1 (erratum 1).
// Dependencies: jose only. The caller supplies the trusted issuer and its keys. Nothing that
// decides trust is read from the response envelope.
import { compactVerify, createLocalJWKSet, createRemoteJWKSet, type JSONWebKeySet } from 'jose'

export interface ActiveConstraints {
  scopes: string[]
  spend_limit: number | null
  spend_used: number
  spend_currency?: string
  tool_restrictions?: string[]
  max_depth?: number
  current_depth?: number
  expires_at?: string
}

export interface GovernanceAttestation {
  signal_type: 'governance_attestation'
  iss: string
  active_constraints: ActiveConstraints
  delegation_chain_hash: string
  evaluation_timestamp: string
  policy_version?: string
  gateway_id?: string
  attestation_grade?: 0 | 1 | 2 | 3
  expires_at?: string
}

export type Result<T> = { ok: true; value: T } | { ok: false; reason: string }

export type KeyResolver = ReturnType<typeof createLocalJWKSet> | ReturnType<typeof createRemoteJWKSet>

/** Trust configuration. Set it from your own configuration, never from a received envelope. */
export interface TrustedIssuer { iss: string; keys: KeyResolver }

export function trustedIssuer(iss: string, jwks: URL | JSONWebKeySet): TrustedIssuer {
  return { iss, keys: jwks instanceof URL ? createRemoteJWKSet(jwks) : createLocalJWKSet(jwks) }
}

export interface VerifyOptions {
  trusted: TrustedIssuer
  /** When you know which chain the claim must describe, its delegation_chain_hash. */
  expectedChainHash?: string
  now?: number
  maxAgeSeconds?: number
  clockSkewSeconds?: number
}

const fail = (reason: string) => ({ ok: false as const, reason })
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const isTime = (v: unknown): v is string =>
  typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v))
const TOP = ['signal_type', 'iss', 'active_constraints', 'delegation_chain_hash', 'evaluation_timestamp', 'policy_version', 'gateway_id', 'attestation_grade', 'expires_at']
const AC = ['scopes', 'spend_limit', 'spend_used', 'spend_currency', 'tool_restrictions', 'max_depth', 'current_depth', 'expires_at']

/** The §1.6 JSON Schema, checked by hand so the verifier needs no schema library. */
export function claimProblem(c: unknown): string | null {
  if (!isObj(c)) return 'claim is not an object'
  for (const k of Object.keys(c)) if (!TOP.includes(k)) return `property ${k} not allowed`
  if (c.signal_type !== 'governance_attestation') return 'wrong signal_type'
  if (typeof c.iss !== 'string') return 'iss missing'
  if (typeof c.delegation_chain_hash !== 'string' || !/^[0-9a-f]{64}$/.test(c.delegation_chain_hash)) return 'bad delegation_chain_hash'
  if (!isTime(c.evaluation_timestamp)) return 'bad evaluation_timestamp'
  for (const k of ['policy_version', 'gateway_id'] as const) if (k in c && typeof c[k] !== 'string') return `bad ${k}`
  if ('attestation_grade' in c && !(Number.isInteger(c.attestation_grade) && (c.attestation_grade as number) >= 0 && (c.attestation_grade as number) <= 3)) return 'bad attestation_grade'
  if ('expires_at' in c && !isTime(c.expires_at)) return 'bad expires_at'
  const a = c.active_constraints
  if (!isObj(a)) return 'active_constraints missing'
  for (const k of Object.keys(a)) if (!AC.includes(k)) return `active_constraints.${k} not allowed`
  if (!Array.isArray(a.scopes) || !a.scopes.every(s => typeof s === 'string')) return 'bad scopes'
  if (!('spend_limit' in a) || !(a.spend_limit === null || (isNum(a.spend_limit) && a.spend_limit >= 0))) return 'bad or missing spend_limit'
  if (!isNum(a.spend_used) || a.spend_used < 0) return 'bad spend_used'
  if ('spend_currency' in a && typeof a.spend_currency !== 'string') return 'bad spend_currency'
  if ('tool_restrictions' in a && !(Array.isArray(a.tool_restrictions) && a.tool_restrictions.every(s => typeof s === 'string'))) return 'bad tool_restrictions'
  for (const k of ['max_depth', 'current_depth'] as const) if (k in a && !(Number.isInteger(a[k]) && (a[k] as number) >= 0)) return `bad ${k}`
  if ('expires_at' in a && !isTime(a.expires_at)) return 'bad active_constraints.expires_at'
  return null
}

/**
 * Checks that a trusted gateway signed this claim recently and that the claim is well formed.
 * Pass the compact JWS only (the envelope's `jws` member). A valid result says what the gateway
 * stated, including a claim with no authority. Use authorizeAction to decide an action.
 */
export async function verifyGovernanceAttestation(jws: string, opts: VerifyOptions): Promise<Result<GovernanceAttestation>> {
  let bytes: Uint8Array
  try {
    const r = await compactVerify(jws, opts.trusted.keys, { algorithms: ['EdDSA'] })
    bytes = r.payload
  } catch (e) {
    return fail(`signature not verified with the trusted keys: ${(e as Error).message}`)
  }
  let claim: unknown
  try { claim = JSON.parse(new TextDecoder().decode(bytes)) } catch { return fail('payload is not JSON') }
  const problem = claimProblem(claim)
  if (problem) return fail(`claim does not match the schema: ${problem}`)
  const c = claim as GovernanceAttestation
  if (c.iss !== opts.trusted.iss) return fail('iss is not the trusted issuer')

  const now = opts.now ?? Date.now()
  const skew = (opts.clockSkewSeconds ?? 60) * 1000
  const evaluated = Date.parse(c.evaluation_timestamp)
  if (evaluated > now + skew) return fail('evaluation_timestamp is in the future')
  if (now - evaluated > (opts.maxAgeSeconds ?? 300) * 1000) return fail('attestation is stale')
  if (c.expires_at !== undefined) {
    const exp = Date.parse(c.expires_at)
    if (exp < evaluated) return fail('expires_at is before evaluation_timestamp')
    if (now >= exp) return fail('attestation expired')
  }
  if (opts.expectedChainHash !== undefined && c.delegation_chain_hash !== opts.expectedChainHash) {
    return fail('delegation_chain_hash is not the expected chain')
  }
  return { ok: true, value: c }
}

export interface ActionRequest {
  /** The scope the action needs. Compared exactly, which can refuse what the gateway would allow. */
  scope: string
  /** What the action would spend, in `currency`. Omit or 0 for no spend. */
  amount?: number
  currency?: string
  /** True when the action creates a further delegation. */
  subDelegate?: boolean
}

/**
 * Decides one action against a verified claim. The claim is a snapshot from evaluation time, so
 * this is a check, not a reservation: two actions can both pass against the same snapshot. The
 * gateway that executes the action must reserve the spend itself.
 */
export function authorizeAction(claim: GovernanceAttestation, req: ActionRequest, opts: { now?: number } = {}): Result<void> {
  const c = claim.active_constraints
  const now = opts.now ?? Date.now()
  if (c.scopes.length === 0) return fail('no active delegation')
  if (!c.scopes.includes(req.scope)) return fail(`scope "${req.scope}" not granted`)
  if (c.tool_restrictions && c.tool_restrictions.length > 0) return fail('tool_restrictions present, and v0.1 defines no rule to apply them')
  if (c.expires_at !== undefined && now >= Date.parse(c.expires_at)) return fail('delegation expired')
  if (c.current_depth !== undefined && c.max_depth !== undefined) {
    if (c.current_depth > c.max_depth) return fail('delegation depth exceeds max_depth')
    if (req.subDelegate && c.current_depth + 1 > c.max_depth) return fail('a further delegation would exceed max_depth')
  }
  const amount = req.amount ?? 0
  if (!isNum(amount) || amount < 0) return fail('bad amount')
  if (amount > 0) {
    if (c.spend_currency === undefined) return fail('the claim states no currency, so no spend can be checked')
    if (req.currency !== c.spend_currency) return fail('currency does not match the claim')
    if (c.spend_limit !== null && c.spend_used + amount > c.spend_limit) return fail('spend would exceed spend_limit')
  }
  return { ok: true, value: undefined }
}
