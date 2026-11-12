# `governance_attestation` Signal Schema

**Status:** Draft v0.1, erratum 1 (2026-11-11)

**Erratum 1.** This erratum aligns the parts of v0.1 that contradicted each other or the issuing gateway. It changes no field name, no field meaning and no signing format. The schema `$id` stays `governance-attestation-v0.1`.

1. §1.6 now lists `iss` in `required` and `properties`, and the §4 interface includes it. §1.2 already required `iss` and the earlier §4 snippet checked it, but the schema left it out while setting `additionalProperties: false`, so a literal validator refused every claim the gateway issued.
2. §1.6 now requires `active_constraints.spend_limit`. §1.4 and the earlier §4 snippet already typed it as required. A claim without it passed the old schema and then read as no cap in that snippet.
3. §1.2 now allows fractional seconds in `evaluation_timestamp`, which the schema's `date-time` format already accepted and the gateway emits.
4. §1 and §1.2 no longer call `delegation_chain_hash` a content address or a request identity. It is a fingerprint of the chain fields listed in §2.3.
5. §1.4 states what an empty `scopes` array means, and that the claim carries a subset of what the gateway enforces.
6. §2 states how this claim relates to the signature chain, and §2.3 states which input the canonicalization covers.
7. §3.2 states that only the decoded JWS payload is authoritative.
8. §4 is replaced. The earlier snippet took its keys and issuer from the envelope it verified, so a party with its own key could pass it. The new §4 takes trust from the caller's configuration and is the tested file `examples/governance-attestation-verifier/verify.ts`.

Items 1 and 2 change which claims the §1.6 schema accepts. A signed claim that carries `iss` and `spend_limit` and otherwise conforms now validates as it was signed, with no change to its bytes. The old schema refused such a claim because of `iss`. A claim that passed the old schema while missing `iss` or `spend_limit` fails the corrected one. The reference gateway has put both fields in every claim since it began issuing this signal, so none of its claims falls in that group.

**Context:** 5th signal type in A2A#1628 (douglasborthwick-crypto). Extends the 2-signature minimum to a 3-signature audit chain. Wraps `active_constraints` as a signed, JWKS-verifiable claim.

**Cross-references:**
- aeoess/agent-passport-system#11 (commit)
- a2aproject/A2A#1628 (extension review)
- douglasborthwick-crypto/insumer-examples#1 (reference implementation)

---

## 1. Schema Contract

A `governance_attestation` is a signed claim, emitted by a gateway, asserting the governance constraints and delegation state in effect for an agent at a point in time. It carries a fingerprint of the agent's delegation chain and can be verified against the gateway's published JWKS. The claim does not carry the agent's identifier, so it is evidence about a given agent only when the verifier fetched it for that agent from a gateway it already trusts.

### 1.1 Signal type identifier

```
signal_type: "governance_attestation"
```

### 1.2 Required fields

| Field | Type | Description |
|---|---|---|
| `signal_type` | `string` | Must be `"governance_attestation"`. Required per §1.6 JSON Schema. |
| `active_constraints` | `object` | Constraints the gateway states for the agent at attestation time. A subset of what the gateway enforces. See §1.4. |
| `delegation_chain_hash` | `string` | SHA-256 fingerprint of the canonicalized delegation chain (root → current), over the fields listed in §2.3. Matching hashes establish that those fields match. They do not establish that the underlying delegation records, agents, authorization state or decisions are the same. With no active delegation the chain is empty and the digest is that of `[]` for every agent. |
| `evaluation_timestamp` | `string` | RFC 3339 UTC timestamp at which constraints were evaluated. Fractional seconds are allowed. |
| `iss` | `string` | Issuer identifier (gateway URL). A verifier compares it with an issuer it trusts from its own configuration, never with a value taken from the envelope. |

### 1.3 Optional fields

| Field | Type | Description |
|---|---|---|
| `policy_version` | `string` | Floor/policy version the evaluator used (e.g. `"floor-v1.2.0"`). |
| `gateway_id` | `string` | Stable identifier of the issuing gateway (e.g. `"gateway.aeoess.com"`). |
| `attestation_grade` | `integer` | Passport grade 0–3 as the issuer assessed it. The claim carries no evidence for the grade. See §1.5. |
| `expires_at` | `string` | RFC 3339 UTC; after which the attestation MUST NOT be treated as fresh. |

### 1.4 `active_constraints` object

Shape derived from the public trust profile endpoint (`GET /api/v1/public/trust/:agentId`).

```ts
interface ActiveConstraints {
  scopes: string[]                    // granted delegation scopes, e.g. ["read:docs", "write:issues"]
  spend_limit: number | null          // cumulative cap; null = unlimited (not recommended)
  spend_used: number                  // cumulative spent so far
  spend_currency?: string             // ISO 4217 (e.g. "USD") or cryptocurrency ticker (e.g. "XNO")
  tool_restrictions?: string[]        // optional denylist of tool IDs
  max_depth?: number                  // sub-delegation depth ceiling
  current_depth?: number              // depth at evaluation time
  expires_at?: string                 // delegation expiry, independent of attestation expiry
}
```

All numeric fields are inclusive. A verifier rejects an action when any monotonic budget would be exceeded, or the requested scope is not authorized by any element in `scopes`.

Reading the constraint set (erratum 1):

- An empty `scopes` array is a conforming claim. It means the agent holds no delegated authority, whatever the spend fields say. The gateway issues it with `spend_limit: null` and `spend_used: 0` when the agent has no active delegation. Here `null` does not mean an unlimited budget.
- `spend_limit: null` means no cap only when `scopes` is not empty.
- `spend_limit` is always present. A verifier rejects a claim that omits it.
- A budget check needs the amount the action would spend. `spend_used` and `spend_limit` describe the state at evaluation time, and a claim alone does not authorize a new spend. When `spend_currency` is absent the claim states no unit, so a verifier must not compare its numbers with an amount in a currency the verifier assumed.
- The claim carries a subset of what the gateway enforces. The reference gateway also enforces delegation depth and carries only `scopes`, `spend_limit` and `spend_used`. A field that is absent is not evidence that the matching control is absent.
- v0.1 does not define how a scope string matches a requested scope. An exact string comparison, as in §4, is stricter than the reference gateway's rule and can refuse what the gateway would allow. A matching grammar for `scopes` and `tool_restrictions` belongs to a later schema version.

### 1.5 `attestation_grade` (0–3)

| Grade | Meaning |
|---|---|
| 0 | Self-signed (bare keypair) |
| 1 | Issuer countersigned |
| 2 | Runtime-bound (issuer + challenge-response + trusted attestation) |
| 3 | Runtime + principal bound |

Source: `src/core/attestation.ts#computePassportGrade`.

### 1.6 JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://aeoess.com/schemas/governance-attestation-v0.1.json",
  "title": "governance_attestation",
  "type": "object",
  "required": ["signal_type", "iss", "active_constraints", "delegation_chain_hash", "evaluation_timestamp"],
  "properties": {
    "signal_type": { "const": "governance_attestation" },
    "iss": { "type": "string" },
    "active_constraints": {
      "type": "object",
      "required": ["scopes", "spend_limit", "spend_used"],
      "properties": {
        "scopes": { "type": "array", "items": { "type": "string" } },
        "spend_limit": { "type": ["number", "null"], "minimum": 0 },
        "spend_used": { "type": "number", "minimum": 0 },
        "spend_currency": { "type": "string" },
        "tool_restrictions": { "type": "array", "items": { "type": "string" } },
        "max_depth": { "type": "integer", "minimum": 0 },
        "current_depth": { "type": "integer", "minimum": 0 },
        "expires_at": { "type": "string", "format": "date-time" }
      },
      "additionalProperties": false
    },
    "delegation_chain_hash": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "evaluation_timestamp": { "type": "string", "format": "date-time" },
    "policy_version": { "type": "string" },
    "gateway_id": { "type": "string" },
    "attestation_grade": { "type": "integer", "minimum": 0, "maximum": 3 },
    "expires_at": { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

---

## 2. 3-Signature Chain Structure

douglasborthwick's spec (A2A#1628) requires a 2-signature minimum: agent intent + evaluator decision. `governance_attestation` wraps this into the APS **three-signature chain** (`src/core/policy.ts`, `src/types/policy.ts`), appending a third signature that binds the executed action to the evaluated decision.

```
┌────────────────────────────────────────────────────────────┐
│  Sig 1: ActionIntent — signed by agent                     │
│  "I want to do X with scope S at time T"                   │
│  agent_private_key → sign(canonicalize(intent))            │
├────────────────────────────────────────────────────────────┤
│  Sig 2: PolicyDecision — signed by evaluator (gateway)     │
│  "Intent I checked against floor F → verdict V"            │
│  gateway_private_key → sign(canonicalize(decision))        │
├────────────────────────────────────────────────────────────┤
│  Sig 3: ActionReceipt — signed by executor                 │
│  "Decision D was honored; here's proof of execution"       │
│  executor_private_key → sign(canonicalize(receipt))        │
└────────────────────────────────────────────────────────────┘
                            │
                            ▼
              PolicyReceipt (binds all three)
              chain = { intentSignature, decisionSignature, receiptSignature }
```

### 2.1 Relation to douglasborthwick's 2-sig minimum

| douglasborthwick (A2A#1628) | APS 3-sig chain |
|---|---|
| Sig A — agent intent | **Sig 1** `ActionIntent.signature` |
| Sig B — evaluator decision | **Sig 2** `PolicyDecision.signature` |
| *(implicit: execution happened)* | **Sig 3** `ActionReceipt.signature` |

The third signature is not redundant. Without it, a verifier can prove that *an evaluation occurred* but not that *the evaluated action ran*. Sig 3 closes the gap between "permitted" and "executed" — the difference between a policy simulator and an enforcement gateway.

### 2.2 Independent verifiability

Each signature is independently verifiable:

1. Resolve the signer's public key via DID or JWKS (`/.well-known/jwks.json`).
2. Canonicalize the unsigned object (deterministic JSON).
3. Verify the Ed25519 signature.

No shared trust root is required. A third party holding only the `PolicyReceipt.chain` block can verify all three without contacting the gateway, *provided* it can resolve the three public keys.

**How this claim relates to the chain (erratum 1).** The reference gateway issues a `governance_attestation` on request, from the public trust endpoint in §3, and not inside a `PolicyReceipt`. It carries one signature, the gateway's, over the constraint set the gateway states for the agent at evaluation time. It does not replace any signature in the chain, and verifying it, as in §4, does not verify Sig 1, Sig 2 or Sig 3. Both this claim and the gateway's decision records carry `delegation_chain_hash`, computed per §2.3. Equal values show that the listed chain fields match. They do not show that a claim and a decision concern the same delegation records, agent or authorization state, because the hash leaves out delegation identifiers, signatures, expiry and revocation state.

### 2.3 Canonicalization

Canonicalization uses **aps-canonical-json** (sorted-keys, null-stripped), implemented in `src/core/canonical.ts`. This is a near-JCS profile that strips `null`/`undefined`-valued object keys before serializing. For strict RFC 8785 JCS, see `src/core/canonical-jcs.ts`.

- UTF-8
- Sorted object keys
- No insignificant whitespace
- `null`/`undefined`-valued object keys omitted (divergence from strict RFC 8785)
- Numbers in shortest round-trippable form

**Scope (erratum 1).** For this signal, the canonicalization above defines the input to `delegation_chain_hash`. It does not apply to the `governance_attestation` JWS. A verifier checks the compact JWS over its payload bytes exactly as received, and does not reserialize or canonicalize the claim. The claim's payload keeps `null` values such as `spend_limit: null`. The earlier list included second-precision timestamp normalization, which `canonicalize` does not perform and which this hash input does not need, since it holds no timestamps.

The chain input is a JSON array, root first, of one object per active delegation link: `parent` (the delegating agent's identifier), `child` (the delegate's identifier), `scope` (the scope string as stored) and `spend_limit` (a number, or `null` which is then omitted). Test vectors, SHA-256 over the canonical form shown:

| Chain | Canonical form | `delegation_chain_hash` |
|---|---|---|
| none | `[]` | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| one link, limit 5 | `[{"child":"a","parent":"root","scope":"read:docs","spend_limit":5}]` | `79cb50af244bbb9b9e16b2dc197b55f0c6327f27abea13aff6cd42bd5194387c` |
| one link, no limit | `[{"child":"a","parent":"root","scope":"read:docs"}]` | `9e0195d7a96d5f7d6a8efe78657c74fb8824755ec607784205a47915af83113d` |

An older copy of this draft published as a gist (2026-04-05) says the canonicalization follows strict RFC 8785, which keeps `null` values. That copy is superseded by this one, and the two produce different digests for any chain with a link that has no limit.

---

## 3. Live Payload Example

> **Endpoint:** `GET /api/v1/public/trust/:agentId?signal=governance_attestation` on `gateway.aeoess.com`. The default response (no `signal` param) returns the existing `passport_grade` shape for backward compatibility.

The following is a realistic attestation envelope. Keys, agent IDs, and signatures are illustrative — they are not drawn from a production tenant.

### 3.1 Unsigned claim

```json
{
  "signal_type": "governance_attestation",
  "iss": "https://gateway.aeoess.com",
  "gateway_id": "gateway.aeoess.com",
  "policy_version": "floor-v1.2.0",
  "attestation_grade": 2,
  "evaluation_timestamp": "2026-04-05T17:42:00Z",
  "expires_at": "2026-04-05T17:47:00Z",
  "delegation_chain_hash": "9c7a3f8d2b1e4a6c5f8d2b1e4a6c9c7a3f8d2b1e4a6c5f8d2b1e4a6c9c7a3f8d",
  "active_constraints": {
    "scopes": ["read:repo", "write:issue-comments", "spend:xno"],
    "spend_limit": 5.0,
    "spend_used": 1.237,
    "spend_currency": "XNO",
    "tool_restrictions": ["delete:*", "admin:*"],
    "max_depth": 3,
    "current_depth": 1,
    "expires_at": "2026-04-12T17:42:00Z"
  }
}
```

### 3.2 Signed envelope (JWS compact, from `GET /api/v1/public/trust/:agentId?signal=governance_attestation`)

```json
{
  "issuer": "https://gateway.aeoess.com",
  "type": "governance_attestation",
  "kid": "gateway-v1",
  "alg": "EdDSA",
  "jwks": "https://gateway.aeoess.com/.well-known/jwks.json",
  "signed": { "...": "the unsigned claim above" },
  "jws": "eyJhbGciOiJFZERTQSIsImtpZCI6ImdhdGV3YXktdjEifQ.eyJzaWduYWxfdHlwZSI6Imdvdm…Vudl9pc3N1ZSJ9.mZ4rK7PNCqP9h2n7Y4fVx8j3bLcKNhT5Xc-wFx8g2sYqDvA3tR1m7P0ZqR4nL2sC8vB9xT6fW3yH7dG4kJpM5Aw"
}
```

**Which part is signed (erratum 1).** The envelope is JSON, and only its `jws` member is a compact JWS. The other members, `signed` included, sit outside the signature and are copies for display. A consumer reads the claim from the decoded and verified JWS payload, takes the key from a JWKS location it trusts by its own configuration, and does not use `issuer`, `jwks`, `kid` or `alg` from the envelope to decide trust. The JWS payload has no `exp` or `iat`, so freshness comes from `evaluation_timestamp` and `expires_at`.

### 3.3 JWKS entry (publicly fetched)

```json
{
  "keys": [{
    "crv": "Ed25519",
    "x": "dvueukplyAkApX4kkIxblvU57u9KuOsAbyUgDv1HekY",
    "kty": "OKP",
    "kid": "gateway-v1",
    "alg": "EdDSA",
    "use": "sig"
  }]
}
```

---

## 4. Verification

**Erratum 1.** The snippet that stood here took its keys from `envelope.jwks` and checked `iss` against `envelope.issuer`. Both come from the unsigned envelope it was verifying, so anyone with their own key and their own JWKS URL could produce an envelope it accepted. It also passed an unparseable `expires_at` and a future `evaluation_timestamp`, ignored the delegation expiry and depth, could not check a spend amount, and fetched an endpoint that returns a different signal type. This section replaces it. The code below is `examples/governance-attestation-verifier/verify.ts` in this repository, tested there against an attacker key, an attacker JWKS, malformed claims, stale and future timestamps and spend checks.

A verifier does three things.

1. **Configure trust.** Choose the issuer and its JWKS location in your own configuration. Never take `issuer`, `jwks`, `kid` or `alg` from the envelope to decide trust.
2. **Verify the claim.** Pass only the compact JWS, the envelope's `jws` member, to `verifyGovernanceAttestation`. It checks the EdDSA signature with the trusted keys, the §1.6 schema, `iss`, and freshness. If you know which chain the claim must describe, pass its `delegation_chain_hash`. A valid result states what the gateway signed, which can be a claim with no authority.
3. **Authorize an action.** `authorizeAction` checks one action against a verified claim: scope, delegation expiry, depth, and the spend amount in the claim's currency. The claim is a snapshot from evaluation time, so this check is not a reservation. Two actions can both pass against one snapshot, and the gateway that executes an action must reserve the spend itself.

Scope matching is exact, which can refuse what the gateway would allow, since v0.1 defines no matching rule. For the same reason a claim with `tool_restrictions` is refused.

```ts
const trusted = trustedIssuer('https://gateway.aeoess.com', new URL('https://gateway.aeoess.com/.well-known/jwks.json'))
const envelope = await fetch(
  `https://gateway.aeoess.com/api/v1/public/trust/${encodeURIComponent(agentId)}?signal=governance_attestation`,
).then(r => r.json())
const verified = await verifyGovernanceAttestation(envelope.jws, { trusted })
if (!verified.ok) throw new Error(`refuse: ${verified.reason}`)
const allowed = authorizeAction(verified.value, { scope: 'write:issue-comments' })
if (!allowed.ok) throw new Error(`refuse action: ${allowed.reason}`)
```

The claim is evidence about `agentId` only because this code fetched it for that agent from the trusted gateway. The claim itself does not name the agent.

<!-- verify.ts begin -->
```ts
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
```
<!-- verify.ts end -->

---

## 5. Open questions (extension review)

1. Should `delegation_chain_hash` bind the *full resolved chain* (root delegation → current) or only the current delegation? Current APS implementation canonicalizes the full chain.
2. Is `spend_limit: null` too permissive for unattested agents? Suggest: require non-null for `attestation_grade < 2`.
3. Does `governance_attestation` need a replay nonce distinct from `evaluation_timestamp`? Current design relies on `expires_at` + short TTL (default 5 min).
4. Format alignment with SPIFFE JWT-SVID claim set and OpenID Federation 1.0 trust marks.

---

## 6. References

- `src/core/policy.ts` — 3-signature chain implementation (`createActionIntent`, `evaluateIntent`, `createPolicyReceipt`)
- `src/types/policy.ts` — `ActionIntent`, `PolicyDecision`, `PolicyReceipt` type definitions
- `src/core/attestation.ts` — `computePassportGrade`, `classifyEvidenceQuality`
- `src/core/canonical.ts` — aps-canonical-json (sorted-keys, null-stripped); near-JCS, not strict RFC 8785
- `src/core/canonical-jcs.ts` — strict RFC 8785 JCS canonicalization
- Gateway `/api/v1/public/trust/:agentId` — `active_constraints` source
- Gateway `/api/v1/public/trust/:agentId?signal=governance_attestation` returns the signed `governance_attestation` envelope (erratum 1). The `/api/v1/public/trust/:agentId/attestation` path returns a `passport_grade` envelope instead.
- Gateway `/.well-known/jwks.json` — EdDSA verification keys
