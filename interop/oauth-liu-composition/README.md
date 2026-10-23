# OAuth composition vectors for the Liu draft family

Three runnable vectors that carry inputs shaped by the Liu OAuth drafts into
signed APS records another party can verify later. The pinned draft texts and
the field extraction live in drafts/. The full field map is MAPPING-TABLE.md.

## The vectors

vectors/v1-permit: an allow under a two-hop delegation_chain whose final hop
narrows the action set. The receipt binds the authorization evidence and the
chain state by digest.

vectors/v2-denial: the requested action falls outside the final hop's narrowed
subset. The signed denial names the requested action and the subset it
exceeded.

vectors/v3-observation: the Section 10.8 case where per-hop introspection is
impractical. A signed revocation observation captures what the relying party
consulted and decided; the field layout is in MAPPING-TABLE.md.

## Verify without the SDK

Node 18 or later, no installs:

    node independent-verify.mjs

From the committed files alone it recomputes:

- the strict JCS (RFC 8785) canonical form of every signed body
- each receipt_id
- the evidence digests from the fixtures in vectors/*/input.json
- every Ed25519 signature
- action_ref, decision_ref and delegation_ref, by the construction below

## Construction of action_ref and decision_ref

Every digest below is SHA-256 over UTF-8 bytes, written as 64 lowercase hex
characters. JCS is RFC 8785. A tagged digest is `sha256(tag || 0x00 || JCS(value))`.
All values are I-JSON with integer numbers only. The inputs come from
`vectors/<vector>/input.json`: the chain `C = delegation_chain`, its final hop
`F = C[last]`, the context `X = rego_decision_context` and `E = X.evaluated_input`.

**action_ref** is the tagged digest `APS-ACTION-REF-V2` over this eight-member object:

| member | value |
|---|---|
| `profile` | `"aps-action-ref-v2"` |
| `agent_id` | `F.delegatee_id` |
| `action_type` | `E.action` |
| `target` | `"item:" + E.item_id` |
| `payload_ref` | `sha256(JCS(E))`, untagged |
| `scope_required` | `[E.action]` |
| `issued_at` | the receipt's `issued_at` (both vectors: `2026-07-18T19:30:00.000Z`) |
| `nonce` | the first 32 hex characters of `sha256("liu-composition-" + vector)`, vector being `v1-permit` or `v2-denial` |

**decision_ref** is the tagged digest `APS-DECISION-REF-V1` over a six-member object.
`profile` is a fixed string, `action_ref` is the action_ref above as it is, not
tagged again, and the other four members are tagged digests of the four
components in the table.

| member | tag | component |
|---|---|---|
| `profile` | | `"aps-decision-ref-v1"` |
| `action_ref` | | the action_ref above |
| `authority_state_ref` | `APS-DECISION-AUTHORITY-V1` | `{"delegation_chain": C}` |
| `policy_ref` | `APS-DECISION-POLICY-V1` | `X.policy_ref` with `hash` replaced by `"sha256-" + base64(sha256(F.delegated_policy.content))`, standard base64 with padding |
| `context_ref` | `APS-DECISION-CONTEXT-V1` | `{"policy_ref": <the filled policy_ref>, "input_hash": "sha256:" + sha256(JCS(E)), "result": X.result, "evaluation_timestamp": X.evaluation_timestamp}` |
| `decision_output_ref` | `APS-DECISION-OUTPUT-V1` | the decision output below |

The decision output has four members. `N` is the narrowed subset: every string
`s` for which `F.delegated_policy.content` contains the clause `input.action == "s"`,
deduplicated and sorted by UTF-8 bytes. This pattern match is how the emitter reads
the two policies in these vectors. It is not a general rule for reading Rego.

- permit (`X.result` is `allow`): `{"profile": "aps-core-decision-output-v1", "verdict": "permit", "effective_authority_ref": <authority_state_ref>, "constraints": N}`
- deny: `{"profile": "aps-core-decision-output-v1", "verdict": "deny", "effective_authority_ref": null, "constraints": ["requested_action_outside_narrowed_subset:" + E.action]}`

`input.json` stores `input_hash` as `""` and `policy_ref.hash` as a placeholder.
The values above replace them, and the stored placeholders are never digested.

**delegation_ref** is `"liu-chain:sha256:" + sha256(JCS({"delegation_chain": C}))`,
the same digest as the chain `evidence_refs` entry.

These constructions reproduce the historical digests in the frozen vectors.
The current SDK rejects their four-member decision output, because
`valid_until` has been required in `CoreDecisionOutputV1` since 2026-07-23
(043a80f), after these vectors were emitted. Adding that member changes the
hashed preimage and the resulting reference. The current SDK also rejects
their `liu-chain:` delegation reference form.

## Verify through the SDK

From the repo root:

    npm ci
    npx tsx interop/oauth-liu-composition/verify-vectors.ts
    npx tsx --test interop/oauth-liu-composition/test.ts

The suite re-emits the vectors and checks byte stability, then runs tamper
cases on in-memory copies.

Fixture compatibility, 2026-10-23: both commands fail on the current main,
because these frozen vectors predate two requirements the validators now
enforce. `verify-vectors.ts` rejects v1-permit and v2-denial with
`ReceiptV1: delegation_ref`: the `sha256:<64 hex>` form has been required
since e78aaa3 (2026-09-19) and these vectors carry `liu-chain:sha256:…`.
`emit-vectors.ts` stops with `CoreDecisionOutputV1: missing field valid_until`
for the reason given above. Passing the checks in `independent-verify.mjs`
establishes the historical digests and signatures, not validity under the
current receipt profile. The committed vectors are unchanged, and a revision
that satisfies the current validators will be a new set of files with new
digests, beside these.

## Boundaries

The signing keys are fixed test keys published with the vectors; never reuse
them for any real identity. Evidence refs are digest-only, so re-deriving them
needs the input artifact, which is the intended model. Section 9.7 of the Rego
draft prescribes the audit tuple's content but not its JSON spellings; the
constructed spellings are marked in MAPPING-TABLE.md. The SET binding in v3
comes from APS record vocabulary; the chain-delegation draft names back-channel
notification without citing RFC 8417.
