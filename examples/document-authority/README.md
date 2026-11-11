# Document authority gateway

A person allows an agent to share one version of one document with an approved recipient.
The agent passes a narrower permission to a second agent. A gateway checks every share
before it happens and refuses anything outside the permission: another recipient, another
version, or bytes that differ from the ones approved. When the person withdraws the
permission, the next share is refused.

Afterwards the gateway exports a portable evidence package. A separate verifier, holding
only public keys it trusts, checks the package without contacting the gateway. A second
check compares the package with the content repository's own share log, so that what the
gateway recorded and what the repository did are checked as separate facts.

This example builds on the same two-phase engine as `examples/payment-authority`, with the
parts specific to documents (payload, target, scope, repository check and the share call)
behind one `ActionProfile`. It uses the public `agent-passport-system` 8.0.1 package, test
keys and a mock repository, in one process.

## Run

```sh
cd examples/document-authority
npm install
npm run demo        # the walkthrough below, writes three files to out/
npm run verify      # checks out/evidence-package.json with out/trusted-keys.json only
npm run reconcile   # compares the package with out/repository-log.json
npm test            # 16 cases
```

`npm run typecheck` needs the development dependencies (`npm install --include=dev` if
your environment sets `NODE_ENV=production`).

## What the demo shows

| Step | Outcome |
|---|---|
| 1. A person allows Agent A, for one hour, to share version 3 of the Q3 board pack (those exact bytes) with `auditor-llp` or `outside-counsel` | issued |
| 2. Agent A tries to let Agent B share it with `press-desk` | refused when issued, `SCOPE_WIDENING` |
| 2. Agent A lets Agent B share it with `auditor-llp` only | issued |
| 3. Agent B tries `outside-counsel`, which Agent A may use and Agent B may not | refused, `not_in_delegated_scope` |
| 3. Agent B tries `press-desk` | refused, `not_in_delegated_scope` |
| 3. Agent B tries version 4 | refused, `not_in_delegated_scope` |
| 4. Agent B shares version 3 with `auditor-llp` through the mock repository | shared |
| The gateway rotates its signing key | later records are signed with `key-2` |
| 5. The person withdraws Agent A's permission | recorded |
| 5. Agent B tries `auditor-llp` again | refused, `authority_invalid:REVOKED` |
| 6. Export, then verify and reconcile from the files alone | every entry verifies, no discrepancies |

## How authority is bound to the document

The scope grant names the repository, the document, the version, the SHA-256 of that
version's bytes and the recipient:

```
content:share:board-room:q3-board-pack:v3:sha256-<64 hex>:auditor-llp
```

A grant for version 3 therefore cannot be used for version 4, and cannot be used for
version 3 if its bytes are replaced. The gateway also asks the repository for the digest of
the requested version, at authorization and again just before the share. The repository
checks the digest a third time when it shares. A request whose bytes no longer match is
refused at whichever point sees the change first, and nothing is shared.

## The evidence package

`out/evidence-package.json` holds the original signed records unchanged, with an index a
content system can use to file and search them:

| Field | Purpose |
|---|---|
| `package_id`, `entries[].entry_id` | Stable identifiers. The entry id is the action reference. The package id is a SHA-256 over the package content, export time excluded, so re-exporting the same records gives the same id. |
| `entries[].receipts` | The agent's signed intent, the gateway's signed decision and, when dispatch ran, its signed result |
| `entries[].document`, `entries[].recipient` | The exact version, digest and recipient |
| `entries[].timestamps` | When the agent signed the request, when the gateway decided and when it recorded the repository's answer |
| `entries[].repository_result` | The share id the repository reported. The signed result carries its SHA-256 as `effect_ref`. |
| `key_resolution` | Which key signed what, with fingerprints and validity windows |
| `delegations`, `revocations` | The signed delegation chain and every revocation the gateway recorded |

The index is not signed. The verifier recomputes every index field from the signed records
and rejects the package when one disagrees. `package_id` names the package and detects
accidental change. It is not a signature.

## What the verifier checks

`verify-package.ts` reads the package and a trusted key file. It resolves every key from
the trusted file, never from the package, and only inside the key's validity window, so
records signed before a rotation keep verifying and a retired key cannot sign anything
dated after its retirement. It imports nothing from the gateway, the repository or the
exporter, and the tests check that.

For every entry it checks that the action reference recomputes, that the intent is signed
by the agent, that the decision is signed by the gateway and binds the authority state,
policy input, reason and output it carries, that the result follows the decision, and that
the reported share id hashes to the signed `effect_ref`. For a permit it verifies the
delegation chain at decision time against a trusted root and recomputes the scope from the
signed payload, so a permit the gateway should not have given fails here even with a valid
signature (case D16). For a refusal that cites revocation it requires a verified revocation
in the package that took effect by then.

## What it does not establish

The verifier does not show that the repository shared anything. That is what
`reconcile.ts` checks, against the repository's own log, in both directions: a share the
gateway recorded must be in the log, and a share in the log with no APS permit is reported
as a share that did not go through this gateway. How far that log can be trusted depends
on the repository and how the log was obtained, not on APS.

It also does not show that no revocation existed which the package does not carry, that
the gateway's clock was right, or that the gateway handled requests it did not export.
Retention, legal hold and the legal standing of a record belong to the content platform
that stores the package. Signing a record does not make it a legally sufficient record.

## What comes from the SDK and what is written here

From `agent-passport-system` 8.0.1, unmodified: delegation issuance, chain verification and
revocation, action references, signed records and their verification, and JCS
canonicalization.

Written for this example: the engine's check order (`engine.ts`), the document share rules
(`document-rules.ts`), the mock repository and its profile (`repository.ts`), key windows
(`trust.ts`), the package format and exporter (`package-format.ts`, `export.ts`), the
verifier (`verify-package.ts`) and the reconciliation (`reconcile.ts`).

## Limits

- `examples/payment-authority` has not been moved onto `engine.ts` yet. The checks and the
  records are the same.
- One process, in memory, nonces never pruned, as in the payment example.
- The mock repository stands in for a content platform. Its share log is a list in memory
  that the demo writes to a file. A real integration would read the platform's own audit
  record through its API.
- The package profile `aps-example-evidence-package-v0`, the action type `document.share`,
  the target `https://content.example/repositories/<repository>/documents/<id>/versions/<n>/shares`
  and the grant shown above are candidate profile text for this example. No published
  profile defines them.
- Document delegations use an unbounded spend facet, because a share spends nothing. The
  engine still reserves a budget for profiles that charge one.

## Cases

| Case | What it checks |
|---|---|
| D1 | The six steps, exported and verified in a separate process, then one altered signed field refused there |
| D2 | A sub-delegation to another recipient, or to the whole document or repository, is refused when issued |
| D3 | Another version, other bytes and another recipient are refused |
| D4 | A repository that no longer holds the approved bytes: refused before anything is shared |
| D5 | Bytes replaced between authorization and dispatch: refused at admission |
| D6 | Revocation between authorization and dispatch: refused at admission, and the package must carry the revocation |
| D7 | A replayed request shares once |
| D8 | An edited reason, verdict or share id fails, even with the package id recomputed |
| D9 | Index fields that disagree with the signed records fail |
| D10 | Records under the old and new gateway keys verify, each only inside its window |
| D11 | The repository log is reconciled in both directions |
| D12 | When the repository call throws, the result is `unknown` and reported as such |
| D13 | The package id is stable across exports |
| D14 | A root the verifier does not trust fails every permit |
| D15 | The verifier and reconciler load no gateway, actor, repository or export code |
| D16 | A gateway with a policy bug signs a permit beyond scope, and the verifier refuses it |
