# governance_attestation reference verifier

`verify.ts` verifies a `governance_attestation` claim (draft v0.1, erratum 1, `specs/governance-attestation-schema.md`) and checks one action against it. It depends on `jose` only. Section 4 of the spec embeds this file, and the test fails if the two differ.

- `trustedIssuer(iss, jwks)` builds the trust configuration. Set it from your own configuration, never from a received envelope.
- `verifyGovernanceAttestation(jws, { trusted })` takes the compact JWS alone and checks the EdDSA signature against the trusted keys, the §1.6 schema, `iss` and freshness. It can also check an expected `delegation_chain_hash`.
- `authorizeAction(claim, { scope, amount, currency, subDelegate })` checks scope, delegation expiry, depth and spend. The claim is a snapshot, so this check reserves nothing. The gateway that executes the action has to reserve the spend.

```
npm ci
npm run typecheck
npm test
```

The tests sign claims with a generated key and cover an attacker key with the trusted `kid`, an attacker JWKS, a wrong `iss`, an unsigned token, malformed claims, stale, future and expired timestamps, an unparseable `expires_at`, chain binding, empty scopes, spend amount and currency, delegation expiry, depth and `tool_restrictions`.
