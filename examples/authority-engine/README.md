# Authority gateway engine

The two-phase enforcement boundary that `examples/payment-authority` and
`examples/document-authority` both run on. It is reference code for those examples, in
one process with in-memory state. It is not a hosted service and not part of the
`agent-passport-system` public API.

`authorize()` runs synchronously for every request. It recomputes the action reference,
checks the agent's signed intent, allows one decision per agent nonce inside a replay
window, verifies the whole delegation chain, applies the action profile, reserves any
budget against every bounded delegation in the chain, and signs a decision. `dispatch()`
consumes a permit once, checks expiry, the stored request, the chain and the profile check
again, and only then calls the external system and signs the result.

Everything specific to one kind of action is an `ActionProfile`: payload validation,
target, scope, an optional gateway-side check, an optional budget charge, the policy facts
a decision records, the refusal reasons that differ between actions, and the call to the
external system. `payment-authority/gateway.ts` and `document-authority/repository.ts`
each define one.

The examples install this folder as a package (`install-links=true` in their `.npmrc`),
so its import of `agent-passport-system` resolves to the version each example pins. After
editing `engine.ts`, run `npm ci` in each example. `npm install` does not refresh the copy,
and each example has a case (P0, D0) that fails while its copy differs from this file.

`npm install && npm run typecheck` checks this folder on its own.
