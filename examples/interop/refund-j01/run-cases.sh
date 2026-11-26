#!/usr/bin/env bash
# Runs the J01 verifier on a produced bundle and on the adversarial variants.
# Usage, from the worktree root: examples/interop/refund-j01/run-cases.sh <bundle> <seed> <at> <after-expiry> <work-dir>
# Writes tampered copies under <work-dir>/cases/ and full verifier output under <work-dir>/transcripts/.
# Prints one SUMMARY line per case with the exact verify command, exit code and failing checks.
set -u
BUNDLE=$1; SEED=$2; AT=$3; AFTER=$4; WORK=$5
TSX=node_modules/.bin/tsx
D=examples/interop/refund-j01
mkdir -p "$WORK/cases" "$WORK/transcripts"

run() { # name, bundle, at, expected-failing-checks
  local name=$1 b=$2 at=$3 expect=$4
  local cmd="$TSX $D/verify.ts --bundle $b --at $at"
  $cmd > "$WORK/transcripts/$name.txt" 2>&1
  local code=$?
  local failed
  failed=$(sed -n 's/^RESULT .* failed_checks=//p' "$WORK/transcripts/$name.txt")
  local verdict=UNEXPECTED
  [ "$failed" = "$expect" ] && verdict=AS_EXPECTED
  echo "SUMMARY $name | exit=$code | failed_checks=$failed | expected=$expect | $verdict"
  echo "  command: $cmd"
}

mk() { # case, rehash
  local out="$WORK/cases/$1-rehash-$2"
  $TSX $D/adversarial.ts --base "$BUNDLE" --out "$out" --seed "$SEED" --case "$1" --rehash-manifest "$2" > /dev/null || exit 2
  echo "$out"
}

run J01-demo-baseline "$BUNDLE" "$AT" none
run ADV1-amount-4001 "$(mk amount-4001 no)" "$AT" file_hashes_match_manifest,action_and_payload_binding
run ADV1b-amount-4001-manifest-rehashed "$(mk amount-4001 yes)" "$AT" action_and_payload_binding
run ADV2-decision-id-replaced "$(mk decision-id-replaced yes)" "$AT" approval_native_validity_composite,decision_ref_recomputed
run ADV3-expired-instant "$BUNDLE" "$AFTER" time_and_revocation_at_instant
run ADV4-prev-other-intent "$(mk prev-other-intent yes)" "$AT" intent_linkage
run ADV5-verdict-deny-resigned "$(mk verdict-deny yes)" "$AT" approval_verdict_permit,time_and_revocation_at_instant
run EXTRA-duplicate-member "$(mk duplicate-member yes)" "$AT" strict_parse_all_inputs,action_and_payload_binding
run EXTRA-signer-revoked-before-instant "$(mk signer-revoked yes)" "$AT" time_and_revocation_at_instant
