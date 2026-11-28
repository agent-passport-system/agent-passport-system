import Lake
open Lake DSL

-- APS formal model. Lean 4.14.0, no Mathlib.
-- Every module is imported by APSFormal.lean, so the default target builds all of them.
package «APSFormal» where
  name := `APSFormal

@[default_target]
lean_lib «APSFormal» where
  roots := #[`APSFormal]
