import Lake
open Lake DSL

package VSEL where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib VSEL where
  srcDir := "."
  roots := #[`VSEL]

lean_exe vselCheck where
  root := `VSEL.Checker.Main
