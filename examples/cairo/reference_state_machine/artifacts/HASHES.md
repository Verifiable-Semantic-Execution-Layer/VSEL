# VSEL Cairo Reference State Machine Hashes

Generated after local build, test, Stwo prove, and Stwo verify on 2026-06-05.

Build outputs under `target/` are intentionally generated artifacts. Reproduce them with the commands below before recomputing hashes.

Toolchain:

```text
scarb 2.16.0 (231227f3f 2026-02-18)
cairo 2.16.0
sierra 1.7.0
snforge 0.57.0
universal-sierra-compiler 2.7.0
scarb prove 2.16.0
scarb verify 2.16.0
```

Commands executed for the artifacts referenced by this manifest:

```sh
cd examples/cairo/reference_state_machine
scarb build
snforge test

cd semantic_core
scarb build
scarb test

cd ../executable
scarb build
scarb execute --print-program-output --arguments-file inputs/valid_transition.json
scarb prove --execute --arguments-file inputs/valid_transition.json --print-program-output
scarb verify --execution-id 6
```

Verified proof:

```text
executable/target/execute/vsel_reference_state_machine_exec/execution6/proof/proof.json
```

The proof above was accepted by local `scarb verify`. It is still not a VSEL final acceptance artifact: it is not packaged as VCAI/v1 and is not bound to VSEL witness, constraint, public-input, Lean-certificate, or adapter-certificate commitments.

Semantic replay output from `scarb execute`:

```text
7
1
1
1750884610196910000670276416677895
```

`scarb prove --execute --print-program-output` also prints prover/bootloader values before the semantic tuple; the semantic post-state remains the final tuple shown above.

## SHA-256

```text
ad9a0324dc546d725f306fc94ca30d9a23ad4f17faf88491f4d5092e15ee78e5  Scarb.toml
67866a00918646e47adce1d970abff2365f0c99e125b154a18a267669293ec77  Scarb.lock
936428bc44871cb52aa1a960370b353595e5ace3b3c5b7904a2d0afe43db6d6a  src/lib.cairo
83a9b4c50ce737ae4adced540a073ac8e7761149f23dd5bca47705676a103c9b  src/reference_contract.cairo
30726a2d4a9c26ecdb70066930b579a0cec5a78be11e343785c050691ede3b0c  tests/test_reference_state_machine.cairo
21a1426cc75c7e6b7f114710c426b42de08331b095db47ae86771dbf9bc72bd1  semantic_core/Scarb.toml
f350f365e6b0193dc9d54f778f6f6e1c1febe99e5f2aac18c0a7a04189df4735  semantic_core/Scarb.lock
4fd392ccece3cf2a4377058dc3f87401d1d63b110249071498836e75dbbf87cb  semantic_core/src/lib.cairo
99feac018c04f58b9f73a39b9ab4744d7c56ccaf9ad8667145dc878b90267905  executable/Scarb.toml
8ef28b86141d052580ec8e8a515bc70352e72cc84c0dda2e072aa40a84f86bbf  executable/Scarb.lock
559c2e8a1f4ce6c23cc29c6fdd5f03aeda440612465eb315d29f557e848e6e5f  executable/src/lib.cairo
81d3c427c237669b3572f073190141dc750fbcaaf2200389b99e443a632a79f3  executable/inputs/valid_transition.json
7a8b8a52d8ed6e025f5fbd1c0921e838cf4c1ec276c665ca247dbbe5c09f2672  target/dev/vsel_reference_state_machine_ReferenceStateMachine.contract_class.json
118b1164adab1b9b17749f2ef574034465a1beefccd48a83e97728735bb9abde  target/dev/vsel_reference_state_machine_ReferenceStateMachine.compiled_contract_class.json
df8e8d0374bb6d3b326d0af9535c6224cdb59378efcac88c66b8f4875d1f09f0  target/dev/vsel_reference_state_machine.starknet_artifacts.json
bb080833aa9fca83926026acec3476f4708f04cd4da7a04137ad3d469513620a  semantic_core/target/dev/vsel_reference_state_machine_core.sierra.json
7b2de5ac9c6c60058e1a990f88a71b34f7f82cac91f774d88e0eeeacccf9900c  executable/target/dev/vsel_reference_state_machine_exec.executable.json
b0ce830c242671e1051e6a43ec4a94452e1b6b67619dc1172f78ec169587a685  executable/target/execute/vsel_reference_state_machine_exec/execution6/proof/proof.json
730f857ebb9fde4b16e808e86fc6e3f26e5dbd306dc47a177cac4909b5a0fbd3  executable/target/execute/vsel_reference_state_machine_exec/execution6/prover_input.json
```

## SHA3-256

```text
4d5f3ad5d73cc9ef920104ed8e8f6892acf00d5b6c4ff09cfbdf3fe86aab4dfc  src/reference_contract.cairo
5c26f667bad5d556d1d74c3b0035f6a102066146308419182dfbbc456945faaf  semantic_core/src/lib.cairo
4751b9a408d583f309813b458692cb4cd29151857c2802f37e6754a522c374a4  target/dev/vsel_reference_state_machine_ReferenceStateMachine.contract_class.json
608fd7cc063a59f1f300ccfc9ecba3b836a6fbfb8d8e800b61a33f0568b661ea  target/dev/vsel_reference_state_machine_ReferenceStateMachine.compiled_contract_class.json
4f9e88f4967d6d4d7bc88ed36a8a2f414536d023e20d27867170e58665f02e6f  executable/target/dev/vsel_reference_state_machine_exec.executable.json
d0e44cc9f0a518f2c2c35e3434cf2023ee5f669177e56a07e1540fc6406f7d29  executable/target/execute/vsel_reference_state_machine_exec/execution6/proof/proof.json
72e7d198e13049e97c8296c33fcd749b850aa45f54f848088fdd7ff9df74042d  executable/target/execute/vsel_reference_state_machine_exec/execution6/prover_input.json
```

These hashes are review evidence only. A VSEL verifier must recompute commitments from supplied artifacts and must not trust this manifest as a verifier input.
