# homing-format test vectors

Language-neutral vectors for anyone implementing or testing a homing package verifier.

- `vectors.json` lists every vector with the verifier settings to use and the expected result:
  `PASS` or an exact error code. `not_covered` lists codes that only installers produce.
- `packages/`: `.homing` packages, valid and invalid (hostile archives, bad signatures,
  incompatible builds).
- `indexes/`: signed update indexes, plus expected build selections for the test device.
- `trust/`: the trust store to verify against (`prod-test.pub`, and `dev-test.pub`, which is
  honored only when `dev_mode` is true).
- `engine.json`: the test device (used when `check_device` is true).
- `keys/`: the matching secret keys. **TEST ONLY: never use them for anything real.**

Package settings: `dev_mode` (honor dev keys), `check_device` (check compatibility against
`engine.json`) and `floor` (anti-rollback floor). Paths in index `select` results are the
exact `url` strings from the index.

The files are generated deterministically by `cargo run --example gen-vectors`. CI fails if
they differ from what the generator produces. Do not edit them by hand.
