# CLAUDE.md
- This crate defines the homing package format: keys, signatures, the trust store, the manifest,
  archive rules and device compatibility. homing-cli and homing-agent depend on it.
- README.md documents the format publicly. Keep it in sync with the code in the same change. If
  a sibling `../homing-spec/` folder exists (a private maintainer checkout), its `spec/` chapters
  are the detailed normative text; keep them in agreement too.
- Keep `schemas/` and `test-vectors/` in sync with the code (tests enforce both; regenerate
  vectors with `cargo run --example gen-vectors`).
- Format changes break every device in the field: call them out in CHANGELOG.md and bump the
  version.
- Security-relevant code (signature checks, archive extraction, path handling) must fail closed and
  have negative tests.
- Keep dependencies minimal and permissively licensed (no GPL); `deny.toml` enforces this.
- All code and docs are MIT-licensed; never add files under another license.
- MSRV is Rust 1.85 (`rust-version`); CI tests stable and 1.85.
- Conventional commits; DCO sign-off (`git commit -s`).
