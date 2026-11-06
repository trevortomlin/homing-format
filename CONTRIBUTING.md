# Contributing to homing-format

Thanks for your interest in improving homing-format. Bug reports, documentation fixes, tests
and code are all welcome.

## Before you start

- For anything larger than a small fix, **open an issue first** so we can agree on the
  approach.
- Changes to the package format, signatures or error codes affect every device in the field.
  They need an issue that explains the motivation and the compatibility impact before any code.
- To report a security vulnerability, **do not open an issue**. Follow [SECURITY.md](SECURITY.md).

## Development

You need Rust 1.85 or newer (`rustup` recommended).

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo +1.85 test                              # minimum supported Rust version
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI runs all of these, plus a license and advisory check with
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) (`cargo deny check`).

## Guidelines

- **Tests:** every change needs them. Security-relevant code (signature checks, archive
  extraction, path handling) must fail closed and needs negative tests: hostile input that
  must be rejected with the right error code.
- **No `unsafe`:** the crate forbids it.
- **Dependencies:** keep them few. They must use permissive licenses (MIT, Apache-2.0, BSD, ISC,
  Zlib or similar); no GPL, LGPL or AGPL.
- **Documentation:** public items need doc comments. Update README.md when behavior or the
  format changes, and add an entry under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`,
  `test:`, ...). Mark breaking changes with `!` (for example `feat!:`).
- Sign off every commit (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- Keep pull requests focused, one logical change each. CI must pass before merge.

## License

By contributing, you agree that your contributions are licensed under the MIT license of this
repository.
