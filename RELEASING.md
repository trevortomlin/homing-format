# Releasing homing-format

Releases follow [Semantic Versioning](https://semver.org/). Before 1.0, a minor version
(0.x → 0.(x+1)) may break the API or the format; a patch version must not. CI's `semver` job
compares the public API with the last release tag and fails on accidental breaking changes.

A format change (anything that makes old packages or indexes invalid, or new ones unreadable
by old verifiers) always needs a minor version and a **Format** note in the changelog,
because devices in the field may run older verifiers.

## Checklist

1. Make sure `main` is green (CI and Fuzz) and the Dependabot PRs are handled.
2. Update `version` in `Cargo.toml` (and `Cargo.lock` with `cargo check`).
3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a new empty
   `## [Unreleased]`, and add the comparison links at the bottom.
4. If the format changed, regenerate the vectors (`cargo run --example gen-vectors`) and
   check that `schemas/` still agrees (`cargo test`).
5. Commit (`chore: release vX.Y.Z`, signed off), then tag and push:

   ```sh
   git tag -s vX.Y.Z -m "homing-format vX.Y.Z"
   git push origin main vX.Y.Z
   ```

6. Publish: `cargo publish --dry-run`, then `cargo publish`.
7. Create a GitHub release from the tag with the changelog section as notes.
8. Bump `homing-format` in homing-cli and homing-agent.
