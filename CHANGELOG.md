# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0,
minor versions may contain breaking changes.

## [Unreleased]

### Added

- Ed25519 key files, key ids and domain-separated detached signatures with strict
  verification.
- Trust stores of `prod-*` and `dev-*` public keys that fail closed on misnamed or duplicate
  keys.
- `manifest.json` model with parsing and semantic validation.
- Streaming `verify`, `verify_and_extract`, `verify_head` and `inspect` for `.homing`
  packages (tar, optionally zstd), with hostile-archive tests.
- Deterministic `PackageWriter`.
- Device compatibility checks (`engine.json`) and anti-rollback floors.
- Shared error codes (`E_SCHEMA`, `E_SIG`, `E_HASH`, ...).
