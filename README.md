# homing-format

[![CI](https://github.com/trevortomlin/homing-format/actions/workflows/ci.yml/badge.svg)](https://github.com/trevortomlin/homing-format/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange.svg)](#minimum-supported-rust-version)

Reference Rust implementation of the **homing** package format: signed, versioned app packages
for embedded Linux devices that run Flutter apps (flutter-pi, ivi-homescreen). This crate
parses, verifies, writes and safely extracts `.homing` packages.

homing is an independent project, not affiliated with Google or the Flutter project.

> **Status: pre-alpha.** The format may still change in incompatible ways before 0.1.0. It has
> not been audited. Do not rely on it to protect devices that matter yet.

## Features

- **Ed25519 signatures** with strict verification and domain separation, so a signature for one
  document type can never be replayed as another.
- **Trust stores** of production and development keys that fail closed on misconfiguration.
- **Streaming verify-and-extract.** The signature is checked before any payload byte is read.
  Every file is hashed while it is written, and on any error nothing is left behind.
- **Hostile-archive hardening.** Rejects path traversal, absolute paths, symlinks, hard links,
  device files, duplicate entries, unlisted or missing files and oversized metadata.
- **Deterministic writer.** The same inputs produce byte-identical packages, so builds are
  reproducible.
- **Device compatibility and anti-rollback checks** against the device's engine, architecture,
  machine, graphics backend and minimum version.
- **Signed update index** for HTTP sources, with selection of the newest build that fits a
  device. Safe to serve over plain `http://`.
- **One error code per failure class** (`E_SIG`, `E_HASH`, ...), shared by every homing tool.
- No `unsafe` code. Only permissively licensed dependencies. Continuously fuzzed.

## Installation

The crate is not on crates.io yet. Use it from Git:

```toml
[dependencies]
homing-format = { git = "https://github.com/trevortomlin/homing-format" }
```

## Usage

Write a package on the publisher side and verify it on the device:

```rust
use homing_format::manifest::{Arch, Compat, Graphics};
use homing_format::{
    DeviceInfo, ErrorCode, KeyRole, Manifest, PackageWriter, SecretKey, TrustStore, VerifyOptions,
};

const ENGINE: &str = "0123456789abcdef0123456789abcdef01234567"; // Flutter engine commit

fn main() -> homing_format::Result<()> {
    // Publisher: build a deterministic, signed package.
    let key = SecretKey::generate()?;
    let mut writer = PackageWriter::new(0); // archive mtime, e.g. SOURCE_DATE_EPOCH
    writer.add_bytes("bundle/flutter_assets/AssetManifest.json", b"{}".to_vec(), false)?;
    writer.add_bytes("bundle/lib/libapp.so", vec![0; 1024], false)?;
    writer.add_bytes("config/app.json", br#"{"greeting":"hi"}"#.to_vec(), false)?;

    let mut compat = Compat::new(ENGINE, Arch::Aarch64);
    compat.machines = vec!["raspberrypi3-64".into()];
    let manifest = Manifest::new("com.example.hello", "Hello", "1.0.0", 10000, compat);
    let mut package = Vec::new();
    writer.write(manifest, &key, &mut package)?; // hashes the files and signs

    // Device: trusted keys, the device's description and its anti-rollback floor.
    let mut trust = TrustStore::new(false);
    trust.add(key.public_key("release"), KeyRole::Prod)?;
    let device =
        DeviceInfo::new(ENGINE, Arch::Aarch64, "raspberrypi3-64", vec![Graphics::DrmGles], "1.0.0");
    let opts = VerifyOptions::new(&trust).device(&device).floor(0);

    let verified = homing_format::verify(&package[..], opts)?;
    assert_eq!(verified.manifest.id, "com.example.hello");

    // Any modification is rejected with a specific error code.
    let mut tampered = package.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xff;
    let err = homing_format::verify(&tampered[..], opts).unwrap_err();
    assert!(matches!(err.code(), ErrorCode::Sig | ErrorCode::Hash | ErrorCode::Schema));
    Ok(())
}
```

To install a package, use `verify_and_extract(reader, opts, staging_dir)`. It streams the
payload into a new staging directory and deletes that directory if anything fails. `verify_head`
checks only the signature, without the payload or a device. `inspect` reads the manifest without
any trust checks, for tooling.

Most users want the tools built on this crate instead:
[homing-cli](https://github.com/trevortomlin/homing-cli) (`homing pack`, `homing verify`, ...)
and [homing-agent](https://github.com/trevortomlin/homing-agent) (the on-device installer with
A/B slots and automatic rollback).

## Format overview

### Package (`.homing`)

A POSIX tar archive, optionally zstd-compressed. Readers detect compression from magic bytes,
not the file extension.

```text
manifest.json               entry 1, at most 1 MiB
manifest.sig                entry 2, at most 4 KiB
bundle/flutter_assets/...   required
bundle/lib/libapp.so        required for release and profile builds
bundle/icudtl.dat           optional; otherwise the device's engine copy is used
config/...                  optional, app-defined configuration
sbom/...                    optional (SPDX JSON recommended)
```

- Only regular files and directories are allowed. Paths are relative, normalized and at most
  255 bytes, with no `.` or `..` components and no duplicates.
- Only the executable bit is honored: files become 0644 or 0755. Owners, times and xattrs are
  ignored.
- Writers sort entries and use uid/gid 0 and a fixed mtime, so output is reproducible.
- `manifest.json` lists every payload file with its SHA-256 and size, along with the app id,
  version, monotonic `version_code`, build mode, embedder, compatibility requirements and
  health-check policy. Unknown fields inside security-relevant sections are rejected.

### Keys and signatures

- Ed25519 (RFC 8032), verified strictly: non-canonical `S` values and small-order keys are
  rejected.
- The signed message is domain-separated:
  `"homing/" || type || "/v1" || 0x00 || exact document bytes`, where `type` is `manifest`,
  `bundle` or `index`. Documents are verified as stored and never re-serialized.
- `manifest.sig` is JSON with exactly the fields `schema`, `alg` (`"ed25519"`), `key_id` and
  `sig`. Unknown fields are rejected.
- Key files are one line each: `homing-ed25519 <base64 public key>[ comment]`, or
  `homing-ed25519-secret <base64 seed>` (created with mode 0600). A key's `key_id` is the first
  16 hex characters of `sha256(public key)`.
- A trust store is a directory of `prod-*.pub` and `dev-*.pub` files. Any other `*.pub` name,
  or a duplicate key id, makes loading fail. Dev keys count only in dev mode.

### Update index (`index.json`)

An HTTP update source publishes `index.json` and a detached `index.json.sig` beside it:

```json
{
  "schema": 1,
  "generated": "2026-11-04T12:00:00Z",
  "apps": [
    { "id": "com.example.hello", "version": "1.2.0", "version_code": 10200,
      "builds": [
        { "engine_hash": "<40 hex>", "arch": "aarch64", "machines": ["raspberrypi3-64"],
          "url": "hello-1.2.0-aarch64.homing", "sha256": "<64 hex>", "size": 123456 } ] }
  ]
}
```

- `verify_index` checks the signature (domain `index`) over the exact bytes before parsing.
- An app may be listed once per version. Each build carries the same compatibility fields as a
  manifest (`engine_hash`, `arch`, `machines`, optional `graphics` and `base_image_min`).
- `url` is relative to the index URL, or an absolute `http://` or `https://` URL. Other schemes
  and scheme-relative URLs are rejected.
- `Index::select` returns the highest `version_code` above the installed version and the
  anti-rollback floor that has a compatible build, or reports that newer versions exist but
  none fits the device.
- The index is only a catalog: unknown fields in it are ignored, and every package it points to
  is still fully verified before installation.

### Verification order

1. Read `manifest.json` and `manifest.sig` (`E_SCHEMA`).
2. Look up the key (`E_KEY_UNKNOWN`) and verify the signature (`E_SIG`). This happens before
   anything else is parsed or any payload is read.
3. Validate the manifest (`E_SCHEMA`).
4. Check compatibility against the device (`E_ENGINE`, `E_ARCH`, `E_MACHINE`, `E_GRAPHICS`,
   `E_BASE_IMAGE`), then the anti-rollback floor (`E_ROLLBACK`).
5. Stream each payload entry: check its path (`E_PATH`), require it to be listed
   (`E_EXTRA_FILE`), and hash it while writing (`E_HASH`). Every listed file must appear.

### Error codes

| Code | Meaning |
|---|---|
| `E_SCHEMA` | Invalid JSON, schema violation, malformed key or signature file |
| `E_KEY_UNKNOWN` | Signing key not trusted (or a dev key outside dev mode) |
| `E_SIG` | Signature invalid |
| `E_HASH` | File hash or size mismatch |
| `E_EXTRA_FILE` | Archive entry not listed in the manifest, or listed but missing |
| `E_PATH` | Illegal path or entry type |
| `E_ENGINE` / `E_ARCH` / `E_MACHINE` / `E_GRAPHICS` / `E_BASE_IMAGE` | Not compatible with this device |
| `E_ROLLBACK` | `version_code` below the device's anti-rollback floor |
| `E_SPACE`, `E_HEALTH`, `E_BUSY`, `E_PERM`, `E_IO` | Used by installers (storage, health checks, concurrency, permissions, I/O) |

### JSON Schemas

[`schemas/`](schemas/) has JSON Schemas (draft 2020-12) for `manifest.json`, signature
documents (`*.sig`), `engine.json` and `index.json`. Each schema's `$comment` lists the few
cross-field rules a schema cannot express. Tests check that every schema gives the same verdict
as this crate's parser on valid and deliberately broken documents.

### Test vectors

[`test-vectors/`](test-vectors/) has language-neutral vectors for anyone implementing or testing a
verifier:
- valid packages, and at least one invalid package for every error code a verifier can return
  (hostile archives, bad or misdirected signatures, incompatible builds);
- signed indexes with expected build selections;
- the test-only keys and test device they need.

`vectors.json` lists each file with the settings to use and the expected result. The vectors
are generated by `cargo run --example gen-vectors`, and CI fails if the committed files differ
from the generator's output.

### Security model and limits

- Integrity comes only from signatures and hashes, never from TLS.
- Extraction assumes no other process can modify the staging directory or its parent while it
  runs. Put it in a directory only the installer can write to.
- Signatures carry no timestamps, because devices may have no reliable clock. A signed update
  index can therefore be replayed (a freeze attack). Anti-rollback floors prevent downgrades,
  but not the withholding of newer versions.
- There is no key revocation yet. Replacing a compromised key needs a trust-store update shipped
  by other means.

## Roadmap

- [x] Keys, signatures, trust store, manifest, path rules
- [x] Streaming verify-and-extract with hostile-archive tests; deterministic writer
- [x] Device compatibility checks and anti-rollback floors
- [x] Signed update index with device-aware build selection
- [ ] Multi-app bundles (`.homingb`) and install reports
- [x] Language-neutral test vectors (every verifier error code)
- [x] JSON Schemas, checked against the parser in CI
- [x] Fuzzing of the archive, manifest, signature, index and path code ([`fuzz/`](fuzz/))
- [ ] Publish to crates.io

## Minimum supported Rust version

Rust **1.85** (edition 2024). CI tests stable and 1.85. Raising the MSRV is treated as a
minor-version change.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues
privately, as described in [SECURITY.md](SECURITY.md). This project follows a
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under the [MIT License](LICENSE).
