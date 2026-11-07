//! Reference implementation of the **homing** package format: signed, versioned app packages
//! for embedded Linux devices that run Flutter apps.
//!
//! This crate parses, verifies, writes and safely extracts `.homing` packages, and handles the
//! signed update index that HTTP update sources serve. Every check fails closed and reports one
//! of the [`ErrorCode`]s shared by all homing tools (`E_SIG`, `E_HASH`, `E_PATH`, ...).
//!
//! # Overview
//!
//! | Task | API |
//! |---|---|
//! | Create keys | [`SecretKey::generate`], [`SecretKey::write_new`], [`PublicKey::to_file_string`] |
//! | Trusted keys | [`TrustStore::load_dir`] (`prod-*.pub`, `dev-*.pub`) |
//! | Build a package | [`Manifest::new`], [`PackageWriter`] |
//! | Verify a package | [`verify`], [`verify_head`] (signature only), [`inspect`] (no trust) |
//! | Install a package | [`verify_and_extract`] |
//! | Device checks | [`DeviceInfo`] (`engine.json`), [`VerifyOptions`] |
//! | Update index | [`Index`], [`verify_index`], [`Index::select`] |
//!
//! # Example
//!
//! ```
//! use homing_format::manifest::{Arch, Compat, Graphics};
//! use homing_format::{DeviceInfo, KeyRole, Manifest, PackageWriter, SecretKey, TrustStore, VerifyOptions};
//!
//! # fn main() -> homing_format::Result<()> {
//! let key = SecretKey::generate()?;
//! let mut writer = PackageWriter::new(0);
//! writer.add_bytes("bundle/flutter_assets/AssetManifest.json", b"{}".to_vec(), false)?;
//! writer.add_bytes("bundle/lib/libapp.so", vec![0; 64], false)?;
//! let engine = "0123456789abcdef0123456789abcdef01234567";
//! let manifest = Manifest::new("com.example.hello", "Hello", "1.0.0", 1, Compat::new(engine, Arch::Aarch64));
//! let mut package = Vec::new();
//! writer.write(manifest, &key, &mut package)?;
//!
//! let mut trust = TrustStore::new(false);
//! trust.add(key.public_key("release"), KeyRole::Prod)?;
//! let device = DeviceInfo::new(engine, Arch::Aarch64, "raspberrypi3-64", vec![Graphics::DrmGles], "1.0.0");
//!
//! let staging = tempfile::tempdir().expect("tempdir");
//! let dest = staging.path().join("slot");
//! let verified = homing_format::verify_and_extract(
//!     &package[..],
//!     VerifyOptions::new(&trust).device(&device),
//!     &dest,
//! )?;
//! assert_eq!(verified.manifest.version_code, 1);
//! assert!(dest.join("bundle/lib/libapp.so").exists());
//! # Ok(())
//! # }
//! ```
//!
//! The [README](https://github.com/trevortomlin/homing-format#readme) describes the format,
//! the security model and the language-neutral test vectors.
//!
//! **Pre-alpha:** the format may still change in incompatible ways before 0.1.0.

pub mod device;
pub mod error;
pub mod index;
pub mod keys;
pub mod manifest;
pub mod package;
pub mod path;
pub mod sig;
pub mod trust;
pub mod writer;

pub use device::DeviceInfo;
pub use error::{Error, ErrorCode, Result};
pub use index::{Index, IndexApp, IndexBuild, Selection, VerifiedIndex, verify_index};
pub use keys::{KeyId, PublicKey, SecretKey};
pub use manifest::Manifest;
pub use package::{
    VerifiedPackage, VerifyOptions, inspect, verify, verify_and_extract, verify_head,
};
pub use sig::{DocType, SigDoc};
pub use trust::{KeyRole, TrustStore};
pub use writer::PackageWriter;

// Compile and run the README example as a doctest so it cannot drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
