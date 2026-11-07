//! Reference implementation of the homing package format: Ed25519 keys and domain-separated
//! signatures, trust stores, `manifest.json`, streaming verify-and-extract of `.homing`
//! packages, a deterministic writer, and device compatibility checks.
//!
//! Every check fails closed and reports one of the [`ErrorCode`]s shared by all homing tools.
//! See the [README](https://github.com/trevortomlin/homing-format#readme) for a format
//! overview and a complete example.
//!
//! Pre-alpha: the format may still change in incompatible ways.

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
