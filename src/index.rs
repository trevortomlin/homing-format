//! Signed update index (`index.json` + `index.json.sig`) served by an HTTP source.
//!
//! The index lists available app versions and, for each, builds for specific device
//! configurations. It is only a catalog: every package it points to is still fully verified
//! before installation, so the index cannot make a device install anything it would otherwise
//! reject. Its own signature protects against tampering in transit, which is why it may be
//! served over plain `http://`. No decision depends on TLS or the device clock.
//!
//! ```json
//! {
//!   "schema": 1,
//!   "generated": "2026-11-04T12:00:00Z",
//!   "apps": [
//!     { "id": "com.example.hello", "version": "1.2.0", "version_code": 10200,
//!       "builds": [
//!         { "engine_hash": "…40 hex…", "arch": "aarch64", "machines": ["raspberrypi3-64"],
//!           "url": "hello-1.2.0-aarch64.homing", "sha256": "…64 hex…", "size": 123456 } ] }
//!   ]
//! }
//! ```
//!
//! Rules:
//! - An app id may appear several times, once per version; `(id, version_code)` is unique.
//! - Build entries carry the same compatibility fields as a manifest's `compat` section.
//! - `url` is either relative to the index URL or an absolute `http://` / `https://` URL.
//! - Unknown fields are ignored everywhere in the index, so newer publishers can add
//!   information without locking out older devices. (The index cannot weaken security: the
//!   package's own signature and checks decide.)

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::device::DeviceInfo;
use crate::error::{Error, Result};
use crate::keys::{KeyId, SecretKey};
use crate::manifest::{Arch, Compat, Graphics, is_lower_hex, validate_app_id};
use crate::sig::{self, DocType};
use crate::trust::TrustStore;

/// Maximum size of `index.json`.
pub const MAX_INDEX: usize = 4 * 1024 * 1024;
/// Maximum length of a build URL.
pub const MAX_URL: usize = 2048;

/// A parsed and validated `index.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// Always 1.
    pub schema: u32,
    /// When the index was generated (informational only; never used for validity decisions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<String>,
    /// Available app versions.
    pub apps: Vec<IndexApp>,
}

/// One version of one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexApp {
    /// Reverse-DNS app id.
    pub id: String,
    /// Semver, display only.
    pub version: String,
    /// Monotonic version code; must equal the package manifest's.
    pub version_code: u64,
    /// Builds of this version for different device configurations.
    pub builds: Vec<IndexBuild>,
}

/// One package of an app version, built for one device configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexBuild {
    /// 40-hex Flutter engine commit the package was built against.
    pub engine_hash: String,
    /// CPU architecture.
    pub arch: Arch,
    /// Yocto `MACHINE` values; empty = any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub machines: Vec<String>,
    /// Graphics backends; `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphics: Option<Vec<Graphics>>,
    /// Minimum base image version (semver).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_image_min: Option<String>,
    /// Package location, relative to the index URL or absolute `http(s)://`.
    pub url: String,
    /// sha256 of the package file (lowercase hex).
    pub sha256: String,
    /// Size of the package file in bytes.
    pub size: u64,
}

impl IndexBuild {
    /// The build's compatibility requirements, as in a manifest's `compat` section.
    pub fn compat(&self) -> Compat {
        Compat {
            engine_hash: self.engine_hash.clone(),
            arch: self.arch,
            machines: self.machines.clone(),
            graphics: self.graphics.clone(),
            base_image_min: self.base_image_min.clone(),
        }
    }

    /// Whether `url` is absolute (`http://` or `https://`) rather than relative to the index.
    pub fn url_is_absolute(&self) -> bool {
        url_scheme(&self.url).is_some()
    }
}

/// Result of [`Index::select`] for one app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection<'a> {
    /// No version newer than the installed one is listed.
    UpToDate,
    /// The newest listed version that has a build for this device.
    Update {
        /// The app version.
        app: &'a IndexApp,
        /// The build to download.
        build: &'a IndexBuild,
    },
    /// Newer versions exist, but none has a build compatible with this device.
    NoCompatibleBuild {
        /// The highest listed `version_code`.
        newest_version_code: u64,
    },
}

impl Index {
    /// Parse and validate `index.json` **without** checking its signature. Use
    /// [`verify_index`] for anything received over the network.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INDEX {
            return Err(Error::schema(format!(
                "index.json is larger than {MAX_INDEX} bytes"
            )));
        }
        let index: Index =
            serde_json::from_slice(bytes).map_err(|e| Error::schema(format!("index.json: {e}")))?;
        index.validate()?;
        Ok(index)
    }

    /// Check every semantic rule. Fails with `E_SCHEMA`.
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err(Error::schema(format!(
                "unknown index.json schema {}",
                self.schema
            )));
        }
        let mut seen = BTreeSet::new();
        for app in &self.apps {
            let ctx = format!("index entry {} {}", app.id, app.version_code);
            validate_app_id(&app.id)?;
            semver::Version::parse(&app.version)
                .map_err(|_| Error::schema(format!("{ctx}: version is not semver")))?;
            if !seen.insert((app.id.as_str(), app.version_code)) {
                return Err(Error::schema(format!("{ctx}: listed twice")));
            }
            if app.builds.is_empty() {
                return Err(Error::schema(format!("{ctx}: no builds")));
            }
            for b in &app.builds {
                validate_build(b).map_err(|e| Error::schema(format!("{ctx}: {}", e.message())))?;
            }
        }
        Ok(())
    }

    /// Serialize as pretty JSON with a trailing newline. These are the exact bytes to sign and
    /// serve.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_default();
        v.push(b'\n');
        v
    }

    /// Validate, serialize and sign. Returns `(index.json bytes, index.json.sig bytes)`.
    pub fn sign(&self, key: &SecretKey) -> Result<(Vec<u8>, Vec<u8>)> {
        self.validate()?;
        let bytes = self.to_bytes();
        let sig = sig::sign(key, DocType::Index, &bytes).to_bytes();
        Ok((bytes, sig))
    }

    /// Pick the update for `app_id` on `device`: the highest `version_code` above both
    /// `installed_version_code` and the anti-rollback `floor` that has a compatible build.
    /// When several builds of that version match, the first listed one wins.
    pub fn select(
        &self,
        app_id: &str,
        installed_version_code: u64,
        floor: u64,
        device: &DeviceInfo,
    ) -> Selection<'_> {
        let mut newer: Vec<&IndexApp> = self
            .apps
            .iter()
            .filter(|a| {
                a.id == app_id && a.version_code > installed_version_code && a.version_code >= floor
            })
            .collect();
        newer.sort_by(|a, b| b.version_code.cmp(&a.version_code));
        let Some(newest) = newer.first() else {
            return Selection::UpToDate;
        };
        for app in &newer {
            if let Some(build) = app
                .builds
                .iter()
                .find(|b| device.check_compat(&b.compat()).is_ok())
            {
                return Selection::Update { app, build };
            }
        }
        Selection::NoCompatibleBuild {
            newest_version_code: newest.version_code,
        }
    }
}

fn validate_build(b: &IndexBuild) -> Result<()> {
    if !is_lower_hex(&b.engine_hash, 40) {
        return Err(Error::schema("engine_hash must be 40 lowercase hex"));
    }
    if !is_lower_hex(&b.sha256, 64) {
        return Err(Error::schema("sha256 must be 64 lowercase hex"));
    }
    if b.size == 0 {
        return Err(Error::schema("size must be positive"));
    }
    if let Some(min) = &b.base_image_min {
        semver::Version::parse(min).map_err(|_| Error::schema("base_image_min is not semver"))?;
    }
    if b.graphics.as_ref().is_some_and(Vec::is_empty) {
        return Err(Error::schema("graphics must not be empty when present"));
    }
    validate_url(&b.url)
}

/// `Some("http")`/`Some("https")` for absolute URLs, `None` for relative ones.
fn url_scheme(url: &str) -> Option<&'static str> {
    let lower = url
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if lower.starts_with("https://") {
        Some("https")
    } else if lower.starts_with("http://") {
        Some("http")
    } else {
        None
    }
}

/// A build URL must be a relative reference or an absolute `http(s)` URL, printable ASCII
/// without spaces or backslashes. Other schemes (`file:`, `ftp:`, ...) and scheme-relative
/// URLs (`//host/...`) are rejected so that a signed index can only point at the update server
/// it was fetched from or at an explicit web location.
fn validate_url(url: &str) -> Result<()> {
    if url.is_empty() || url.len() > MAX_URL {
        return Err(Error::schema(format!(
            "url must be 1..={MAX_URL} bytes long"
        )));
    }
    if !url.bytes().all(|c| c.is_ascii_graphic() && c != b'\\') {
        return Err(Error::schema(
            "url must be printable ASCII without spaces or backslashes",
        ));
    }
    if url_scheme(url).is_some() {
        let rest = &url[url.find("://").map_or(0, |i| i + 3)..];
        if rest.is_empty() || rest.starts_with('/') {
            return Err(Error::schema("url has no host"));
        }
        return Ok(());
    }
    if url.starts_with("//") {
        return Err(Error::schema("scheme-relative urls are not allowed"));
    }
    // Any other `scheme:` prefix before the first `/`, `?` or `#` is a different scheme.
    let head = url.split(['/', '?', '#']).next().unwrap_or_default();
    if head.contains(':') {
        return Err(Error::schema(
            "url must be relative or use http:// or https://",
        ));
    }
    Ok(())
}

/// A verified index and the key that signed it.
#[derive(Debug, Clone)]
pub struct VerifiedIndex {
    /// The validated index.
    pub index: Index,
    /// Key that signed it.
    pub key_id: KeyId,
}

/// Verify `index.json.sig` over the exact `index.json` bytes, then parse and validate the
/// index. The signature is checked before the index is parsed.
///
/// Fails with `E_SCHEMA` (oversized or malformed index or signature document), `E_KEY_UNKNOWN`
/// or `E_SIG`.
pub fn verify_index(
    index_bytes: &[u8],
    sig_bytes: &[u8],
    trust: &TrustStore,
) -> Result<VerifiedIndex> {
    if index_bytes.len() > MAX_INDEX {
        return Err(Error::schema(format!(
            "index.json is larger than {MAX_INDEX} bytes"
        )));
    }
    if sig_bytes.len() > sig::MAX_SIG_DOC {
        return Err(Error::schema("index.json.sig is too large"));
    }
    let key = sig::verify(trust, DocType::Index, index_bytes, sig_bytes)?;
    let key_id = key.key_id();
    let index = Index::parse(index_bytes)?;
    Ok(VerifiedIndex { index, key_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::trust::KeyRole;

    const ENGINE: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba98";

    fn build(engine: &str, url: &str) -> IndexBuild {
        IndexBuild {
            engine_hash: engine.into(),
            arch: Arch::Aarch64,
            machines: vec!["raspberrypi3-64".into()],
            graphics: None,
            base_image_min: None,
            url: url.into(),
            sha256: "a".repeat(64),
            size: 1000,
        }
    }

    fn app(version_code: u64, builds: Vec<IndexBuild>) -> IndexApp {
        IndexApp {
            id: "com.example.hello".into(),
            version: format!("1.{version_code}.0"),
            version_code,
            builds,
        }
    }

    fn index(apps: Vec<IndexApp>) -> Index {
        Index {
            schema: 1,
            generated: None,
            apps,
        }
    }

    fn device(engine: &str) -> DeviceInfo {
        DeviceInfo::parse(
            serde_json::json!({
                "schema": 1, "engine_hash": engine, "arch": "aarch64",
                "machine": "raspberrypi3-64", "graphics": ["drm-gles"],
                "base_image_version": "1.0.0"
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn trust(sk: &SecretKey) -> TrustStore {
        let mut t = TrustStore::new(false);
        t.add(sk.public_key("t"), KeyRole::Prod).unwrap();
        t
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = SecretKey::from_seed(&[3; 32]);
        let idx = index(vec![app(2, vec![build(ENGINE, "a.homing")])]);
        let (bytes, sig) = idx.sign(&sk).unwrap();
        let v = verify_index(&bytes, &sig, &trust(&sk)).unwrap();
        assert_eq!(v.index, idx);
        assert_eq!(v.key_id, sk.key_id());
    }

    #[test]
    fn tampered_or_untrusted_index_is_rejected() {
        let sk = SecretKey::from_seed(&[3; 32]);
        let (mut bytes, sig) = index(vec![app(2, vec![build(ENGINE, "a.homing")])])
            .sign(&sk)
            .unwrap();
        let other = SecretKey::from_seed(&[4; 32]);
        assert_eq!(
            verify_index(&bytes, &sig, &trust(&other))
                .unwrap_err()
                .code(),
            ErrorCode::KeyUnknown
        );
        let pos = bytes.iter().position(|&b| b == b'2').unwrap();
        bytes[pos] = b'9';
        assert_eq!(
            verify_index(&bytes, &sig, &trust(&sk)).unwrap_err().code(),
            ErrorCode::Sig
        );
    }

    #[test]
    fn signature_is_checked_before_parsing() {
        // Garbage that is not JSON at all must fail on the signature, not the parser.
        let sk = SecretKey::from_seed(&[3; 32]);
        let other = sig::sign(&sk, DocType::Index, b"something else").to_bytes();
        assert_eq!(
            verify_index(b"not json", &other, &trust(&sk))
                .unwrap_err()
                .code(),
            ErrorCode::Sig
        );
    }

    #[test]
    fn manifest_signature_does_not_verify_as_index() {
        let sk = SecretKey::from_seed(&[3; 32]);
        let bytes = index(vec![app(2, vec![build(ENGINE, "a.homing")])]).to_bytes();
        let wrong = sig::sign(&sk, DocType::Manifest, &bytes).to_bytes();
        assert_eq!(
            verify_index(&bytes, &wrong, &trust(&sk))
                .unwrap_err()
                .code(),
            ErrorCode::Sig
        );
    }

    #[test]
    fn unknown_fields_are_ignored_and_schema_enforced() {
        let json = format!(
            r#"{{"schema":1,"future":true,"apps":[{{"id":"com.example.hello","version":"1.0.0",
               "version_code":1,"note":"x","builds":[{{"engine_hash":"{ENGINE}","arch":"aarch64",
               "url":"a.homing","sha256":"{}","size":1,"signature_hint":1}}]}}]}}"#,
            "b".repeat(64)
        );
        Index::parse(json.as_bytes()).unwrap();
        let bad = json.replacen(r#""schema":1"#, r#""schema":2"#, 1);
        assert_eq!(
            Index::parse(bad.as_bytes()).unwrap_err().code(),
            ErrorCode::Schema
        );
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let cases: Vec<(&str, Index)> = vec![
            (
                "duplicate version",
                index(vec![
                    app(2, vec![build(ENGINE, "a")]),
                    app(2, vec![build(ENGINE, "b")]),
                ]),
            ),
            ("no builds", index(vec![app(2, vec![])])),
            ("bad engine", index(vec![app(2, vec![build("ABC", "a")])])),
            (
                "file url",
                index(vec![app(2, vec![build(ENGINE, "file:///etc/shadow")])]),
            ),
            (
                "other scheme",
                index(vec![app(2, vec![build(ENGINE, "ftp://host/a.homing")])]),
            ),
            (
                "scheme-relative",
                index(vec![app(2, vec![build(ENGINE, "//evil/a.homing")])]),
            ),
            (
                "no host",
                index(vec![app(2, vec![build(ENGINE, "https:///a.homing")])]),
            ),
            (
                "space",
                index(vec![app(2, vec![build(ENGINE, "a b.homing")])]),
            ),
            (
                "backslash",
                index(vec![app(2, vec![build(ENGINE, "a\\b.homing")])]),
            ),
            ("empty url", index(vec![app(2, vec![build(ENGINE, "")])])),
        ];
        for (name, idx) in cases {
            assert_eq!(
                idx.validate().unwrap_err().code(),
                ErrorCode::Schema,
                "{name}"
            );
        }
        let mut bad_id = index(vec![app(2, vec![build(ENGINE, "a")])]);
        bad_id.apps[0].id = "Not An Id".into();
        assert!(bad_id.validate().is_err());
        let mut zero = index(vec![app(2, vec![build(ENGINE, "a")])]);
        zero.apps[0].builds[0].size = 0;
        assert!(zero.validate().is_err());
    }

    #[test]
    fn valid_urls() {
        for u in [
            "a.homing",
            "builds/1.2.0/a.homing",
            "../pool/a.homing",
            "https://cdn.example.com/a.homing",
            "HTTP://example.com:8080/a.homing?x=1",
            "a.homing?token=x:y",
        ] {
            validate_url(u).unwrap_or_else(|e| panic!("{u}: {e}"));
        }
        assert!(build(ENGINE, "https://x/a").url_is_absolute());
        assert!(!build(ENGINE, "a").url_is_absolute());
    }

    #[test]
    fn select_picks_newest_compatible_version() {
        let idx = index(vec![
            app(3, vec![build(OTHER, "v3-other")]), // newest, but only for another engine
            app(2, vec![build(OTHER, "v2-other"), build(ENGINE, "v2")]),
            app(1, vec![build(ENGINE, "v1")]),
        ]);
        let dev = device(ENGINE);
        match idx.select("com.example.hello", 1, 0, &dev) {
            Selection::Update { app, build } => {
                assert_eq!(app.version_code, 2);
                assert_eq!(build.url, "v2");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            idx.select("com.example.hello", 3, 0, &dev),
            Selection::UpToDate
        );
        assert_eq!(
            idx.select("com.example.other", 0, 0, &dev),
            Selection::UpToDate
        );
        // Newer versions exist, but none for this engine.
        assert_eq!(
            idx.select("com.example.hello", 2, 0, &dev),
            Selection::NoCompatibleBuild {
                newest_version_code: 3
            }
        );
        // The anti-rollback floor excludes versions below it.
        assert_eq!(
            idx.select("com.example.hello", 0, 3, &dev),
            Selection::NoCompatibleBuild {
                newest_version_code: 3
            }
        );
    }
}
