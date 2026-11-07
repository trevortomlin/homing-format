//! `manifest.json`.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::path;

/// Maximum size of `manifest.json`.
pub const MAX_MANIFEST: usize = 1024 * 1024;
/// Maximum number of files a package may list.
pub const MAX_FILES: usize = 100_000;
/// Largest integer allowed for version codes and sizes: 2^53 - 1, the largest integer every JSON
/// implementation represents exactly (I-JSON, RFC 7493). Larger values could compare
/// differently in JavaScript or Dart-on-web, which matters for anti-rollback.
pub const MAX_JSON_INT: u64 = (1 << 53) - 1;

/// Build mode of the AOT payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum BuildMode {
    /// Release (AOT `libapp.so`).
    Release,
    /// Profile (AOT `libapp.so`).
    Profile,
    /// Debug (kernel snapshot; dev mode only).
    Debug,
}

/// Embedder that runs the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Embedder {
    /// flutter-pi.
    #[serde(rename = "flutter-pi")]
    FlutterPi,
    /// ivi-homescreen.
    #[serde(rename = "ivi-homescreen")]
    IviHomescreen,
}

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Arch {
    /// 64-bit Arm.
    Aarch64,
    /// 32-bit Arm (hard float).
    Armv7,
    /// x86-64.
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64-bit RISC-V.
    Riscv64,
}

impl Arch {
    /// Spec string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::Armv7 => "armv7",
            Self::X86_64 => "x86_64",
            Self::Riscv64 => "riscv64",
        }
    }
}

/// Graphics backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Graphics {
    /// DRM/KMS with OpenGL ES.
    #[serde(rename = "drm-gles")]
    DrmGles,
    /// DRM/KMS with Vulkan.
    #[serde(rename = "drm-vulkan")]
    DrmVulkan,
    /// Wayland with OpenGL ES.
    #[serde(rename = "wayland-gles")]
    WaylandGles,
    /// Wayland with Vulkan.
    #[serde(rename = "wayland-vulkan")]
    WaylandVulkan,
}

/// Health check mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum HealthMode {
    /// The app must call `app.ready` within `ready_timeout_s`.
    Ready,
    /// The process must stay up without restarting for `trial_s`.
    Alive,
}

/// App permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Permission {
    /// May confirm pending installs.
    ConfirmUpdates,
    /// May observe update events.
    ObserveUpdates,
}

/// `runtime` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Runtime {
    /// Embedder.
    pub embedder: Embedder,
    /// Extra embedder arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment variables.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// `compat` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Compat {
    /// 40-hex Flutter engine commit.
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
}

/// `health` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Health {
    /// Mode.
    #[serde(default = "default_mode")]
    pub mode: HealthMode,
    /// Seconds the app has to call `app.ready`.
    #[serde(default = "default_ready_timeout")]
    pub ready_timeout_s: u32,
    /// Seconds the app must stay alive (alive mode).
    #[serde(default = "default_trial")]
    pub trial_s: u32,
}

fn default_mode() -> HealthMode {
    HealthMode::Ready
}
fn default_ready_timeout() -> u32 {
    30
}
fn default_trial() -> u32 {
    60
}

impl FileEntry {
    /// A payload file entry. Normally created by [`PackageWriter`](crate::PackageWriter).
    pub fn new(path: impl Into<String>, sha256: impl Into<String>, size: u64, exec: bool) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
            size,
            exec,
        }
    }
}

impl Runtime {
    /// A runtime section for `embedder` with no extra arguments or environment.
    pub fn new(embedder: Embedder) -> Self {
        Self {
            embedder,
            args: vec![],
            env: BTreeMap::new(),
        }
    }
}

impl Compat {
    /// Requirements for one engine commit and architecture; any machine, graphics backend and
    /// base image.
    pub fn new(engine_hash: impl Into<String>, arch: Arch) -> Self {
        Self {
            engine_hash: engine_hash.into(),
            arch,
            machines: vec![],
            graphics: None,
            base_image_min: None,
        }
    }
}

impl Default for Health {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            ready_timeout_s: default_ready_timeout(),
            trial_s: default_trial(),
        }
    }
}

/// One payload file entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct FileEntry {
    /// Package path.
    pub path: String,
    /// Lowercase hex sha256.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// Executable bit.
    #[serde(default)]
    pub exec: bool,
}

/// A validated manifest.
///
/// Unknown top-level fields are ignored; unknown fields inside `runtime`, `compat`, `health`,
/// `permissions` and `files` entries are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Manifest {
    /// Always 1.
    pub schema: u32,
    /// Reverse-DNS app id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Semver, display only.
    pub version: String,
    /// Monotonic version code.
    pub version_code: u64,
    /// Raises the device floor on commit.
    #[serde(default)]
    pub min_version_code: u64,
    /// Build mode.
    pub build_mode: BuildMode,
    /// Runtime.
    pub runtime: Runtime,
    /// Compatibility.
    pub compat: Compat,
    /// Health check.
    #[serde(default)]
    pub health: Health,
    /// Permissions.
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// Payload files.
    pub files: Vec<FileEntry>,
    /// Informational creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

/// Check an app id against `^[a-z0-9]+(\.[a-z0-9_-]+)+$`, max 128 chars.
pub fn validate_app_id(id: &str) -> Result<()> {
    let ok = id.len() <= 128 && {
        let mut parts = id.split('.');
        let first = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        !first.is_empty()
            && first
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && !rest.is_empty()
            && rest.iter().all(|p| {
                !p.is_empty()
                    && p.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-'
                    })
            })
    };
    if ok {
        Ok(())
    } else {
        Err(Error::schema(format!("invalid app id {id:?}")))
    }
}

pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_env_name(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

impl Manifest {
    /// A manifest with the given identity and compatibility, and defaults for everything else:
    /// release build, flutter-pi embedder, default health check, no permissions. `files` is
    /// filled in by [`PackageWriter::write`](crate::PackageWriter::write).
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        version_code: u64,
        compat: Compat,
    ) -> Self {
        Self {
            schema: 1,
            id: id.into(),
            name: name.into(),
            version: version.into(),
            version_code,
            min_version_code: 0,
            build_mode: BuildMode::Release,
            runtime: Runtime::new(Embedder::FlutterPi),
            compat,
            health: Health::default(),
            permissions: vec![],
            files: vec![],
            created: None,
        }
    }

    /// Parse and validate manifest bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::schema("manifest larger than 1 MiB"));
        }
        // Check `schema` first so a future schema gets a clear error instead of a field error.
        let v: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| Error::schema("manifest is not valid JSON").with_source(e))?;
        match v.get("schema").and_then(serde_json::Value::as_u64) {
            Some(1) => {}
            Some(n) => return Err(Error::schema(format!("unknown manifest schema {n}"))),
            None => return Err(Error::schema("manifest has no integer schema field")),
        }
        let m: Manifest =
            serde_json::from_value(v).map_err(|e| Error::schema(format!("manifest: {e}")))?;
        m.validate()?;
        Ok(m)
    }

    /// Semantic validation (everything serde cannot express).
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err(Error::schema("schema must be 1"));
        }
        validate_app_id(&self.id)?;
        if self.name.is_empty() || self.name.len() > 128 {
            return Err(Error::schema("name must be 1..=128 bytes"));
        }
        semver::Version::parse(&self.version)
            .map_err(|_| Error::schema(format!("version {:?} is not semver", self.version)))?;
        if self.version_code > MAX_JSON_INT {
            return Err(Error::schema("version_code is larger than 2^53 - 1"));
        }
        if self.min_version_code > self.version_code {
            return Err(Error::schema(
                "min_version_code is greater than version_code",
            ));
        }
        for k in self.runtime.env.keys() {
            if !is_env_name(k) || k.starts_with("HOMING_") {
                return Err(Error::schema(format!("runtime.env name {k:?} not allowed")));
            }
        }
        if !is_lower_hex(&self.compat.engine_hash, 40) {
            return Err(Error::schema(
                "compat.engine_hash must be 40 lowercase hex characters",
            ));
        }
        if let Some(min) = &self.compat.base_image_min {
            semver::Version::parse(min)
                .map_err(|_| Error::schema("compat.base_image_min is not semver"))?;
        }
        let h = &self.health;
        if !(1..=3600).contains(&h.ready_timeout_s) || !(1..=3600).contains(&h.trial_s) {
            return Err(Error::schema("health timeouts must be 1..=3600 seconds"));
        }
        let mut perms = HashSet::new();
        if !self.permissions.iter().all(|p| perms.insert(*p)) {
            return Err(Error::schema("duplicate permission"));
        }
        if self.files.len() > MAX_FILES {
            return Err(Error::schema("too many files"));
        }
        let mut seen = HashSet::new();
        for f in &self.files {
            // Path problems inside the signed manifest are schema errors, not archive errors.
            path::validate_payload_file(f.path.as_bytes())
                .map_err(|e| Error::schema(format!("files: {}", e.message())))?;
            if !seen.insert(f.path.as_str()) {
                return Err(Error::schema(format!("files: duplicate path {}", f.path)));
            }
            if !is_lower_hex(&f.sha256, 64) {
                return Err(Error::schema(format!("files: bad sha256 for {}", f.path)));
            }
            if f.size > MAX_JSON_INT {
                return Err(Error::schema(format!(
                    "files: size of {} is too large",
                    f.path
                )));
            }
        }
        // A file and a directory may not share a name (e.g. "bundle/a" and "bundle/a/b").
        for f in &self.files {
            let mut p = f.path.as_str();
            while let Some((parent, _)) = p.rsplit_once('/') {
                if seen.contains(parent) {
                    return Err(Error::schema(format!(
                        "files: {parent} is both file and directory"
                    )));
                }
                p = parent;
            }
        }
        if !self
            .files
            .iter()
            .any(|f| f.path.starts_with("bundle/flutter_assets/"))
        {
            return Err(Error::schema("package has no bundle/flutter_assets/ files"));
        }
        if matches!(self.build_mode, BuildMode::Release | BuildMode::Profile)
            && !seen.contains("bundle/lib/libapp.so")
        {
            return Err(Error::schema(
                "release/profile package lacks bundle/lib/libapp.so",
            ));
        }
        Ok(())
    }

    /// Serialize to the canonical pretty form used by writers.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = serde_json::to_vec_pretty(self).unwrap_or_default();
        out.push(b'\n');
        out
    }

    /// Look up a file entry by path.
    pub fn file(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.path == path)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::error::ErrorCode;

    pub(crate) fn sample() -> serde_json::Value {
        serde_json::json!({
            "schema": 1,
            "id": "com.example.hello",
            "name": "Hello",
            "version": "1.2.0",
            "version_code": 10200,
            "build_mode": "release",
            "runtime": { "embedder": "flutter-pi" },
            "compat": { "engine_hash": "a".repeat(40), "arch": "aarch64",
                        "machines": ["raspberrypi3-64"], "graphics": ["drm-gles"] },
            "files": [
                { "path": "bundle/flutter_assets/AssetManifest.json", "sha256": "0".repeat(64), "size": 2 },
                { "path": "bundle/lib/libapp.so", "sha256": "1".repeat(64), "size": 10 }
            ]
        })
    }

    fn parse(v: &serde_json::Value) -> Result<Manifest> {
        Manifest::parse(&serde_json::to_vec(v).unwrap())
    }

    #[test]
    fn sample_parses_with_defaults() {
        let m = parse(&sample()).unwrap();
        assert_eq!(m.health, Health::default());
        assert_eq!(m.min_version_code, 0);
        assert!(m.permissions.is_empty());
        assert_eq!(Manifest::parse(&m.to_bytes()).unwrap(), m);
    }

    #[test]
    fn unknown_top_level_field_ignored() {
        let mut v = sample();
        v["future"] = serde_json::json!(true);
        assert!(parse(&v).is_ok());
    }

    fn expect_schema_err(mutate: impl FnOnce(&mut serde_json::Value)) {
        let mut v = sample();
        mutate(&mut v);
        let e = parse(&v).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Schema, "{v}");
    }

    #[test]
    fn fail_closed_sections() {
        expect_schema_err(|v| v["runtime"]["sandbox"] = true.into());
        expect_schema_err(|v| v["compat"]["kernel"] = "6".into());
        expect_schema_err(|v| v["health"] = serde_json::json!({"mode": "ready", "x": 1}));
        expect_schema_err(|v| v["permissions"] = serde_json::json!(["root"]));
        expect_schema_err(|v| v["files"][0]["mode"] = 0o777.into());
    }

    #[test]
    fn semantic_rules() {
        expect_schema_err(|v| v["schema"] = 2.into());
        expect_schema_err(|v| {
            v.as_object_mut().unwrap().remove("schema");
        });
        expect_schema_err(|v| v["id"] = "hello".into());
        expect_schema_err(|v| v["id"] = "Com.example".into());
        expect_schema_err(|v| v["id"] = "com..example".into());
        expect_schema_err(|v| v["version"] = "1.2".into());
        expect_schema_err(|v| v["min_version_code"] = 99999.into());
        expect_schema_err(|v| v["build_mode"] = "fast".into());
        expect_schema_err(|v| v["runtime"]["embedder"] = "x".into());
        expect_schema_err(|v| v["runtime"]["env"] = serde_json::json!({"HOMING_SLOT": "a"}));
        expect_schema_err(|v| v["runtime"]["env"] = serde_json::json!({"A=B": "a"}));
        expect_schema_err(|v| v["compat"]["engine_hash"] = "A".repeat(40).into());
        expect_schema_err(|v| v["compat"]["arch"] = "mips".into());
        expect_schema_err(|v| v["compat"]["base_image_min"] = "one".into());
        expect_schema_err(|v| v["health"] = serde_json::json!({"ready_timeout_s": 0}));
        expect_schema_err(|v| {
            v["permissions"] = serde_json::json!(["confirm_updates", "confirm_updates"])
        });
        expect_schema_err(|v| {
            v["files"][1]["path"] = "bundle/flutter_assets/AssetManifest.json".into()
        });
        expect_schema_err(|v| v["files"][1]["path"] = "../x".into());
        expect_schema_err(|v| v["files"][1]["path"] = "other/x".into());
        expect_schema_err(|v| v["files"][1]["sha256"] = "zz".into());
        expect_schema_err(|v| {
            v["files"][1]["path"] = "bundle/flutter_assets/AssetManifest.json/x".into()
        });
        expect_schema_err(|v| {
            v["files"].as_array_mut().unwrap().remove(1);
        });
        expect_schema_err(|v| {
            v["files"].as_array_mut().unwrap().remove(0);
        });
    }

    #[test]
    fn debug_build_needs_no_libapp() {
        let mut v = sample();
        v["build_mode"] = "debug".into();
        v["files"].as_array_mut().unwrap().remove(1);
        assert!(parse(&v).is_ok());
    }

    #[test]
    fn app_ids() {
        for ok in ["com.example.hello", "a.b", "io.x-y.z_1"] {
            assert!(validate_app_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a", "a.", ".a", "a.B", "a_b.c", "a.b/c"] {
            assert!(validate_app_id(bad).is_err(), "{bad}");
        }
    }
}
