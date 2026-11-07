//! Deterministic generator for the language-neutral test vectors in `test-vectors/`.
//!
//! Shared by `examples/gen-vectors` (writes the files) and `tests/vectors.rs` (checks that the
//! committed files are exactly what this code produces, and that each vector verifies to its
//! expected result).

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

use homing_format::manifest::{Arch, Compat, FileEntry, Graphics};
use homing_format::package::sha256_reader;
use homing_format::sig::{self, DocType};
use homing_format::{Index, IndexApp, IndexBuild, Manifest, PackageWriter, SecretKey};
use serde_json::{Value, json};

/// Result type of the generator.
pub type R<T> = Result<T, Box<dyn Error>>;

/// Engine commit of the test device.
pub const ENGINE: &str = "0123456789abcdef0123456789abcdef01234567";
/// Another engine commit, for compatibility vectors.
pub const OTHER_ENGINE: &str = "fedcba9876543210fedcba9876543210fedcba98";
const APP: &str = "com.example.hello";

/// TEST ONLY keys with fixed seeds. Never use them for anything real.
pub fn prod_key() -> SecretKey {
    SecretKey::from_seed(&[0x11; 32])
}
/// Dev key, trusted only in dev mode.
pub fn dev_key() -> SecretKey {
    SecretKey::from_seed(&[0x22; 32])
}
/// A key that is not in the trust store.
pub fn untrusted_key() -> SecretKey {
    SecretKey::from_seed(&[0x33; 32])
}

/// All generated files: relative path -> bytes.
pub type Files = BTreeMap<String, Vec<u8>>;

const ASSET: (&str, &[u8]) = ("bundle/flutter_assets/AssetManifest.json", b"{}\n");
const LIB: (&str, &[u8]) = ("bundle/lib/libapp.so", b"\x7fELF test-only AOT snapshot\n");
const CONFIG: (&str, &[u8]) = ("config/app.json", b"{\"greeting\":\"hello\"}\n");

fn compat() -> Compat {
    let mut c = Compat::new(ENGINE, Arch::Aarch64);
    c.machines = vec!["raspberrypi3-64".into()];
    c
}

fn manifest(version_code: u64, compat: Compat) -> Manifest {
    let mut m = Manifest::new(APP, "Hello", "1.0.0", version_code, compat);
    m.created = Some("2026-01-01T00:00:00Z".into());
    m
}

/// A well-formed package written by the reference writer.
fn written(m: Manifest, key: &SecretKey, compression: Option<i32>) -> R<Vec<u8>> {
    let mut w = PackageWriter::new(0).compression(compression);
    for (p, d) in [ASSET, LIB, CONFIG] {
        w.add_bytes(p, d.to_vec(), false)?;
    }
    let mut out = Vec::new();
    w.write(m, key, &mut out)?;
    Ok(out)
}

/// Hand-built uncompressed tar, for packages the writer refuses to produce.
struct Raw(tar::Builder<Vec<u8>>);

impl Raw {
    fn new() -> Self {
        Self(tar::Builder::new(Vec::new()))
    }
    fn header(name: &[u8], size: usize, et: tar::EntryType) -> R<tar::Header> {
        // Old-style header with the name written verbatim: the tar crate would sanitize
        // hostile names like `../x` or `/x`.
        let mut h = tar::Header::new_old();
        let field = &mut h.as_old_mut().name;
        if name.len() > field.len() {
            return Err("name too long".into());
        }
        field[..name.len()].copy_from_slice(name);
        h.set_size(size as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        h.set_entry_type(et);
        h.set_cksum();
        Ok(h)
    }
    fn entry(mut self, name: &str, data: &[u8], et: tar::EntryType) -> R<Self> {
        let h = Self::header(name.as_bytes(), data.len(), et)?;
        self.0.append(&h, data)?;
        Ok(self)
    }
    fn file(self, name: &str, data: &[u8]) -> R<Self> {
        self.entry(name, data, tar::EntryType::Regular)
    }
    fn symlink(mut self, name: &str, target: &str) -> R<Self> {
        let mut h = Self::header(name.as_bytes(), 0, tar::EntryType::Symlink)?;
        h.set_link_name(target)?;
        h.set_cksum();
        self.0.append(&h, &[][..])?;
        Ok(self)
    }
    fn finish(self) -> R<Vec<u8>> {
        Ok(self.0.into_inner()?)
    }
}

/// Signed manifest bytes listing `files`, plus its signature document.
fn head(files: &[(&str, &[u8])], key: &SecretKey, domain: DocType) -> R<(Vec<u8>, Vec<u8>)> {
    let mut m = manifest(10000, compat());
    for (p, d) in files {
        let (sha256, size) = sha256_reader(*d)?;
        m.files.push(FileEntry::new(*p, sha256, size, false));
    }
    let mb = m.to_bytes();
    let sb = sig::sign(key, domain, &mb).to_bytes();
    Ok((mb, sb))
}

/// The standard payload, hand-built, with a correct signed head.
fn good_raw() -> R<Raw> {
    let (mb, sb) = head(&[ASSET, LIB, CONFIG], &prod_key(), DocType::Manifest)?;
    Raw::new()
        .file("manifest.json", &mb)?
        .file("manifest.sig", &sb)
}

fn with_payload(r: Raw) -> R<Raw> {
    r.file(ASSET.0, ASSET.1)?
        .file(LIB.0, LIB.1)?
        .file(CONFIG.0, CONFIG.1)
}

/// Generate every vector. Returns the files, including `vectors.json`.
pub fn generate() -> R<Files> {
    let mut files = Files::new();
    let mut packages: Vec<Value> = vec![];
    // --- keys and device ---
    files.insert("keys/prod-test.key".into(), secret_file(&prod_key()));
    files.insert("keys/dev-test.key".into(), secret_file(&dev_key()));
    files.insert("keys/untrusted.key".into(), secret_file(&untrusted_key()));
    files.insert(
        "trust/prod-test.pub".into(),
        prod_key()
            .public_key("homing test vectors (TEST ONLY)")
            .to_file_string()
            .into_bytes(),
    );
    files.insert(
        "trust/dev-test.pub".into(),
        dev_key()
            .public_key("homing test vectors dev (TEST ONLY)")
            .to_file_string()
            .into_bytes(),
    );
    let device = json!({ "schema": 1, "engine_hash": ENGINE, "flutter_version": "3.44.9",
                         "arch": "aarch64", "machine": "raspberrypi3-64",
                         "graphics": ["drm-gles"], "base_image_version": "1.0.0" });
    files.insert("engine.json".into(), pretty(&device));

    // --- valid packages ---
    let basic = written(manifest(10000, compat()), &prod_key(), Some(12))?;
    add(
        &mut files,
        &mut packages,
        "pass-basic",
        basic.clone(),
        "PASS",
        "zstd package from the reference writer",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "pass-uncompressed",
        written(manifest(10000, compat()), &prod_key(), None)?,
        "PASS",
        "uncompressed tar",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "pass-hand-built",
        with_payload(good_raw()?)?.finish()?,
        "PASS",
        "hand-built tar with old-style headers",
        json!({}),
    );
    let dev_signed = written(manifest(10000, compat()), &dev_key(), Some(12))?;
    add(
        &mut files,
        &mut packages,
        "pass-dev-key",
        dev_signed,
        "PASS",
        "signed by a dev key, verified in dev mode",
        json!({ "dev_mode": true }),
    );
    packages.push(
        json!({ "file": "packages/pass-dev-key.homing", "expect": "E_KEY_UNKNOWN",
        "description": "dev-signed package outside dev mode", "dev_mode": false,
        "check_device": true, "floor": 0 }),
    );
    packages.push(
        json!({ "file": "packages/pass-basic.homing", "expect": "E_ROLLBACK",
        "description": "version_code 10000 below floor 20000", "dev_mode": false,
        "check_device": true, "floor": 20000 }),
    );

    // --- E_SCHEMA ---
    let (mb, sb) = head(&[ASSET, LIB, CONFIG], &prod_key(), DocType::Manifest)?;
    add(
        &mut files,
        &mut packages,
        "schema-wrong-order",
        with_payload(
            Raw::new()
                .file("manifest.sig", &sb)?
                .file("manifest.json", &mb)?,
        )?
        .finish()?,
        "E_SCHEMA",
        "manifest.sig before manifest.json",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "schema-missing-sig",
        with_payload(Raw::new().file("manifest.json", &mb)?)?.finish()?,
        "E_SCHEMA",
        "second entry is not manifest.sig",
        json!({}),
    );
    let big = vec![b' '; 1024 * 1024 + 1];
    add(
        &mut files,
        &mut packages,
        "schema-oversized-manifest",
        Raw::new()
            .file("manifest.json", &big)?
            .file("manifest.sig", &sb)?
            .finish()?,
        "E_SCHEMA",
        "manifest.json larger than 1 MiB",
        json!({}),
    );
    let signed_doc = |doc: &[u8]| -> R<Vec<u8>> {
        let s = sig::sign(&prod_key(), DocType::Manifest, doc).to_bytes();
        Raw::new()
            .file("manifest.json", doc)?
            .file("manifest.sig", &s)?
            .finish()
    };
    add(
        &mut files,
        &mut packages,
        "schema-invalid-json",
        signed_doc(b"{ not json")?,
        "E_SCHEMA",
        "correctly signed manifest that is not JSON",
        json!({}),
    );
    let mut m2: Value = serde_json::from_slice(&mb)?;
    m2["schema"] = json!(2);
    add(
        &mut files,
        &mut packages,
        "schema-unknown-version",
        signed_doc(&pretty(&m2))?,
        "E_SCHEMA",
        "correctly signed manifest with schema 2",
        json!({}),
    );
    let mut m3: Value = serde_json::from_slice(&mb)?;
    m3["compat"]["unexpected"] = json!(true);
    add(
        &mut files,
        &mut packages,
        "schema-unknown-compat-field",
        signed_doc(&pretty(&m3))?,
        "E_SCHEMA",
        "unknown field inside compat (fail closed)",
        json!({}),
    );
    let mut sig_extra: Value = serde_json::from_slice(&sb)?;
    sig_extra["comment"] = json!("x");
    add(
        &mut files,
        &mut packages,
        "schema-sig-unknown-field",
        with_payload(
            Raw::new()
                .file("manifest.json", &mb)?
                .file("manifest.sig", &pretty(&sig_extra))?,
        )?
        .finish()?,
        "E_SCHEMA",
        "unknown field in manifest.sig",
        json!({}),
    );

    // --- E_KEY_UNKNOWN / E_SIG ---
    add(
        &mut files,
        &mut packages,
        "key-untrusted",
        written(manifest(10000, compat()), &untrusted_key(), Some(12))?,
        "E_KEY_UNKNOWN",
        "signed by a key that is not in the trust store",
        json!({}),
    );
    let mut tampered = mb.clone();
    let pos = tampered
        .windows(5)
        .position(|w| w == b"Hello")
        .ok_or("no name")?;
    tampered[pos] = b'J';
    add(
        &mut files,
        &mut packages,
        "sig-tampered-manifest",
        with_payload(
            Raw::new()
                .file("manifest.json", &tampered)?
                .file("manifest.sig", &sb)?,
        )?
        .finish()?,
        "E_SIG",
        "manifest changed after signing",
        json!({}),
    );
    let (mbi, sbi) = head(&[ASSET, LIB, CONFIG], &prod_key(), DocType::Index)?;
    add(
        &mut files,
        &mut packages,
        "sig-wrong-domain",
        with_payload(
            Raw::new()
                .file("manifest.json", &mbi)?
                .file("manifest.sig", &sbi)?,
        )?
        .finish()?,
        "E_SIG",
        "manifest signed with the index domain (domain separation)",
        json!({}),
    );

    // --- E_HASH / E_EXTRA_FILE ---
    add(
        &mut files,
        &mut packages,
        "hash-tampered-payload",
        good_raw()?
            .file(ASSET.0, ASSET.1)?
            .file(LIB.0, b"\x7fELF tampered AOT snapshot!!\n")?
            .file(CONFIG.0, CONFIG.1)?
            .finish()?,
        "E_HASH",
        "payload file content differs from the manifest",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "hash-wrong-size",
        good_raw()?
            .file(ASSET.0, ASSET.1)?
            .file(LIB.0, LIB.1)?
            .file(CONFIG.0, b"{}\n")?
            .finish()?,
        "E_HASH",
        "payload file size differs from the manifest",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "extra-file-unlisted",
        with_payload(good_raw()?)?
            .file("bundle/flutter_assets/extra", b"x")?
            .finish()?,
        "E_EXTRA_FILE",
        "archive contains a file the manifest does not list",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "extra-file-missing",
        good_raw()?
            .file(ASSET.0, ASSET.1)?
            .file(LIB.0, LIB.1)?
            .finish()?,
        "E_EXTRA_FILE",
        "a listed file is missing from the archive",
        json!({}),
    );

    // --- E_PATH ---
    add(
        &mut files,
        &mut packages,
        "path-traversal",
        with_payload(good_raw()?)?
            .file("../../etc/evil", b"x")?
            .finish()?,
        "E_PATH",
        "entry name escapes the package with ..",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "path-absolute",
        with_payload(good_raw()?)?
            .file("/etc/evil", b"x")?
            .finish()?,
        "E_PATH",
        "absolute entry name",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "path-symlink",
        good_raw()?
            .symlink("bundle/lib", "/etc")?
            .file(LIB.0, LIB.1)?
            .finish()?,
        "E_PATH",
        "symlink entry",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "path-hardlink",
        with_payload(good_raw()?)?
            .entry("bundle/x", b"", tar::EntryType::Link)?
            .finish()?,
        "E_PATH",
        "hard link entry",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "path-device",
        with_payload(good_raw()?)?
            .entry("bundle/x", b"", tar::EntryType::Char)?
            .finish()?,
        "E_PATH",
        "character device entry",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "path-duplicate",
        good_raw()?
            .file(ASSET.0, ASSET.1)?
            .file(ASSET.0, ASSET.1)?
            .file(LIB.0, LIB.1)?
            .file(CONFIG.0, CONFIG.1)?
            .finish()?,
        "E_PATH",
        "the same path twice",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "path-outside-payload",
        with_payload(good_raw()?)?
            .file("etc/evil", b"x")?
            .finish()?,
        "E_PATH",
        "path outside bundle/, config/ and sbom/",
        json!({}),
    );

    // --- compatibility ---
    let variant = |f: &dyn Fn(&mut Compat)| -> R<Vec<u8>> {
        let mut c = compat();
        f(&mut c);
        written(manifest(10000, c), &prod_key(), Some(12))
    };
    add(
        &mut files,
        &mut packages,
        "compat-engine",
        variant(&|c| c.engine_hash = OTHER_ENGINE.into())?,
        "E_ENGINE",
        "built for another engine commit",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "compat-arch",
        variant(&|c| c.arch = Arch::X86_64)?,
        "E_ARCH",
        "built for x86_64",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "compat-machine",
        variant(&|c| c.machines = vec!["raspberrypi4-64".into()])?,
        "E_MACHINE",
        "built for another machine",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "compat-graphics",
        variant(&|c| c.graphics = Some(vec![Graphics::WaylandGles]))?,
        "E_GRAPHICS",
        "needs a graphics backend the device lacks",
        json!({}),
    );
    add(
        &mut files,
        &mut packages,
        "compat-base-image",
        variant(&|c| c.base_image_min = Some("2.0.0".into()))?,
        "E_BASE_IMAGE",
        "needs a newer base image",
        json!({}),
    );
    packages.push(
        json!({ "file": "packages/compat-engine.homing", "expect": "PASS",
        "description": "compatibility is not checked without a device (host-side verify)",
        "dev_mode": false, "check_device": false, "floor": 0 }),
    );

    // --- indexes ---
    let sha = |b: &[u8]| -> R<String> { Ok(sha256_reader(b)?.0) };
    let mut idx = Index::new();
    idx.generated = Some("2026-01-01T00:00:00Z".into());
    let mut v1 = IndexApp::new(APP, "1.0.0", 10000);
    v1.builds.push(IndexBuild::new(
        ENGINE,
        Arch::Aarch64,
        "../packages/pass-basic.homing",
        sha(&basic)?,
        basic.len() as u64,
    ));
    let mut v2 = IndexApp::new(APP, "2.0.0", 20000);
    v2.builds.push(IndexBuild::new(
        OTHER_ENGINE,
        Arch::Aarch64,
        "https://updates.example.com/hello-2.0.0-other.homing",
        "e".repeat(64),
        4096,
    ));
    idx.apps = vec![v2, v1];
    let (ib, isig) = idx.sign(&prod_key())?;
    let mut indexes: Vec<Value> = vec![];
    add_index(
        &mut files,
        &mut indexes,
        "valid",
        ib.clone(),
        isig.clone(),
        "PASS",
        "two versions; only 1.0.0 has a build for the test device",
        json!([
            { "app": APP, "installed_version_code": 0, "floor": 0,
              "expect": { "result": "update", "version_code": 10000, "url": "../packages/pass-basic.homing" } },
            { "app": APP, "installed_version_code": 10000, "floor": 0,
              "expect": { "result": "no_compatible_build", "newest_version_code": 20000 } },
            { "app": APP, "installed_version_code": 20000, "floor": 0, "expect": { "result": "up_to_date" } },
            { "app": "com.example.other", "installed_version_code": 0, "floor": 0, "expect": { "result": "up_to_date" } },
        ]),
    );
    let mut t = ib.clone();
    let pos = t
        .windows(5)
        .position(|w| w == b"20000")
        .ok_or("no version")?;
    t[pos] = b'9';
    add_index(
        &mut files,
        &mut indexes,
        "sig-tampered",
        t,
        isig.clone(),
        "E_SIG",
        "index changed after signing",
        json!([]),
    );
    add_index(
        &mut files,
        &mut indexes,
        "key-untrusted",
        ib.clone(),
        sig::sign(&untrusted_key(), DocType::Index, &ib).to_bytes(),
        "E_KEY_UNKNOWN",
        "signed by an untrusted key",
        json!([]),
    );
    add_index(
        &mut files,
        &mut indexes,
        "sig-wrong-domain",
        ib.clone(),
        sig::sign(&prod_key(), DocType::Manifest, &ib).to_bytes(),
        "E_SIG",
        "index signed with the manifest domain",
        json!([]),
    );
    let mut bad: Value = serde_json::from_slice(&ib)?;
    bad["apps"][0]["builds"][0]["url"] = json!("file:///etc/shadow");
    let bad = pretty(&bad);
    let bad_sig = sig::sign(&prod_key(), DocType::Index, &bad).to_bytes();
    add_index(
        &mut files,
        &mut indexes,
        "schema-file-url",
        bad,
        bad_sig,
        "E_SCHEMA",
        "correctly signed index with a file:// url",
        json!([]),
    );

    let doc = json!({
        "schema": 1,
        "description": "homing-format test vectors. Keys are TEST ONLY. Generated by `cargo run --example gen-vectors`.",
        "trust_dir": "trust",
        "device": "engine.json",
        "not_covered": ["E_SPACE", "E_HEALTH", "E_BUSY", "E_PERM", "E_IO"],
        "packages": packages,
        "indexes": indexes,
    });
    files.insert("vectors.json".into(), pretty(&doc));
    files.insert("README.md".into(), README.as_bytes().to_vec());
    Ok(files)
}

fn secret_file(k: &SecretKey) -> Vec<u8> {
    k.to_file_string().into_bytes()
}

/// Record a package vector. `opts` overrides the default settings.
fn add(
    files: &mut Files,
    packages: &mut Vec<Value>,
    name: &str,
    bytes: Vec<u8>,
    expect: &str,
    desc: &str,
    opts: Value,
) {
    let path = format!("packages/{name}.homing");
    files.insert(path.clone(), bytes);
    let mut v = json!({ "file": path, "expect": expect, "description": desc,
                        "dev_mode": false, "check_device": true, "floor": 0 });
    if let (Some(o), Some(map)) = (opts.as_object(), v.as_object_mut()) {
        for (k, val) in o {
            map.insert(k.clone(), val.clone());
        }
    }
    packages.push(v);
}

/// Record an index vector (`index.json` + `index.json.sig`).
#[allow(clippy::too_many_arguments)] // one flat call per vector reads best
fn add_index(
    files: &mut Files,
    indexes: &mut Vec<Value>,
    name: &str,
    doc: Vec<u8>,
    sig: Vec<u8>,
    expect: &str,
    desc: &str,
    select: Value,
) {
    let (f, sf) = (
        format!("indexes/{name}.json"),
        format!("indexes/{name}.json.sig"),
    );
    files.insert(f.clone(), doc);
    files.insert(sf.clone(), sig);
    indexes.push(
        json!({ "file": f, "sig": sf, "expect": expect, "description": desc, "select": select }),
    );
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec_pretty(v).unwrap_or_default();
    b.push(b'\n');
    b
}

/// Write `files` under `dir`, replacing its previous contents.
pub fn write_all(dir: &Path, files: &Files) -> R<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    for (rel, bytes) in files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, bytes)?;
    }
    Ok(())
}

const README: &str = "# homing-format test vectors

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
";
