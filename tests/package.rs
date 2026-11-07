//! End-to-end tests of writer + verifier, including hostile archives.
#![allow(clippy::unwrap_used)]

use std::io::Write as _;

use homing_format::manifest::Compat;
use homing_format::*;

const ENGINE: &str = "0123456789abcdef0123456789abcdef01234567";

fn key() -> SecretKey {
    SecretKey::from_seed(&[42; 32])
}

fn trust() -> TrustStore {
    let mut t = TrustStore::new(false);
    t.add(key().public_key("test"), KeyRole::Prod).unwrap();
    t
}

fn device() -> DeviceInfo {
    DeviceInfo::parse(
        format!(
            r#"{{"schema":1,"engine_hash":"{ENGINE}","arch":"aarch64","machine":"raspberrypi3-64",
               "graphics":["drm-gles"],"base_image_version":"1.0.0"}}"#
        )
        .as_bytes(),
    )
    .unwrap()
}

fn base_manifest(version_code: u64) -> Manifest {
    let mut compat = Compat::new(ENGINE, manifest::Arch::Aarch64);
    compat.machines = vec!["raspberrypi3-64".into()];
    Manifest::new("com.example.hello", "Hello", "1.0.0", version_code, compat)
}

fn writer() -> PackageWriter {
    let mut w = PackageWriter::new(0);
    w.add_bytes(
        "bundle/flutter_assets/AssetManifest.json",
        b"{}".to_vec(),
        false,
    )
    .unwrap();
    w.add_bytes("bundle/lib/libapp.so", vec![7u8; 100_000], false)
        .unwrap();
    w.add_bytes("config/app.json", br#"{"greeting":"hi"}"#.to_vec(), false)
        .unwrap();
    w.add_bytes("bundle/run.sh", b"#!/bin/sh\n".to_vec(), true)
        .unwrap();
    w
}

fn build(w: &PackageWriter, vc: u64) -> Vec<u8> {
    let mut out = Vec::new();
    w.write(base_manifest(vc), &key(), &mut out).unwrap();
    out
}

fn opts<'a>(t: &'a TrustStore, d: &'a DeviceInfo) -> VerifyOptions<'a> {
    VerifyOptions::new(t).device(d)
}

#[test]
fn round_trip_compressed_and_plain() {
    for level in [Some(3), None] {
        let pkg = {
            let mut out = Vec::new();
            writer()
                .compression(level)
                .write(base_manifest(1), &key(), &mut out)
                .unwrap();
            out
        };
        let (t, d) = (trust(), device());
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("slot");
        let v = verify_and_extract(&pkg[..], opts(&t, &d), &dest).unwrap();
        assert_eq!(v.manifest.files.len(), 4);
        assert_eq!(
            std::fs::read(dest.join("config/app.json")).unwrap(),
            br#"{"greeting":"hi"}"#
        );
        assert_eq!(
            std::fs::read(dest.join("bundle/lib/libapp.so"))
                .unwrap()
                .len(),
            100_000
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &str| {
                std::fs::metadata(dest.join(p))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode("bundle/run.sh"), 0o755);
            assert_eq!(mode("config/app.json"), 0o644);
        }
        let (m, s) = inspect(&pkg[..]).unwrap();
        assert_eq!(m, v.manifest);
        assert_eq!(s.key_id, key().key_id());
    }
}

#[test]
fn writer_is_deterministic() {
    assert_eq!(build(&writer(), 1), build(&writer(), 1));
}

#[test]
fn add_dir_rejects_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("flutter_assets")).unwrap();
    std::fs::write(dir.path().join("flutter_assets/a"), "x").unwrap();
    let mut w = PackageWriter::new(0);
    w.add_dir(dir.path(), "bundle").unwrap();
    assert_eq!(w.paths().collect::<Vec<_>>(), ["bundle/flutter_assets/a"]);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("evil")).unwrap();
        let mut w = PackageWriter::new(0);
        assert_eq!(
            w.add_dir(dir.path(), "bundle").unwrap_err().code(),
            ErrorCode::Path
        );
    }
}

fn expect(pkg: &[u8], code: ErrorCode) {
    let (t, d) = (trust(), device());
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("slot");
    let err = verify_and_extract(pkg, opts(&t, &d), &dest).unwrap_err();
    assert_eq!(err.code(), code, "{err}");
    assert!(!dest.exists(), "staging dir must be removed on failure");
}

#[test]
fn compat_and_floor_errors() {
    let pkg = build(&writer(), 5);
    let (t, mut d) = (trust(), device());
    d.engine_hash = "f".repeat(40);
    assert_eq!(
        verify(&pkg[..], opts(&t, &d)).unwrap_err().code(),
        ErrorCode::Engine
    );
    let d = device();
    let o = VerifyOptions::new(&t).device(&d).floor(6);
    assert_eq!(verify(&pkg[..], o).unwrap_err().code(), ErrorCode::Rollback);
}

#[test]
fn untrusted_key() {
    let pkg = build(&writer(), 1);
    let t = TrustStore::new(false);
    let d = device();
    assert_eq!(
        verify(&pkg[..], opts(&t, &d)).unwrap_err().code(),
        ErrorCode::KeyUnknown
    );
}

// ---- hostile archives, built by hand ----

struct Raw {
    b: tar::Builder<Vec<u8>>,
}

impl Raw {
    fn new() -> Self {
        Self {
            b: tar::Builder::new(Vec::new()),
        }
    }
    fn file(mut self, p: &str, data: &[u8]) -> Self {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        self.b.append_data(&mut h, p, data).unwrap();
        self
    }
    /// Write a header with a raw name, bypassing the tar crate's path sanitizing.
    fn raw_file(mut self, name: &[u8], data: &[u8], et: tar::EntryType) -> Self {
        let mut h = tar::Header::new_old();
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(et);
        h.set_cksum();
        self.b.append(&h, data).unwrap();
        self
    }
    fn symlink(mut self, p: &str, target: &str) -> Self {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        self.b.append_link(&mut h, p, target).unwrap();
        self
    }
    fn finish(self) -> Vec<u8> {
        self.b.into_inner().unwrap()
    }
}

/// A manifest + signature for these payload files, as raw bytes.
fn signed_head(files: &[(&str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let mut m = base_manifest(1);
    for (p, data) in files {
        let (sha256, size) = package::sha256_reader(*data).unwrap();
        m.files
            .push(manifest::FileEntry::new(*p, sha256, size, false));
    }
    let mb = m.to_bytes();
    let sb = sig::sign(&key(), DocType::Manifest, &mb).to_bytes();
    (mb, sb)
}

const ASSET: (&str, &[u8]) = ("bundle/flutter_assets/a", b"asset");
const LIB: (&str, &[u8]) = ("bundle/lib/libapp.so", b"lib");

fn good_raw() -> Raw {
    let (mb, sb) = signed_head(&[ASSET, LIB]);
    Raw::new()
        .file("manifest.json", &mb)
        .file("manifest.sig", &sb)
}

#[test]
fn hand_built_good_package_passes() {
    let pkg = good_raw()
        .file(ASSET.0, ASSET.1)
        .file(LIB.0, LIB.1)
        .finish();
    let (t, d) = (trust(), device());
    verify(&pkg[..], opts(&t, &d)).unwrap();
}

#[test]
fn path_traversal() {
    let pkg = good_raw()
        .file(ASSET.0, ASSET.1)
        .file(LIB.0, LIB.1)
        .raw_file(b"../../etc/evil", b"x", tar::EntryType::Regular)
        .finish();
    expect(&pkg, ErrorCode::Path);
    let pkg = good_raw()
        .raw_file(b"/etc/evil", b"x", tar::EntryType::Regular)
        .finish();
    expect(&pkg, ErrorCode::Path);
}

#[test]
fn symlink_entry() {
    let pkg = good_raw()
        .symlink("bundle/lib", "/etc")
        .file(LIB.0, LIB.1)
        .finish();
    expect(&pkg, ErrorCode::Path);
}

#[test]
fn hardlink_and_device_entries() {
    for et in [
        tar::EntryType::Link,
        tar::EntryType::Char,
        tar::EntryType::Fifo,
    ] {
        let pkg = good_raw().raw_file(b"bundle/x", b"", et).finish();
        expect(&pkg, ErrorCode::Path);
    }
}

#[test]
fn duplicate_entry() {
    let pkg = good_raw()
        .file(ASSET.0, ASSET.1)
        .file(ASSET.0, ASSET.1)
        .file(LIB.0, LIB.1)
        .finish();
    expect(&pkg, ErrorCode::Path);
}

#[test]
fn extra_file() {
    let pkg = good_raw()
        .file(ASSET.0, ASSET.1)
        .file(LIB.0, LIB.1)
        .file("bundle/flutter_assets/extra", b"x")
        .finish();
    expect(&pkg, ErrorCode::ExtraFile);
}

#[test]
fn missing_file() {
    let pkg = good_raw().file(ASSET.0, ASSET.1).finish();
    expect(&pkg, ErrorCode::ExtraFile);
}

#[test]
fn tampered_payload() {
    let pkg = good_raw()
        .file(ASSET.0, ASSET.1)
        .file(LIB.0, b"LIB")
        .finish();
    expect(&pkg, ErrorCode::Hash);
    let pkg = good_raw()
        .file(ASSET.0, ASSET.1)
        .file(LIB.0, b"lib!")
        .finish();
    expect(&pkg, ErrorCode::Hash);
}

#[test]
fn tampered_manifest() {
    let (mut mb, sb) = signed_head(&[ASSET, LIB]);
    let pos = mb.windows(5).position(|w| w == b"Hello").unwrap();
    mb[pos] = b'J';
    let pkg = Raw::new()
        .file("manifest.json", &mb)
        .file("manifest.sig", &sb)
        .finish();
    expect(&pkg, ErrorCode::Sig);
}

#[test]
fn verify_head_checks_signature_before_parsing() {
    let (mut mb, sb) = signed_head(&[ASSET, LIB]);
    mb[0] = b'X'; // no longer JSON, and no longer matches the signature
    let pkg = Raw::new()
        .file("manifest.json", &mb)
        .file("manifest.sig", &sb)
        .finish();
    assert_eq!(
        verify_head(&pkg[..], &trust()).unwrap_err().code(),
        ErrorCode::Sig
    );
    let pkg = good_raw().finish();
    assert_eq!(
        verify_head(&pkg[..], &trust()).unwrap().manifest.id,
        "com.example.hello"
    );
}

#[test]
fn wrong_entry_order() {
    let (mb, sb) = signed_head(&[ASSET, LIB]);
    let pkg = Raw::new()
        .file("manifest.sig", &sb)
        .file("manifest.json", &mb)
        .finish();
    expect(&pkg, ErrorCode::Schema);
    let pkg = Raw::new()
        .file(ASSET.0, ASSET.1)
        .file("manifest.json", &mb)
        .finish();
    expect(&pkg, ErrorCode::Schema);
}

#[test]
fn oversized_manifest() {
    let big = vec![b' '; manifest::MAX_MANIFEST + 1];
    let pkg = Raw::new().file("manifest.json", &big).finish();
    expect(&pkg, ErrorCode::Schema);
}

#[test]
fn garbage_and_empty_input() {
    expect(b"", ErrorCode::Schema);
    expect(&[0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3], ErrorCode::Schema);
    let mut junk = Vec::new();
    junk.write_all(&[0xffu8; 2048]).unwrap();
    let (t, d) = (trust(), device());
    assert!(verify(&junk[..], opts(&t, &d)).is_err());
}

#[test]
fn directory_entries() {
    let mut b = good_raw();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_size(0);
    h.set_mode(0o755);
    b.b.append_data(&mut h, "bundle/lib/", &b""[..]).unwrap();
    let pkg = b.file(ASSET.0, ASSET.1).file(LIB.0, LIB.1).finish();
    let (t, d) = (trust(), device());
    verify(&pkg[..], opts(&t, &d)).unwrap();

    let mut b = good_raw();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_size(0);
    b.b.append_data(&mut h, "etc/", &b""[..]).unwrap();
    expect(&b.finish(), ErrorCode::Path);
}
