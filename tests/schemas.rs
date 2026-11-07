//! The JSON Schemas in `schemas/` must agree with the Rust parsers: every sample document gets
//! the same verdict from the schema and from the crate.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read as _;
use std::path::{Path, PathBuf};

use homing_format::{DeviceInfo, Index, Manifest, SigDoc};
use serde_json::{Value, json};

type Mutation = Box<dyn Fn(&mut Value)>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn schema(name: &str) -> jsonschema::Validator {
    let s: Value =
        serde_json::from_slice(&std::fs::read(root().join("schemas").join(name)).unwrap()).unwrap();
    jsonschema::draft202012::new(&s).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// First two archive entries (manifest.json, manifest.sig) of a vector package.
fn head(vector: &str) -> (Vec<u8>, Vec<u8>) {
    let f = std::fs::File::open(root().join("test-vectors/packages").join(vector)).unwrap();
    let r = homing_format::package::decompressing_reader(f).unwrap();
    let mut a = tar::Archive::new(r);
    let mut it = a.entries().unwrap();
    let mut read = || {
        let mut v = vec![];
        it.next().unwrap().unwrap().read_to_end(&mut v).unwrap();
        v
    };
    (read(), read())
}

/// Assert that schema and parser agree on `doc`, and that the verdict is `valid`.
fn agree(
    validator: &jsonschema::Validator,
    parse: impl Fn(&[u8]) -> bool,
    doc: &[u8],
    valid: bool,
    what: &str,
) {
    let v: Value = serde_json::from_slice(doc).unwrap();
    let by_schema = validator.is_valid(&v);
    let by_parser = parse(doc);
    assert_eq!(by_parser, valid, "parser verdict for {what}");
    assert_eq!(by_schema, valid, "schema verdict for {what}: {v}");
}

fn mutate(doc: &[u8], f: impl Fn(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(doc).unwrap();
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn manifests() {
    let s = schema("manifest.schema.json");
    let parse = |b: &[u8]| Manifest::parse(b).is_ok();
    for v in [
        "pass-basic.homing",
        "pass-uncompressed.homing",
        "pass-hand-built.homing",
    ] {
        agree(&s, parse, &head(v).0, true, v);
    }
    for v in [
        "schema-unknown-version.homing",
        "schema-unknown-compat-field.homing",
    ] {
        agree(&s, parse, &head(v).0, false, v);
    }
    let good = head("pass-basic.homing").0;
    agree(
        &s,
        parse,
        &mutate(&good, |m| m["unknown_top_level"] = json!(1)),
        true,
        "unknown top-level field",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |m| m["permissions"] = json!(["observe_updates"])),
        true,
        "permission",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |m| m["runtime"]["env"] = json!({"LANG": "C"})),
        true,
        "env",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |m| m["compat"]["graphics"] = json!(["drm-gles"])),
        true,
        "graphics",
    );
    let bad: Vec<(&str, Mutation)> = vec![
        ("bad app id", Box::new(|m| m["id"] = json!("Hello"))),
        ("one-part app id", Box::new(|m| m["id"] = json!("hello"))),
        ("bad version", Box::new(|m| m["version"] = json!("1.0"))),
        (
            "negative version_code",
            Box::new(|m| m["version_code"] = json!(-1)),
        ),
        (
            "bad build mode",
            Box::new(|m| m["build_mode"] = json!("fast")),
        ),
        (
            "unknown runtime field",
            Box::new(|m| m["runtime"]["x"] = json!(1)),
        ),
        (
            "unknown embedder",
            Box::new(|m| m["runtime"]["embedder"] = json!("other")),
        ),
        (
            "HOMING_ env",
            Box::new(|m| m["runtime"]["env"] = json!({"HOMING_X": "1"})),
        ),
        (
            "bad env name",
            Box::new(|m| m["runtime"]["env"] = json!({"1A": "1"})),
        ),
        (
            "short engine hash",
            Box::new(|m| m["compat"]["engine_hash"] = json!("abc")),
        ),
        (
            "uppercase engine hash",
            Box::new(|m| m["compat"]["engine_hash"] = json!("A".repeat(40))),
        ),
        (
            "unknown arch",
            Box::new(|m| m["compat"]["arch"] = json!("mips")),
        ),
        (
            "bad base image",
            Box::new(|m| m["compat"]["base_image_min"] = json!("1")),
        ),
        (
            "unknown health field",
            Box::new(|m| m["health"] = json!({"mode": "ready", "x": 1})),
        ),
        (
            "zero timeout",
            Box::new(|m| m["health"] = json!({"ready_timeout_s": 0})),
        ),
        (
            "huge trial",
            Box::new(|m| m["health"] = json!({"trial_s": 3601})),
        ),
        (
            "duplicate permission",
            Box::new(|m| m["permissions"] = json!(["observe_updates", "observe_updates"])),
        ),
        (
            "unknown permission",
            Box::new(|m| m["permissions"] = json!(["root"])),
        ),
        (
            "traversal path",
            Box::new(|m| m["files"][0]["path"] = json!("bundle/../etc/x")),
        ),
        (
            "dot path",
            Box::new(|m| m["files"][0]["path"] = json!("bundle/./x")),
        ),
        (
            "absolute path",
            Box::new(|m| m["files"][0]["path"] = json!("/bundle/x")),
        ),
        (
            "outside roots",
            Box::new(|m| m["files"][0]["path"] = json!("etc/x")),
        ),
        (
            "backslash path",
            Box::new(|m| m["files"][0]["path"] = json!("bundle\\x")),
        ),
        (
            "control char path",
            Box::new(|m| m["files"][0]["path"] = json!("bundle/a\u{1}b")),
        ),
        (
            "empty component",
            Box::new(|m| m["files"][0]["path"] = json!("bundle//x")),
        ),
        (
            "bad sha",
            Box::new(|m| m["files"][0]["sha256"] = json!("xyz")),
        ),
        (
            "unknown file field",
            Box::new(|m| m["files"][0]["mode"] = json!(420)),
        ),
        (
            "missing files",
            Box::new(|m| {
                m.as_object_mut().unwrap().remove("files");
            }),
        ),
    ];
    for (what, f) in bad {
        agree(&s, parse, &mutate(&good, f), false, what);
    }
    // A manifest built with the Rust API validates against the schema.
    let mut m = Manifest::new(
        "com.example.app",
        "App",
        "0.1.0-beta.1+build.5",
        1,
        homing_format::manifest::Compat::new(
            "a".repeat(40),
            homing_format::manifest::Arch::Riscv64,
        ),
    );
    m.files.push(homing_format::manifest::FileEntry::new(
        "bundle/flutter_assets/x",
        "b".repeat(64),
        1,
        true,
    ));
    m.files.push(homing_format::manifest::FileEntry::new(
        "bundle/lib/libapp.so",
        "c".repeat(64),
        1,
        false,
    ));
    agree(&s, parse, &m.to_bytes(), true, "Manifest::new");
}

#[test]
fn signatures() {
    let s = schema("sig.schema.json");
    let parse = |b: &[u8]| SigDoc::parse(b).is_ok();
    let good = head("pass-basic.homing").1;
    agree(&s, parse, &good, true, "manifest.sig");
    agree(
        &s,
        parse,
        &head("schema-sig-unknown-field.homing").1,
        false,
        "unknown field",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["alg"] = json!("rsa")),
        false,
        "alg",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["key_id"] = json!("ABCDEF0123456789")),
        false,
        "key id",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["sig"] = json!("AAAA")),
        false,
        "short sig",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["schema"] = json!(2)),
        false,
        "schema 2",
    );
    let idx_sig = std::fs::read(root().join("test-vectors/indexes/valid.json.sig")).unwrap();
    agree(&s, parse, &idx_sig, true, "index.json.sig");
}

#[test]
fn engine() {
    let s = schema("engine.schema.json");
    let parse = |b: &[u8]| DeviceInfo::parse(b).is_ok();
    let good = std::fs::read(root().join("test-vectors/engine.json")).unwrap();
    agree(&s, parse, &good, true, "engine.json");
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["extra"] = json!(1)),
        true,
        "unknown field",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["engine_hash"] = json!("x")),
        false,
        "engine hash",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["arch"] = json!("mips")),
        false,
        "arch",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["base_image_version"] = json!("1")),
        false,
        "base image",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["graphics"] = json!(["vga"])),
        false,
        "graphics",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| {
            v.as_object_mut().unwrap().remove("machine");
        }),
        false,
        "missing machine",
    );
}

#[test]
fn indexes() {
    let s = schema("index.schema.json");
    let parse = |b: &[u8]| Index::parse(b).is_ok();
    let good = std::fs::read(root().join("test-vectors/indexes/valid.json")).unwrap();
    agree(&s, parse, &good, true, "valid.json");
    let file_url = std::fs::read(root().join("test-vectors/indexes/schema-file-url.json")).unwrap();
    agree(&s, parse, &file_url, false, "file url");
    let url = |u: &'static str| move |v: &mut Value| v["apps"][0]["builds"][0]["url"] = json!(u);
    for (u, ok) in [
        ("a.homing", true),
        ("dir/a.homing?x=1:2", true),
        ("../a.homing", true),
        ("HTTPS://cdn.example.com/a.homing", true),
        ("http://example.com:8080/a", true),
        ("ftp://example.com/a", false),
        ("//example.com/a", false),
        ("https:///a", false),
        ("javascript:alert(1)", false),
        ("a b", false),
        ("a\\b", false),
        ("", false),
    ] {
        agree(&s, parse, &mutate(&good, url(u)), ok, u);
    }
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["future"] = json!(1)),
        true,
        "unknown top-level field",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["apps"][0]["builds"][0]["mirror"] = json!("x")),
        true,
        "unknown build field",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["apps"][0]["builds"] = json!([])),
        false,
        "no builds",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["apps"][0]["builds"][0]["size"] = json!(0)),
        false,
        "zero size",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["apps"][0]["builds"][0]["graphics"] = json!([])),
        false,
        "empty graphics",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["apps"][0]["id"] = json!("x")),
        false,
        "bad id",
    );
    agree(
        &s,
        parse,
        &mutate(&good, |v| v["schema"] = json!(2)),
        false,
        "schema 2",
    );
}
