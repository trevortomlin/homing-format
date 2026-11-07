//! The committed test vectors (`test-vectors/`) must (1) be exactly what the generator produces
//! and (2) each verify to its expected result.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../examples/gen-vectors/vectors.rs"]
#[allow(dead_code)]
mod vectors;

use std::path::{Path, PathBuf};

use homing_format::{DeviceInfo, Index, Selection, TrustStore, VerifyOptions, verify_index};
use serde_json::Value;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn code<T>(r: homing_format::Result<T>) -> String {
    match r {
        Ok(_) => "PASS".into(),
        Err(e) => e.code().as_str().into(),
    }
}

#[test]
fn committed_vectors_match_the_generator() {
    let files = vectors::generate().unwrap();
    let mut committed = vec![];
    collect(&dir(), &dir(), &mut committed);
    committed.sort();
    let generated: Vec<String> = files.keys().cloned().collect();
    assert_eq!(
        committed, generated,
        "file list differs; run `cargo run --example gen-vectors`"
    );
    for (rel, bytes) in &files {
        let on_disk = std::fs::read(dir().join(rel)).unwrap();
        assert!(
            on_disk == *bytes,
            "{rel} differs from the generator; run `cargo run --example gen-vectors`"
        );
    }
}

fn collect(root: &Path, d: &Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect(root, &p, out);
        } else {
            out.push(
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn spec() -> Value {
    serde_json::from_slice(&std::fs::read(dir().join("vectors.json")).unwrap()).unwrap()
}

#[test]
fn package_vectors_give_expected_results() {
    let spec = spec();
    let device = DeviceInfo::read(&dir().join("engine.json")).unwrap();
    let mut codes_seen = std::collections::BTreeSet::new();
    for v in spec["packages"].as_array().unwrap() {
        let dev_mode = v["dev_mode"].as_bool().unwrap();
        let trust = TrustStore::load_dir(&dir().join("trust"), dev_mode).unwrap();
        let mut opts = VerifyOptions::new(&trust).floor(v["floor"].as_u64().unwrap());
        if v["check_device"].as_bool().unwrap() {
            opts = opts.device(&device);
        }
        let file = std::fs::File::open(dir().join(v["file"].as_str().unwrap())).unwrap();
        let got = code(homing_format::verify(file, opts));
        assert_eq!(got, v["expect"].as_str().unwrap(), "{}", v["description"]);
        codes_seen.insert(got);
    }
    // Every verifier-level error code has at least one vector.
    for c in homing_format::ErrorCode::ALL {
        let covered = codes_seen.contains(c.as_str())
            || spec["not_covered"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == c.as_str());
        assert!(covered, "no vector for {}", c.as_str());
    }
}

#[test]
fn index_vectors_give_expected_results_and_selections() {
    let spec = spec();
    let device = DeviceInfo::read(&dir().join("engine.json")).unwrap();
    let trust = TrustStore::load_dir(&dir().join("trust"), false).unwrap();
    for v in spec["indexes"].as_array().unwrap() {
        let doc = std::fs::read(dir().join(v["file"].as_str().unwrap())).unwrap();
        let sig = std::fs::read(dir().join(v["sig"].as_str().unwrap())).unwrap();
        let res = verify_index(&doc, &sig, &trust);
        let got = match &res {
            Ok(_) => "PASS",
            Err(e) => e.code().as_str(),
        };
        assert_eq!(got, v["expect"].as_str().unwrap(), "{}", v["description"]);
        let Ok(verified) = res else { continue };
        for s in v["select"].as_array().unwrap() {
            let index: &Index = &verified.index;
            let got = index.select(
                s["app"].as_str().unwrap(),
                s["installed_version_code"].as_u64().unwrap(),
                s["floor"].as_u64().unwrap(),
                &device,
            );
            let want = &s["expect"];
            match got {
                Selection::Update { app, build } => {
                    assert_eq!(want["result"], "update", "{s}");
                    assert_eq!(want["version_code"], app.version_code, "{s}");
                    assert_eq!(want["url"], build.url.as_str(), "{s}");
                }
                Selection::NoCompatibleBuild {
                    newest_version_code,
                } => {
                    assert_eq!(want["result"], "no_compatible_build", "{s}");
                    assert_eq!(want["newest_version_code"], newest_version_code, "{s}");
                }
                Selection::UpToDate => assert_eq!(want["result"], "up_to_date", "{s}"),
                _ => panic!("unexpected selection {got:?}"),
            }
        }
    }
}
