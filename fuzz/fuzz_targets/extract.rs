//! Extraction must never write outside the staging directory and must leave nothing behind on
//! failure. Seed with the valid test vectors, like the `package` target.
#![no_main]

use homing_format::{KeyRole, SecretKey, TrustStore, VerifyOptions};
use libfuzzer_sys::fuzz_target;

fn entries(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).expect("read_dir").flatten() {
        out.push(e.path());
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let mut trust = TrustStore::new(false);
    trust
        .add(SecretKey::from_seed(&[0x11; 32]).public_key("test"), KeyRole::Prod)
        .expect("trust");
    let parent = tempfile::tempdir().expect("tempdir");
    let dest = parent.path().join("staging");
    let res = homing_format::verify_and_extract(data, VerifyOptions::new(&trust), &dest);
    let left = entries(parent.path());
    match res {
        // Success: the only thing created is the staging directory itself.
        Ok(_) => assert_eq!(left, vec![dest.clone()], "wrote outside the staging dir"),
        // Failure: nothing is left behind at all.
        Err(_) => assert!(left.is_empty(), "left files after a failed extraction: {left:?}"),
    }
});
