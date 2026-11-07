//! Full package verification must never panic. Seed the corpus with the valid test vectors
//! (signed with the test key trusted here) so that mutations behind the signed head reach the
//! archive checks.
#![no_main]

use homing_format::manifest::{Arch, Graphics};
use homing_format::{DeviceInfo, KeyRole, SecretKey, TrustStore, VerifyOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut trust = TrustStore::new(false);
    // The test-vector key (TEST ONLY).
    trust
        .add(SecretKey::from_seed(&[0x11; 32]).public_key("test"), KeyRole::Prod)
        .expect("trust");
    let device = DeviceInfo::new(
        "0123456789abcdef0123456789abcdef01234567",
        Arch::Aarch64,
        "raspberrypi3-64",
        vec![Graphics::DrmGles],
        "1.0.0",
    );
    let _ = homing_format::verify(data, VerifyOptions::new(&trust).device(&device));
    let _ = homing_format::verify_head(data, &trust);
    let _ = homing_format::inspect(data);
});
