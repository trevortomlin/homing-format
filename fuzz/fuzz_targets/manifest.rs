//! Manifest parsing and validation must never panic, and a parsed manifest must round-trip.
#![no_main]

use homing_format::Manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Manifest::parse(data) {
        let again = Manifest::parse(&m.to_bytes()).expect("serialized manifest must parse");
        assert_eq!(m, again);
    }
});
