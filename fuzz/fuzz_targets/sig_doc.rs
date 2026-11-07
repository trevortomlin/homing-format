//! Signature document parsing must never panic, and a parsed document must round-trip.
#![no_main]

use homing_format::SigDoc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = SigDoc::parse(data) {
        assert_eq!(SigDoc::parse(&s.to_bytes()).expect("round trip"), s);
    }
});
