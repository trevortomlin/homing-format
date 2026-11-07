//! Accepted package paths are always relative, normalized and inside the package.
#![no_main]

use homing_format::path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for is_dir in [false, true] {
        if let Ok(p) = path::validate(data, is_dir) {
            assert!(!p.is_empty() && p.len() <= path::MAX_PATH);
            assert!(!p.starts_with('/') && !p.contains('\\'));
            assert!(p.split('/').all(|c| !c.is_empty() && c != "." && c != ".."));
            assert!(!p.chars().any(char::is_control));
        }
    }
    if let Ok(p) = path::validate_payload_file(data) {
        assert!(path::PAYLOAD_ROOTS.iter().any(|r| p.starts_with(r)));
    }
});
