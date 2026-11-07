//! Index parsing and build selection must never panic; a parsed index must round-trip, and a
//! selected build must be newer than the installed version and compatible with the device.
#![no_main]

use homing_format::manifest::{Arch, Graphics};
use homing_format::{DeviceInfo, Index, Selection};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(index) = Index::parse(data) else { return };
    assert_eq!(Index::parse(&index.to_bytes()).expect("round trip"), index);
    let device = DeviceInfo::new(
        "0123456789abcdef0123456789abcdef01234567",
        Arch::Aarch64,
        "raspberrypi3-64",
        vec![Graphics::DrmGles],
        "1.0.0",
    );
    for app in &index.apps {
        for installed in [0, app.version_code.saturating_sub(1), app.version_code] {
            if let Selection::Update { app: a, build } = index.select(&app.id, installed, 0, &device) {
                assert_eq!(a.id, app.id);
                assert!(a.version_code > installed);
                assert!(device.check_compat(&build.compat()).is_ok());
            }
        }
    }
});
