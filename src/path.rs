//! Package path rules.

use crate::error::{Error, ErrorCode, Result};

/// Maximum length of a package path in bytes.
pub const MAX_PATH: usize = 255;

/// Top-level directories a payload file may live in.
pub const PAYLOAD_ROOTS: [&str; 3] = ["bundle/", "config/", "sbom/"];

/// Validate a relative package path.
///
/// Rules: UTF-8; 1..=255 bytes; `/`-separated; no leading `/`; no empty, `.` or `..`
/// components; no control characters or backslashes. A single trailing `/` is allowed only when
/// `is_dir` is true and is stripped from the returned value.
pub fn validate(raw: &[u8], is_dir: bool) -> Result<String> {
    let s = std::str::from_utf8(raw).map_err(|_| path_err("path is not UTF-8", raw))?;
    let s = if is_dir {
        s.strip_suffix('/').unwrap_or(s)
    } else {
        s
    };
    if s.is_empty() || s.len() > MAX_PATH {
        return Err(path_err("path empty or longer than 255 bytes", raw));
    }
    if s.starts_with('/') {
        return Err(path_err("absolute path", raw));
    }
    if s.chars().any(|c| c.is_control() || c == '\\') {
        return Err(path_err("control character or backslash in path", raw));
    }
    for comp in s.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(path_err("empty, '.' or '..' path component", raw));
        }
    }
    Ok(s.to_owned())
}

/// Validate a path that must name a payload file (under `bundle/`, `config/` or `sbom/`).
pub fn validate_payload_file(raw: &[u8]) -> Result<String> {
    let p = validate(raw, false)?;
    if !PAYLOAD_ROOTS.iter().any(|r| p.starts_with(r)) {
        return Err(path_err("file outside bundle/, config/ or sbom/", raw));
    }
    Ok(p)
}

fn path_err(why: &str, raw: &[u8]) -> Error {
    Error::new(
        ErrorCode::Path,
        format!("{why}: {:?}", String::from_utf8_lossy(raw)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_paths() {
        assert_eq!(
            validate(b"bundle/lib/libapp.so", false).unwrap(),
            "bundle/lib/libapp.so"
        );
        assert_eq!(validate(b"bundle/lib/", true).unwrap(), "bundle/lib");
        assert_eq!(
            validate(b"config/a b.json", false).unwrap(),
            "config/a b.json"
        );
    }

    #[test]
    fn rejects_bad_paths() {
        let long = "a/".repeat(130) + "b";
        let cases: &[&[u8]] = &[
            b"",
            b"/etc/passwd",
            b"../x",
            b"bundle/../../x",
            b"bundle/./x",
            b"bundle//x",
            b"bundle/x/",
            b"bundle\\x",
            b"bundle/\x01",
            b"bundle/\xff",
            long.as_bytes(),
        ];
        for c in cases {
            assert_eq!(
                validate(c, false).unwrap_err().code(),
                ErrorCode::Path,
                "{c:?}"
            );
        }
    }

    #[test]
    fn payload_roots_enforced() {
        assert!(validate_payload_file(b"config/app.json").is_ok());
        assert!(validate_payload_file(b"sbom/spdx.json").is_ok());
        for bad in [
            &b"manifest.json"[..],
            b"bundleX/a",
            b"other/a",
            b".homing-meta/x",
        ] {
            assert_eq!(
                validate_payload_file(bad).unwrap_err().code(),
                ErrorCode::Path
            );
        }
    }
}
