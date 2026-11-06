//! Error codes shared by every homing implementation.

use std::fmt;

/// A spec error code. The string form (`E_SCHEMA`, ...) is part of the contract: it appears in
/// CLI output, the agent API (`error.data.code`) and `report.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Unknown schema, invalid JSON, schema violation, malformed key or signature file.
    Schema,
    /// Signing key not in the trust store (or a dev key outside dev mode).
    KeyUnknown,
    /// Signature invalid.
    Sig,
    /// File hash or size mismatch.
    Hash,
    /// Archive entry not listed in the manifest, or listed but missing.
    ExtraFile,
    /// Illegal path or entry type.
    Path,
    /// `engine_hash` does not match the device.
    Engine,
    /// Architecture mismatch.
    Arch,
    /// Machine mismatch.
    Machine,
    /// Graphics backend mismatch.
    Graphics,
    /// Base image too old.
    BaseImage,
    /// `version_code` below the anti-rollback floor.
    Rollback,
    /// Insufficient storage.
    Space,
    /// New version failed its trial and was rolled back.
    Health,
    /// Another job is running or the install is deferred.
    Busy,
    /// Caller not permitted.
    Perm,
    /// Filesystem error.
    Io,
}

impl ErrorCode {
    /// Every code, in spec order.
    pub const ALL: [ErrorCode; 17] = [
        Self::Schema,
        Self::KeyUnknown,
        Self::Sig,
        Self::Hash,
        Self::ExtraFile,
        Self::Path,
        Self::Engine,
        Self::Arch,
        Self::Machine,
        Self::Graphics,
        Self::BaseImage,
        Self::Rollback,
        Self::Space,
        Self::Health,
        Self::Busy,
        Self::Perm,
        Self::Io,
    ];

    /// The wire form, e.g. `"E_SCHEMA"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "E_SCHEMA",
            Self::KeyUnknown => "E_KEY_UNKNOWN",
            Self::Sig => "E_SIG",
            Self::Hash => "E_HASH",
            Self::ExtraFile => "E_EXTRA_FILE",
            Self::Path => "E_PATH",
            Self::Engine => "E_ENGINE",
            Self::Arch => "E_ARCH",
            Self::Machine => "E_MACHINE",
            Self::Graphics => "E_GRAPHICS",
            Self::BaseImage => "E_BASE_IMAGE",
            Self::Rollback => "E_ROLLBACK",
            Self::Space => "E_SPACE",
            Self::Health => "E_HEALTH",
            Self::Busy => "E_BUSY",
            Self::Perm => "E_PERM",
            Self::Io => "E_IO",
        }
    }

    /// Parse the wire form.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error with its spec code and a human-readable context message.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Error {
    code: ErrorCode,
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// Create an error with a code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    /// Attach an underlying cause.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The spec error code.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The context message (without the code prefix).
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn schema(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Schema, message)
    }

    pub(crate) fn io(message: impl Into<String>, source: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, message).with_source(source)
    }
}

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in ErrorCode::ALL {
            assert!(seen.insert(c.as_str()));
            assert_eq!(ErrorCode::parse(c.as_str()), Some(c));
        }
        assert_eq!(ErrorCode::parse("E_NOPE"), None);
    }

    #[test]
    fn display_includes_code() {
        let e = Error::new(ErrorCode::Sig, "bad");
        assert_eq!(e.to_string(), "E_SIG: bad");
    }
}
