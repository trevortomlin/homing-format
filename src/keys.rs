//! Ed25519 key files and key ids.

use std::fmt;
use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, ErrorCode, Result};

const PUB_TAG: &str = "homing-ed25519";
const SECRET_TAG: &str = "homing-ed25519-secret";
/// Key files are tiny; refuse to read anything larger.
const MAX_KEY_FILE: u64 = 4096;

/// A 16-hex-character key id: first 8 bytes of sha256(public key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 8]);

impl KeyId {
    /// Compute the key id of a raw public key.
    pub fn of(public: &[u8; 32]) -> Self {
        let digest = Sha256::digest(public);
        let mut id = [0u8; 8];
        id.copy_from_slice(&digest[..8]);
        Self(id)
    }

    /// Parse the 16 lowercase hex character form. Uppercase is rejected.
    pub fn parse(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.len() != 16 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(Error::schema(format!("invalid key_id {s:?}")));
        }
        let mut id = [0u8; 8];
        for (i, pair) in b.chunks(2).enumerate() {
            id[i] = (hex_val(pair[0]) << 4) | hex_val(pair[1]);
        }
        Ok(Self(id))
    }
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A public key as stored in a `*.pub` file.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
    comment: String,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("key_id", &self.key_id())
            .field("comment", &self.comment)
            .finish()
    }
}

impl PublicKey {
    /// Parse the single-line `homing-ed25519 <base64>[ <comment>]` format.
    pub fn parse(text: &str) -> Result<Self> {
        let line = single_line(text)?;
        let rest = line
            .strip_prefix(PUB_TAG)
            .and_then(|r| r.strip_prefix(' '))
            .ok_or_else(|| Error::schema(format!("public key must start with \"{PUB_TAG} \"")))?;
        let (b64, comment) = match rest.split_once(' ') {
            Some((k, c)) => (k, c),
            None => (rest, ""),
        };
        if !comment.bytes().all(|c| (0x20..0x7f).contains(&c)) {
            return Err(Error::schema("public key comment must be printable ASCII"));
        }
        let raw = decode_32(b64, "public key")?;
        // `from_bytes` rejects points that do not decompress. Small-order keys are rejected at
        // verification time by `verify_strict`.
        let key = VerifyingKey::from_bytes(&raw)
            .map_err(|e| Error::schema("public key is not a valid Ed25519 point").with_source(e))?;
        Ok(Self {
            key,
            comment: comment.to_owned(),
        })
    }

    /// Read and parse a `*.pub` file.
    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(&read_small(path)?)
    }

    /// Serialize to the file format (with trailing newline).
    pub fn to_file_string(&self) -> String {
        let b64 = B64.encode(self.key.as_bytes());
        if self.comment.is_empty() {
            format!("{PUB_TAG} {b64}\n")
        } else {
            format!("{PUB_TAG} {b64} {}\n", self.comment)
        }
    }

    /// The key id.
    pub fn key_id(&self) -> KeyId {
        KeyId::of(self.key.as_bytes())
    }

    /// The comment (may be empty).
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_bytes()
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// A secret signing key (`*.key` file). The seed is zeroized on drop.
pub struct SecretKey {
    key: SigningKey,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl SecretKey {
    /// Generate a new key from the OS random number generator.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| {
            Error::new(
                ErrorCode::Io,
                format!("random number generator failed: {e}"),
            )
        })?;
        let key = SigningKey::from_bytes(&seed);
        zeroize_array(&mut seed);
        Ok(Self { key })
    }

    /// Build a key from a 32-byte seed (used for deterministic test vectors).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Parse the single-line `homing-ed25519-secret <base64>` format.
    pub fn parse(text: &str) -> Result<Self> {
        let line = single_line(text)?;
        let b64 = line
            .strip_prefix(SECRET_TAG)
            .and_then(|r| r.strip_prefix(' '))
            .ok_or_else(|| {
                Error::schema(format!("secret key must start with \"{SECRET_TAG} \""))
            })?;
        let mut seed = decode_32(b64, "secret key")?;
        let key = SigningKey::from_bytes(&seed);
        zeroize_array(&mut seed);
        Ok(Self { key })
    }

    /// Parse a base64 seed without the tag (for `HOMING_SIGNING_KEY` env var in CI).
    pub fn from_base64_seed(b64: &str) -> Result<Self> {
        let mut seed = decode_32(b64.trim(), "secret key")?;
        let key = SigningKey::from_bytes(&seed);
        zeroize_array(&mut seed);
        Ok(Self { key })
    }

    /// Read and parse a `*.key` file.
    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(&read_small(path)?)
    }

    /// Write the key file with mode 0600, refusing to overwrite an existing file.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| Error::io(format!("cannot create {}", path.display()), e))?;
        let line = format!("{SECRET_TAG} {}\n", B64.encode(self.key.as_bytes()));
        f.write_all(line.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| Error::io(format!("cannot write {}", path.display()), e))
    }

    /// The matching public key with a comment.
    pub fn public_key(&self, comment: &str) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
            comment: comment.to_owned(),
        }
    }

    /// The key id of the matching public key.
    pub fn key_id(&self) -> KeyId {
        KeyId::of(self.key.verifying_key().as_bytes())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

fn zeroize_array(a: &mut [u8; 32]) {
    // Volatile-ish clear without an extra dependency; SigningKey itself zeroizes on drop.
    for b in a.iter_mut() {
        // SAFETY not needed: plain write; `black_box` discourages the optimizer from eliding it.
        *b = std::hint::black_box(0);
    }
}

/// Accept exactly one line, optionally followed by a single `\n`.
fn single_line(text: &str) -> Result<&str> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') || line.contains('\r') {
        return Err(Error::schema("key file must be a single line"));
    }
    Ok(line)
}

fn decode_32(b64: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| Error::schema(format!("{what}: invalid base64")).with_source(e))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| Error::schema(format!("{what}: expected 32 bytes, got {}", v.len())))
}

fn read_small(path: &Path) -> Result<String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::io(format!("cannot stat {}", path.display()), e))?;
    if meta.len() > MAX_KEY_FILE {
        return Err(Error::schema(format!(
            "{} is too large for a key file",
            path.display()
        )));
    }
    let bytes =
        std::fs::read(path).map_err(|e| Error::io(format!("cannot read {}", path.display()), e))?;
    String::from_utf8(bytes).map_err(|_| Error::schema(format!("{} is not UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn public_key_round_trip_with_and_without_comment() {
        let sk = SecretKey::from_seed(&SEED);
        for comment in ["", "release key 2026"] {
            let pk = sk.public_key(comment);
            let text = pk.to_file_string();
            let back = PublicKey::parse(&text).expect("parse");
            assert_eq!(back, pk);
            assert_eq!(back.comment(), comment);
            // Also without the trailing newline.
            assert_eq!(PublicKey::parse(text.trim_end()).expect("parse"), pk);
        }
    }

    #[test]
    fn key_id_is_sha256_prefix() {
        let pk = SecretKey::from_seed(&SEED).public_key("");
        let full = Sha256::digest(pk.as_bytes());
        let expect: String = full[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(pk.key_id().to_string(), expect);
        assert_eq!(KeyId::parse(&expect).expect("parse"), pk.key_id());
    }

    #[test]
    fn key_id_parse_rejects_bad_forms() {
        for bad in [
            "",
            "0123",
            "0123456789ABCDEF",
            "0123456789abcdeg",
            "0123456789abcdef0",
        ] {
            assert_eq!(
                KeyId::parse(bad).unwrap_err().code(),
                ErrorCode::Schema,
                "{bad}"
            );
        }
    }

    #[test]
    fn public_key_rejects_malformed() {
        let good_b64 = B64.encode(SecretKey::from_seed(&SEED).public_key("").as_bytes());
        let cases = [
            String::new(),
            format!("ssh-ed25519 {good_b64}"),
            format!("homing-ed25519  {good_b64}"), // double space
            format!("homing-ed25519 {good_b64}\n\n"), // two newlines
            format!("homing-ed25519 {good_b64}\r\n"), // CRLF
            format!("homing-ed25519 {}", B64.encode([1u8; 31])), // short
            format!("homing-ed25519 {}", B64.encode([1u8; 33])), // long
            "homing-ed25519 !!!notbase64!!!".to_owned(),
            format!("homing-ed25519 {good_b64} tab\tcomment"),
            format!("homing-ed25519-secret {good_b64}"),
        ];
        for c in cases {
            assert_eq!(
                PublicKey::parse(&c).unwrap_err().code(),
                ErrorCode::Schema,
                "{c:?}"
            );
        }
    }

    #[test]
    fn secret_key_rejects_public_key_file_and_vice_versa() {
        let sk = SecretKey::from_seed(&SEED);
        let pub_text = sk.public_key("x").to_file_string();
        assert!(SecretKey::parse(&pub_text).is_err());
    }

    #[test]
    fn secret_key_file_is_0600_and_not_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("release.key");
        let sk = SecretKey::generate().expect("generate");
        sk.write_new(&path).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let back = SecretKey::read(&path).expect("read");
        assert_eq!(back.key_id(), sk.key_id());
        let err = sk.write_new(&path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Io);
    }

    #[test]
    fn oversized_key_file_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.pub");
        std::fs::write(&path, vec![b'a'; 5000]).expect("write");
        assert_eq!(
            PublicKey::read(&path).unwrap_err().code(),
            ErrorCode::Schema
        );
    }

    #[test]
    fn generated_keys_differ() {
        let a = SecretKey::generate().expect("a");
        let b = SecretKey::generate().expect("b");
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let sk = SecretKey::from_seed(&SEED);
        let dbg = format!("{sk:?}");
        assert!(!dbg.contains(&B64.encode(SEED)));
    }
}
