//! Detached signature documents and domain-separated signing.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer as _};
use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorCode, Result};
use crate::keys::{KeyId, PublicKey, SecretKey};
use crate::trust::TrustStore;

/// Maximum size of a signature document.
pub const MAX_SIG_DOC: usize = 4096;

/// Which kind of document a signature covers. Part of the signed message, so a signature for one
/// kind can never verify as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocType {
    /// `manifest.json` inside a package.
    Manifest,
    /// `bundle.json` inside an offline bundle.
    Bundle,
    /// `index.json` served by an HTTP source.
    Index,
}

impl DocType {
    fn context(self) -> &'static [u8] {
        match self {
            Self::Manifest => b"homing/manifest/v1\0",
            Self::Bundle => b"homing/bundle/v1\0",
            Self::Index => b"homing/index/v1\0",
        }
    }
}

fn message(doc_type: DocType, doc: &[u8]) -> Vec<u8> {
    let ctx = doc_type.context();
    let mut m = Vec::with_capacity(ctx.len() + doc.len());
    m.extend_from_slice(ctx);
    m.extend_from_slice(doc);
    m
}

/// A parsed `*.sig` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigDoc {
    /// Id of the signing key.
    pub key_id: KeyId,
    /// The 64-byte Ed25519 signature.
    pub sig: [u8; 64],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigDocJson {
    schema: u32,
    alg: String,
    key_id: String,
    sig: String,
}

impl SigDoc {
    /// Parse and validate a signature document. Unknown fields are rejected.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIG_DOC {
            return Err(Error::schema("signature document larger than 4 KiB"));
        }
        let j: SigDocJson = serde_json::from_slice(bytes)
            .map_err(|e| Error::schema("invalid signature document").with_source(e))?;
        if j.schema != 1 {
            return Err(Error::schema(format!(
                "unknown signature schema {}",
                j.schema
            )));
        }
        if j.alg != "ed25519" {
            return Err(Error::schema(format!(
                "unsupported signature alg {:?}",
                j.alg
            )));
        }
        let key_id = KeyId::parse(&j.key_id)?;
        let raw = B64
            .decode(&j.sig)
            .map_err(|e| Error::schema("signature: invalid base64").with_source(e))?;
        let sig: [u8; 64] = raw.try_into().map_err(|v: Vec<u8>| {
            Error::schema(format!("signature: expected 64 bytes, got {}", v.len()))
        })?;
        Ok(Self { key_id, sig })
    }

    /// Serialize to compact JSON with a trailing newline.
    pub fn to_bytes(&self) -> Vec<u8> {
        let j = SigDocJson {
            schema: 1,
            alg: "ed25519".into(),
            key_id: self.key_id.to_string(),
            sig: B64.encode(self.sig),
        };
        // Serializing a struct of strings and an integer cannot fail.
        let mut out = serde_json::to_vec(&j).unwrap_or_default();
        out.push(b'\n');
        out
    }
}

/// Sign the exact bytes of a document.
pub fn sign(key: &SecretKey, doc_type: DocType, doc: &[u8]) -> SigDoc {
    let sig = key.signing_key().sign(&message(doc_type, doc));
    SigDoc {
        key_id: key.key_id(),
        sig: sig.to_bytes(),
    }
}

/// Verify a signature against one specific public key (strict verification).
pub fn verify_with_key(key: &PublicKey, doc_type: DocType, doc: &[u8], sig: &SigDoc) -> Result<()> {
    if sig.key_id != key.key_id() {
        return Err(Error::new(
            ErrorCode::KeyUnknown,
            format!("signature is by key {}", sig.key_id),
        ));
    }
    let s = Signature::from_bytes(&sig.sig);
    key.verifying_key()
        .verify_strict(&message(doc_type, doc), &s)
        .map_err(|e| Error::new(ErrorCode::Sig, "signature verification failed").with_source(e))
}

/// Parse a signature document and verify it against a trust store.
///
/// Returns the key that signed the document. Fails with `E_SCHEMA` (malformed signature
/// document), `E_KEY_UNKNOWN` (key not trusted in the store's mode) or `E_SIG`.
pub fn verify<'a>(
    trust: &'a TrustStore,
    doc_type: DocType,
    doc: &[u8],
    sig_bytes: &[u8],
) -> Result<&'a PublicKey> {
    let sig = SigDoc::parse(sig_bytes)?;
    let key = trust.lookup(&sig.key_id)?;
    verify_with_key(key, doc_type, doc, &sig)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{KeyRole, TrustStore};

    fn store(seed: u8) -> (SecretKey, TrustStore) {
        let sk = SecretKey::from_seed(&[seed; 32]);
        let mut t = TrustStore::new(false);
        t.add(sk.public_key("test"), KeyRole::Prod).expect("add");
        (sk, t)
    }

    #[test]
    fn sign_verify_round_trip() {
        let (sk, t) = store(1);
        let doc = br#"{"schema":1}"#;
        let sig = sign(&sk, DocType::Manifest, doc).to_bytes();
        let key = verify(&t, DocType::Manifest, doc, &sig).expect("verify");
        assert_eq!(key.key_id(), sk.key_id());
    }

    #[test]
    fn signatures_are_deterministic() {
        let (sk, _) = store(1);
        assert_eq!(
            sign(&sk, DocType::Index, b"x"),
            sign(&sk, DocType::Index, b"x")
        );
    }

    #[test]
    fn modified_document_fails_with_e_sig() {
        let (sk, t) = store(1);
        let sig = sign(&sk, DocType::Manifest, b"hello").to_bytes();
        let err = verify(&t, DocType::Manifest, b"hellp", &sig).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Sig);
    }

    #[test]
    fn domain_separation_prevents_cross_type_use() {
        let (sk, t) = store(1);
        let doc = b"{}";
        let sig = sign(&sk, DocType::Index, doc).to_bytes();
        for other in [DocType::Manifest, DocType::Bundle] {
            assert_eq!(
                verify(&t, other, doc, &sig).unwrap_err().code(),
                ErrorCode::Sig
            );
        }
    }

    #[test]
    fn raw_unprefixed_signature_is_rejected() {
        let (sk, t) = store(1);
        let doc = b"{}";
        let raw = sk.signing_key().sign(doc).to_bytes();
        let sig = SigDoc {
            key_id: sk.key_id(),
            sig: raw,
        }
        .to_bytes();
        assert_eq!(
            verify(&t, DocType::Manifest, doc, &sig).unwrap_err().code(),
            ErrorCode::Sig
        );
    }

    #[test]
    fn unknown_key_fails_with_e_key_unknown() {
        let (_, t) = store(1);
        let (other, _) = store(2);
        let sig = sign(&other, DocType::Manifest, b"x").to_bytes();
        assert_eq!(
            verify(&t, DocType::Manifest, b"x", &sig)
                .unwrap_err()
                .code(),
            ErrorCode::KeyUnknown
        );
    }

    #[test]
    fn non_canonical_s_is_rejected() {
        // Adding the group order L to S yields a signature that lenient verifiers accept.
        let (sk, t) = store(1);
        let mut s = sign(&sk, DocType::Manifest, b"x");
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for (byte, l) in s.sig[32..].iter_mut().zip(L) {
            let v = u16::from(*byte) + u16::from(l) + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        let err = verify(&t, DocType::Manifest, b"x", &s.to_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Sig);
    }

    #[test]
    fn malformed_sig_docs_fail_with_e_schema() {
        let (sk, t) = store(1);
        let good = sign(&sk, DocType::Manifest, b"x");
        let kid = good.key_id.to_string();
        let sig = B64.encode(good.sig);
        let cases: Vec<String> = vec![
            "".into(),
            "not json".into(),
            "[]".into(),
            format!(r#"{{"schema":2,"alg":"ed25519","key_id":"{kid}","sig":"{sig}"}}"#),
            format!(r#"{{"schema":1,"alg":"rsa","key_id":"{kid}","sig":"{sig}"}}"#),
            format!(
                r#"{{"schema":1,"alg":"ed25519","key_id":"{}","sig":"{sig}"}}"#,
                kid.to_uppercase()
            ),
            format!(
                r#"{{"schema":1,"alg":"ed25519","key_id":"{kid}","sig":"{}"}}"#,
                B64.encode([0u8; 63])
            ),
            format!(r#"{{"schema":1,"alg":"ed25519","key_id":"{kid}"}}"#),
            format!(r#"{{"schema":1,"alg":"ed25519","key_id":"{kid}","sig":"{sig}","extra":1}}"#),
            format!(r#"{{"schema":"1","alg":"ed25519","key_id":"{kid}","sig":"{sig}"}}"#),
            format!(
                r#"{{"schema":1,"alg":"ed25519","key_id":"{kid}","sig":"{sig}"}}{}"#,
                " ".repeat(MAX_SIG_DOC)
            ),
        ];
        for c in cases {
            let err = verify(&t, DocType::Manifest, b"x", c.as_bytes()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Schema, "{c}");
        }
    }

    #[test]
    fn sig_doc_round_trip() {
        let (sk, _) = store(3);
        let d = sign(&sk, DocType::Bundle, b"b");
        assert_eq!(SigDoc::parse(&d.to_bytes()).expect("parse"), d);
    }
}
