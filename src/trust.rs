//! Trust store: the set of public keys a verifier accepts.

use std::collections::HashMap;
use std::path::Path;

use crate::error::{Error, ErrorCode, Result};
use crate::keys::{KeyId, PublicKey};

/// Role of a trusted key, taken from its file name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// `prod-*.pub`: always honored.
    Prod,
    /// `dev-*.pub`: honored only in dev mode.
    Dev,
}

#[derive(Debug, Clone)]
struct Entry {
    key: PublicKey,
    role: KeyRole,
}

/// A set of trusted public keys plus the dev-mode flag.
#[derive(Debug, Clone)]
pub struct TrustStore {
    keys: HashMap<KeyId, Entry>,
    allow_dev: bool,
}

impl TrustStore {
    /// An empty store. `allow_dev` enables dev keys (device dev mode).
    pub fn new(allow_dev: bool) -> Self {
        Self {
            keys: HashMap::new(),
            allow_dev,
        }
    }

    /// Load every `*.pub` file directly inside `dir` (not recursive).
    ///
    /// Fails closed: a `*.pub` file without a `prod-` or `dev-` prefix, a malformed key, or two
    /// files with the same key id make loading fail.
    pub fn load_dir(dir: &Path, allow_dev: bool) -> Result<Self> {
        let mut store = Self::new(allow_dev);
        let rd = std::fs::read_dir(dir)
            .map_err(|e| Error::io(format!("cannot read trust store {}", dir.display()), e))?;
        let mut paths = Vec::new();
        for ent in rd {
            let ent = ent.map_err(|e| Error::io(format!("cannot read {}", dir.display()), e))?;
            paths.push(ent.path());
        }
        paths.sort();
        for path in paths {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".pub") {
                continue;
            }
            let role = if name.starts_with("prod-") {
                KeyRole::Prod
            } else if name.starts_with("dev-") {
                KeyRole::Dev
            } else {
                return Err(Error::schema(format!(
                    "trust store key {name} must be named prod-*.pub or dev-*.pub"
                )));
            };
            let key = PublicKey::read(&path).map_err(|e| {
                Error::new(e.code(), format!("{}: {}", path.display(), e.message()))
            })?;
            store.add(key, role)?;
        }
        Ok(store)
    }

    /// Add a key. Fails if the key id is already present.
    pub fn add(&mut self, key: PublicKey, role: KeyRole) -> Result<()> {
        let id = key.key_id();
        if self.keys.contains_key(&id) {
            return Err(Error::schema(format!(
                "duplicate key id {id} in trust store"
            )));
        }
        self.keys.insert(id, Entry { key, role });
        Ok(())
    }

    /// Whether dev keys are honored.
    pub fn allow_dev(&self) -> bool {
        self.allow_dev
    }

    /// Number of keys honored in the current mode.
    pub fn usable_len(&self) -> usize {
        self.keys.values().filter(|e| self.usable(e)).count()
    }

    /// True if the store contains at least one prod key.
    pub fn has_prod_key(&self) -> bool {
        self.keys.values().any(|e| e.role == KeyRole::Prod)
    }

    fn usable(&self, e: &Entry) -> bool {
        e.role == KeyRole::Prod || self.allow_dev
    }

    /// Find a key usable in the current mode, else `E_KEY_UNKNOWN`.
    pub fn lookup(&self, id: &KeyId) -> Result<&PublicKey> {
        match self.keys.get(id) {
            Some(e) if self.usable(e) => Ok(&e.key),
            Some(_) => Err(Error::new(
                ErrorCode::KeyUnknown,
                format!("key {id} is a dev key and dev mode is off"),
            )),
            None => Err(Error::new(
                ErrorCode::KeyUnknown,
                format!("key {id} is not trusted"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;

    fn write_key(dir: &Path, name: &str, seed: u8) -> KeyId {
        let pk = SecretKey::from_seed(&[seed; 32]).public_key(name);
        std::fs::write(dir.join(name), pk.to_file_string()).expect("write");
        pk.key_id()
    }

    #[test]
    fn loads_prod_and_dev_keys_and_ignores_other_files() {
        let d = tempfile::tempdir().expect("tempdir");
        let prod = write_key(d.path(), "prod-release.pub", 1);
        let dev = write_key(d.path(), "dev-alice.pub", 2);
        std::fs::write(d.path().join("README"), "not a key").expect("write");
        std::fs::create_dir(d.path().join("sub")).expect("mkdir");
        write_key(&d.path().join("sub"), "bogus.pub", 3); // not recursive, so never seen

        let t = TrustStore::load_dir(d.path(), false).expect("load");
        assert!(t.lookup(&prod).is_ok());
        assert_eq!(t.lookup(&dev).unwrap_err().code(), ErrorCode::KeyUnknown);
        assert_eq!(t.usable_len(), 1);
        assert!(t.has_prod_key());

        let t = TrustStore::load_dir(d.path(), true).expect("load");
        assert!(t.lookup(&dev).is_ok());
        assert_eq!(t.usable_len(), 2);
    }

    #[test]
    fn unprefixed_pub_file_fails_closed() {
        let d = tempfile::tempdir().expect("tempdir");
        write_key(d.path(), "prod-a.pub", 1);
        write_key(d.path(), "release.pub", 2);
        assert_eq!(
            TrustStore::load_dir(d.path(), false).unwrap_err().code(),
            ErrorCode::Schema
        );
    }

    #[test]
    fn malformed_key_fails_closed() {
        let d = tempfile::tempdir().expect("tempdir");
        std::fs::write(d.path().join("prod-x.pub"), "garbage").expect("write");
        let err = TrustStore::load_dir(d.path(), false).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Schema);
        assert!(err.message().contains("prod-x.pub"));
    }

    #[test]
    fn duplicate_key_id_fails_closed() {
        let d = tempfile::tempdir().expect("tempdir");
        write_key(d.path(), "prod-a.pub", 1);
        write_key(d.path(), "dev-a.pub", 1);
        assert_eq!(
            TrustStore::load_dir(d.path(), true).unwrap_err().code(),
            ErrorCode::Schema
        );
    }

    #[test]
    fn missing_dir_is_e_io() {
        let d = tempfile::tempdir().expect("tempdir");
        let err = TrustStore::load_dir(&d.path().join("nope"), false).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Io);
    }

    #[test]
    fn unknown_key_is_e_key_unknown() {
        let t = TrustStore::new(true);
        let id = SecretKey::from_seed(&[9; 32]).key_id();
        assert_eq!(t.lookup(&id).unwrap_err().code(), ErrorCode::KeyUnknown);
    }
}
