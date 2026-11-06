//! Deterministic package writer.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, ErrorCode, Result};
use crate::keys::SecretKey;
use crate::manifest::{FileEntry, Manifest};
use crate::package::sha256_reader;
use crate::path;
use crate::sig::{self, DocType};

#[derive(Debug, Clone)]
enum Source {
    Disk(PathBuf),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
struct Item {
    source: Source,
    exec: bool,
}

/// Collects payload files and writes a signed, deterministic package.
#[derive(Debug, Default)]
pub struct PackageWriter {
    items: BTreeMap<String, Item>,
    mtime: u64,
    zstd_level: Option<i32>,
}

impl PackageWriter {
    /// New writer. `mtime` is used for every entry (use `SOURCE_DATE_EPOCH` or 0).
    pub fn new(mtime: u64) -> Self {
        Self {
            items: BTreeMap::new(),
            mtime,
            zstd_level: Some(12),
        }
    }

    /// Set zstd compression level, or `None` for an uncompressed tar.
    pub fn compression(mut self, level: Option<i32>) -> Self {
        self.zstd_level = level;
        self
    }

    /// Add every regular file under `src` with package path prefix `prefix` (e.g. `bundle`).
    /// Symlinks and special files are rejected (`E_PATH`).
    pub fn add_dir(&mut self, src: &Path, prefix: &str) -> Result<()> {
        let mut stack = vec![(src.to_path_buf(), prefix.to_owned())];
        while let Some((dir, pre)) = stack.pop() {
            let rd = fs::read_dir(&dir)
                .map_err(|e| Error::io(format!("cannot read {}", dir.display()), e))?;
            for ent in rd {
                let ent =
                    ent.map_err(|e| Error::io(format!("cannot read {}", dir.display()), e))?;
                let name = ent.file_name();
                let name = name.to_str().ok_or_else(|| {
                    Error::new(
                        ErrorCode::Path,
                        format!("non-UTF-8 name in {}", dir.display()),
                    )
                })?;
                let ft = fs::symlink_metadata(ent.path())
                    .map_err(|e| Error::io(format!("cannot stat {}", ent.path().display()), e))?;
                let pkg = format!("{pre}/{name}");
                if ft.is_dir() {
                    stack.push((ent.path(), pkg));
                } else if ft.is_file() {
                    #[cfg(unix)]
                    let exec = {
                        use std::os::unix::fs::PermissionsExt as _;
                        ft.permissions().mode() & 0o111 != 0
                    };
                    #[cfg(not(unix))]
                    let exec = false;
                    self.add_file(&pkg, ent.path(), exec)?;
                } else {
                    return Err(Error::new(
                        ErrorCode::Path,
                        format!("{} is a symlink or special file", ent.path().display()),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Add one file from disk.
    pub fn add_file(&mut self, pkg_path: &str, src: PathBuf, exec: bool) -> Result<()> {
        self.insert(
            pkg_path,
            Item {
                source: Source::Disk(src),
                exec,
            },
        )
    }

    /// Add one file from memory.
    pub fn add_bytes(&mut self, pkg_path: &str, data: Vec<u8>, exec: bool) -> Result<()> {
        self.insert(
            pkg_path,
            Item {
                source: Source::Bytes(data),
                exec,
            },
        )
    }

    fn insert(&mut self, pkg_path: &str, item: Item) -> Result<()> {
        let p = path::validate_payload_file(pkg_path.as_bytes())?;
        if self.items.insert(p.clone(), item).is_some() {
            return Err(Error::new(ErrorCode::Path, format!("duplicate path {p}")));
        }
        Ok(())
    }

    /// Paths added so far, sorted.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.items.keys().map(String::as_str)
    }

    fn open(item: &Item) -> Result<Box<dyn Read + '_>> {
        Ok(match &item.source {
            Source::Disk(p) => Box::new(
                fs::File::open(p)
                    .map_err(|e| Error::io(format!("cannot open {}", p.display()), e))?,
            ),
            Source::Bytes(b) => Box::new(&b[..]),
        })
    }

    /// Hash the payload, fill `manifest.files`, validate, sign and write the package.
    /// Returns the final manifest.
    pub fn write<W: Write>(
        &self,
        mut manifest: Manifest,
        key: &SecretKey,
        out: W,
    ) -> Result<Manifest> {
        manifest.files.clear();
        for (p, item) in &self.items {
            let (sha256, size) = sha256_reader(Self::open(item)?)
                .map_err(|e| Error::io(format!("hashing {p}"), e))?;
            manifest.files.push(FileEntry {
                path: p.clone(),
                sha256,
                size,
                exec: item.exec,
            });
        }
        manifest.validate()?;
        let mbytes = manifest.to_bytes();
        let sbytes = sig::sign(key, DocType::Manifest, &mbytes).to_bytes();

        match self.zstd_level {
            Some(level) => {
                let mut enc =
                    zstd::Encoder::new(out, level).map_err(|e| Error::io("zstd init failed", e))?;
                enc.include_checksum(true)
                    .map_err(|e| Error::io("zstd", e))?;
                let enc = self.write_tar(enc, &manifest, &mbytes, &sbytes)?;
                enc.finish()
                    .map_err(|e| Error::io("zstd finish failed", e))?;
            }
            None => {
                self.write_tar(out, &manifest, &mbytes, &sbytes)?;
            }
        }
        Ok(manifest)
    }

    fn write_tar<W: Write>(&self, out: W, m: &Manifest, mbytes: &[u8], sbytes: &[u8]) -> Result<W> {
        let mut b = tar::Builder::new(out);
        b.mode(tar::HeaderMode::Deterministic);
        self.append(&mut b, "manifest.json", mbytes.len() as u64, false, mbytes)?;
        self.append(&mut b, "manifest.sig", sbytes.len() as u64, false, sbytes)?;
        for f in &m.files {
            let item = &self.items[&f.path];
            // Size comes from the manifest; a file changing between hashing and writing makes the
            // tar crate fail (short read) or the package fail verification, never silently pass.
            self.append(&mut b, &f.path, f.size, f.exec, Self::open(item)?)?;
        }
        b.into_inner().map_err(|e| Error::io("writing tar", e))
    }

    fn append<W: Write, R: Read>(
        &self,
        b: &mut tar::Builder<W>,
        p: &str,
        size: u64,
        exec: bool,
        data: R,
    ) -> Result<()> {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(size);
        h.set_mode(if exec { 0o755 } else { 0o644 });
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(self.mtime);
        b.append_data(&mut h, p, data.take(size))
            .map_err(|e| Error::io(format!("writing {p} to archive"), e))
    }
}
