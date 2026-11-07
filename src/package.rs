//! Reading, verifying and extracting `.homing` packages.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::device::{DeviceInfo, check_floor};
use crate::error::{Error, ErrorCode, Result};
use crate::keys::KeyId;
use crate::manifest::{MAX_MANIFEST, Manifest};
use crate::path;
use crate::sig::{self, DocType, MAX_SIG_DOC, SigDoc};
use crate::trust::TrustStore;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Wrap a reader, transparently decompressing zstd (detected by magic bytes, not extension).
pub fn decompressing_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    let mut br = BufReader::with_capacity(64 * 1024, r);
    let head = br
        .fill_buf()
        .map_err(|e| Error::io("cannot read package", e))?;
    if head.starts_with(&ZSTD_MAGIC) {
        let d = zstd::Decoder::with_buffer(br).map_err(|e| Error::io("zstd init failed", e))?;
        Ok(Box::new(d))
    } else {
        Ok(Box::new(br))
    }
}

/// Result of a successful verification.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedPackage {
    /// The validated manifest.
    pub manifest: Manifest,
    /// Exact bytes of `manifest.json` (what the signature covers).
    pub manifest_bytes: Vec<u8>,
    /// Exact bytes of `manifest.sig`.
    pub sig_bytes: Vec<u8>,
    /// Key that signed the manifest.
    pub key_id: KeyId,
}

/// Inputs for a full verification.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct VerifyOptions<'a> {
    /// Trusted keys (and dev mode).
    pub trust: &'a TrustStore,
    /// Device to check `compat` against; `None` skips compat checks (host-side verify).
    pub device: Option<&'a DeviceInfo>,
    /// Anti-rollback floor for this app id.
    pub floor: u64,
}

impl<'a> VerifyOptions<'a> {
    /// Options for verifying against `trust`, with no device checks and a floor of 0.
    pub fn new(trust: &'a TrustStore) -> Self {
        Self {
            trust,
            device: None,
            floor: 0,
        }
    }

    /// Also check compatibility with `device`.
    pub fn device(mut self, device: &'a DeviceInfo) -> Self {
        self.device = Some(device);
        self
    }

    /// Reject packages whose `version_code` is below `floor`.
    pub fn floor(mut self, floor: u64) -> Self {
        self.floor = floor;
        self
    }
}

/// Read only `manifest.json` and `manifest.sig`, with no trust checks (for `homing inspect`).
pub fn inspect<R: Read>(r: R) -> Result<(Manifest, SigDoc)> {
    let reader = decompressing_reader(r)?;
    let mut ar = tar::Archive::new(reader);
    let mut entries = ar
        .entries()
        .map_err(|e| Error::schema("not a tar archive").with_source(e))?;
    let (mbytes, sbytes) = read_head(&mut entries)?;
    Ok((Manifest::parse(&mbytes)?, SigDoc::parse(&sbytes)?))
}

/// Read `manifest.json` + `manifest.sig` and check the signature (steps 1-3 of the verification
/// algorithm) without reading the payload. Use this instead of [`inspect`] whenever the manifest
/// will drive a decision, e.g. choosing the install directory.
pub fn verify_head<R: Read>(r: R, trust: &TrustStore) -> Result<VerifiedPackage> {
    let reader = decompressing_reader(r)?;
    let mut ar = tar::Archive::new(reader);
    let mut entries = ar
        .entries()
        .map_err(|e| Error::schema("not a tar archive").with_source(e))?;
    let (manifest_bytes, sig_bytes) = read_head(&mut entries)?;
    let key = sig::verify(trust, DocType::Manifest, &manifest_bytes, &sig_bytes)?;
    let key_id = key.key_id();
    let manifest = Manifest::parse(&manifest_bytes)?;
    Ok(VerifiedPackage {
        manifest,
        manifest_bytes,
        sig_bytes,
        key_id,
    })
}

/// Verify a package without writing anything (for `homing verify`).
pub fn verify<R: Read>(r: R, opts: VerifyOptions<'_>) -> Result<VerifiedPackage> {
    run(r, opts, None)
}

/// Verify a package and extract its payload into `dest`, which must not exist yet.
///
/// The signature is verified before any payload byte is read, and each file is hashed while it
/// is written. On any failure `dest` is removed. Files are created with mode 0644, or 0755 when
/// the manifest marks them `exec`; archive modes, owners and times are ignored. Every file is
/// fsynced; the caller is responsible for fsyncing directories and renaming `dest` into place.
///
/// # Security
///
/// Entry paths are validated (no absolute paths, `..`, links or special files) and files are
/// created with `create_new`, so an archive cannot overwrite anything or escape `dest`.
/// This relies on one assumption: **no other process can modify `dest` or its parent while
/// extraction runs.** If an attacker could, for example, replace a directory inside `dest`
/// with a symlink between the check and the write, files could land elsewhere. Put `dest` in
/// a directory that only the installing process can write to, as homing-agent does.
pub fn verify_and_extract<R: Read>(
    r: R,
    opts: VerifyOptions<'_>,
    dest: &Path,
) -> Result<VerifiedPackage> {
    fs::create_dir(dest)
        .map_err(|e| Error::io(format!("cannot create staging dir {}", dest.display()), e))?;
    let res = run(r, opts, Some(dest));
    if res.is_err() {
        let _ = fs::remove_dir_all(dest);
    }
    res
}

type Entries<'a, R> = tar::Entries<'a, R>;

fn read_head<R: Read>(entries: &mut Entries<'_, R>) -> Result<(Vec<u8>, Vec<u8>)> {
    let m = read_named(entries, "manifest.json", MAX_MANIFEST)?;
    let s = read_named(entries, "manifest.sig", MAX_SIG_DOC)?;
    Ok((m, s))
}

fn read_named<R: Read>(entries: &mut Entries<'_, R>, name: &str, max: usize) -> Result<Vec<u8>> {
    let mut e = entries
        .next()
        .ok_or_else(|| Error::schema(format!("archive ends before {name}")))?
        .map_err(|e| Error::schema("corrupt tar archive").with_source(e))?;
    let path = e.path_bytes().into_owned();
    if path != name.as_bytes() || !e.header().entry_type().is_file() {
        return Err(Error::schema(format!(
            "expected {name} as the next entry, found {:?}",
            String::from_utf8_lossy(&path)
        )));
    }
    let size = e
        .header()
        .size()
        .map_err(|e| Error::schema("bad tar header").with_source(e))?;
    if size > max as u64 {
        return Err(Error::schema(format!("{name} larger than {max} bytes")));
    }
    let mut buf = Vec::with_capacity(size as usize);
    e.by_ref()
        .take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::schema(format!("cannot read {name}")).with_source(e))?;
    Ok(buf)
}

fn run<R: Read>(r: R, opts: VerifyOptions<'_>, dest: Option<&Path>) -> Result<VerifiedPackage> {
    let reader = decompressing_reader(r)?;
    let mut ar = tar::Archive::new(reader);
    let mut entries = ar
        .entries()
        .map_err(|e| Error::schema("not a tar archive").with_source(e))?;

    // Steps 1-3: manifest + signature before any payload byte.
    let (manifest_bytes, sig_bytes) = read_head(&mut entries)?;
    let key = sig::verify(opts.trust, DocType::Manifest, &manifest_bytes, &sig_bytes)?;
    let key_id = key.key_id();
    let manifest = Manifest::parse(&manifest_bytes)?;

    // Step 4: compat + floor.
    if let Some(dev) = opts.device {
        dev.check(&manifest)?;
    }
    check_floor(&manifest, opts.floor)?;

    // Steps 5-6: payload.
    let listed: HashMap<&str, &crate::manifest::FileEntry> = manifest
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut buf = vec![0u8; 64 * 1024];

    for entry in entries {
        let mut e =
            entry.map_err(|e| Error::new(ErrorCode::Path, "corrupt tar entry").with_source(e))?;
        let et = e.header().entry_type();
        let raw = e.path_bytes().into_owned();
        if et.is_dir() {
            let p = path::validate(&raw, true)?;
            let under_root = path::PAYLOAD_ROOTS
                .iter()
                .any(|r| p == r.trim_end_matches('/') || p.starts_with(r));
            if !under_root || listed.contains_key(p.as_str()) || !seen.insert(p.clone()) {
                return Err(Error::new(
                    ErrorCode::Path,
                    format!("illegal directory entry {p}"),
                ));
            }
            if let Some(d) = dest {
                fs::create_dir_all(d.join(&p)).map_err(|e| {
                    Error::new(ErrorCode::Path, format!("cannot create {p}")).with_source(e)
                })?;
            }
            continue;
        }
        if !et.is_file() {
            return Err(Error::new(
                ErrorCode::Path,
                format!(
                    "entry {:?} has disallowed type",
                    String::from_utf8_lossy(&raw)
                ),
            ));
        }
        // Files outside bundle/, config/ and sbom/ are illegal paths, whether or not listed.
        let p = path::validate_payload_file(&raw)?;
        if !seen.insert(p.clone()) {
            return Err(Error::new(ErrorCode::Path, format!("duplicate entry {p}")));
        }
        let Some(fe) = listed.get(p.as_str()) else {
            return Err(Error::new(
                ErrorCode::ExtraFile,
                format!("{p} is not listed in the manifest"),
            ));
        };
        let hsize = e
            .header()
            .size()
            .map_err(|e| Error::schema("bad tar header").with_source(e))?;
        if hsize != fe.size {
            return Err(Error::new(
                ErrorCode::Hash,
                format!("{p}: size {hsize} != {}", fe.size),
            ));
        }

        let mut out = match dest {
            Some(d) => Some(create_file(d, &p, fe.exec)?),
            None => None,
        };
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        loop {
            let n = e
                .read(&mut buf)
                .map_err(|e| Error::io(format!("reading {p}"), e))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > fe.size {
                return Err(Error::new(
                    ErrorCode::Hash,
                    format!("{p}: longer than listed"),
                ));
            }
            hasher.update(&buf[..n]);
            if let Some(f) = out.as_mut() {
                f.write_all(&buf[..n])
                    .map_err(|e| Error::io(format!("writing {p}"), e))?;
            }
        }
        let digest = hex(&hasher.finalize());
        if total != fe.size || digest != fe.sha256 {
            return Err(Error::new(
                ErrorCode::Hash,
                format!("{p}: sha256 or size mismatch"),
            ));
        }
        if let Some(f) = out {
            f.sync_all()
                .map_err(|e| Error::io(format!("fsync {p}"), e))?;
        }
    }

    if let Some(missing) = manifest.files.iter().find(|f| !seen.contains(&f.path)) {
        return Err(Error::new(
            ErrorCode::ExtraFile,
            format!("{} is listed but missing from the archive", missing.path),
        ));
    }

    Ok(VerifiedPackage {
        manifest,
        manifest_bytes,
        sig_bytes,
        key_id,
    })
}

fn create_file(dest: &Path, p: &str, exec: bool) -> Result<fs::File> {
    let full = dest.join(p);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::new(ErrorCode::Path, format!("cannot create parent of {p}")).with_source(e)
        })?;
    }
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(if exec { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = exec;
    // `create_new` refuses to follow or overwrite anything already at the path. `dest` was
    // created empty by us and we never create symlinks, so no component can redirect the write.
    o.open(&full)
        .map_err(|e| Error::new(ErrorCode::Path, format!("cannot create {p}")).with_source(e))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// sha256 of a reader, as lowercase hex, plus its length.
pub fn sha256_reader<R: Read>(mut r: R) -> io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n_total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        n_total += n as u64;
        h.update(&buf[..n]);
    }
    Ok((hex(&h.finalize()), n_total))
}
