//! Device information (`engine.json`) and compatibility checks.

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorCode, Result};
use crate::manifest::{Arch, Compat, Graphics, Manifest, is_lower_hex};

/// Parsed `/etc/homing/engine.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Always 1.
    pub schema: u32,
    /// 40-hex engine commit of the engine installed on the device.
    pub engine_hash: String,
    /// Flutter version (informational).
    #[serde(default)]
    pub flutter_version: String,
    /// CPU architecture.
    pub arch: Arch,
    /// Yocto `MACHINE`.
    pub machine: String,
    /// Graphics backends the device supports.
    pub graphics: Vec<Graphics>,
    /// Base image version (semver).
    pub base_image_version: String,
}

impl DeviceInfo {
    /// Parse and validate `engine.json`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let d: DeviceInfo = serde_json::from_slice(bytes)
            .map_err(|e| Error::schema(format!("engine.json: {e}")))?;
        if d.schema != 1 {
            return Err(Error::schema(format!(
                "unknown engine.json schema {}",
                d.schema
            )));
        }
        if !is_lower_hex(&d.engine_hash, 40) {
            return Err(Error::schema(
                "engine.json: engine_hash must be 40 lowercase hex",
            ));
        }
        semver::Version::parse(&d.base_image_version)
            .map_err(|_| Error::schema("engine.json: base_image_version is not semver"))?;
        Ok(d)
    }

    /// Read and parse a file.
    pub fn read(path: &std::path::Path) -> Result<Self> {
        let b = std::fs::read(path)
            .map_err(|e| Error::io(format!("cannot read {}", path.display()), e))?;
        Self::parse(&b)
    }

    /// Check a manifest's `compat` section against this device.
    pub fn check(&self, m: &Manifest) -> Result<()> {
        self.check_compat(&m.compat)
    }

    /// Check compatibility requirements against this device: engine (`E_ENGINE`), architecture
    /// (`E_ARCH`), machine (`E_MACHINE`), graphics (`E_GRAPHICS`) and base image
    /// (`E_BASE_IMAGE`), in that order.
    pub fn check_compat(&self, c: &Compat) -> Result<()> {
        if c.engine_hash != self.engine_hash {
            return Err(Error::new(
                ErrorCode::Engine,
                format!(
                    "package engine {} != device engine {}",
                    c.engine_hash, self.engine_hash
                ),
            ));
        }
        if c.arch != self.arch {
            return Err(Error::new(
                ErrorCode::Arch,
                format!(
                    "package arch {} != device arch {}",
                    c.arch.as_str(),
                    self.arch.as_str()
                ),
            ));
        }
        if !c.machines.is_empty() && !c.machines.contains(&self.machine) {
            return Err(Error::new(
                ErrorCode::Machine,
                format!("device machine {} not in {:?}", self.machine, c.machines),
            ));
        }
        if let Some(g) = &c.graphics {
            if !g.iter().any(|x| self.graphics.contains(x)) {
                return Err(Error::new(
                    ErrorCode::Graphics,
                    "no supported graphics backend",
                ));
            }
        }
        if let Some(min) = &c.base_image_min {
            let min = semver::Version::parse(min)
                .map_err(|_| Error::schema("compat.base_image_min is not semver"))?;
            let have = semver::Version::parse(&self.base_image_version)
                .map_err(|_| Error::schema("base_image_version is not semver"))?;
            if have < min {
                return Err(Error::new(
                    ErrorCode::BaseImage,
                    format!("base image {have} older than required {min}"),
                ));
            }
        }
        Ok(())
    }
}

/// Anti-rollback check: `version_code` must be at least the floor.
pub fn check_floor(m: &Manifest, floor: u64) -> Result<()> {
    if m.version_code < floor {
        return Err(Error::new(
            ErrorCode::Rollback,
            format!("version_code {} below floor {floor}", m.version_code),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceInfo {
        DeviceInfo::parse(
            serde_json::json!({
                "schema": 1, "engine_hash": "a".repeat(40), "flutter_version": "3.x",
                "arch": "aarch64", "machine": "raspberrypi3-64", "graphics": ["drm-gles"],
                "base_image_version": "1.0.0"
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn manifest(mutate: impl FnOnce(&mut serde_json::Value)) -> Manifest {
        let mut v = crate::manifest::tests::sample();
        mutate(&mut v);
        Manifest::parse(&serde_json::to_vec(&v).unwrap()).unwrap()
    }

    #[test]
    fn compatible() {
        device().check(&manifest(|_| {})).unwrap();
        device()
            .check(&manifest(|v| {
                v["compat"]["machines"] = serde_json::json!([])
            }))
            .unwrap();
        device()
            .check(&manifest(|v| {
                v["compat"].as_object_mut().unwrap().remove("graphics");
            }))
            .unwrap();
    }

    #[test]
    fn each_mismatch_has_its_code() {
        let d = device();
        type Mutate = Box<dyn FnOnce(&mut serde_json::Value)>;
        let cases: Vec<(Mutate, ErrorCode)> = vec![
            (
                Box::new(|v| v["compat"]["engine_hash"] = "b".repeat(40).into()),
                ErrorCode::Engine,
            ),
            (
                Box::new(|v| v["compat"]["arch"] = "armv7".into()),
                ErrorCode::Arch,
            ),
            (
                Box::new(|v| v["compat"]["machines"] = serde_json::json!(["rpi4"])),
                ErrorCode::Machine,
            ),
            (
                Box::new(|v| v["compat"]["graphics"] = serde_json::json!(["wayland-gles"])),
                ErrorCode::Graphics,
            ),
            (
                Box::new(|v| v["compat"]["base_image_min"] = "1.1.0".into()),
                ErrorCode::BaseImage,
            ),
        ];
        for (mutate, code) in cases {
            assert_eq!(d.check(&manifest(mutate)).unwrap_err().code(), code);
        }
    }

    #[test]
    fn floor() {
        let m = manifest(|_| {});
        check_floor(&m, 10200).unwrap();
        assert_eq!(
            check_floor(&m, 10201).unwrap_err().code(),
            ErrorCode::Rollback
        );
    }

    #[test]
    fn bad_engine_json() {
        assert!(DeviceInfo::parse(b"{}").is_err());
        let mut v = serde_json::to_value(device()).unwrap();
        v["engine_hash"] = "xyz".into();
        assert!(DeviceInfo::parse(v.to_string().as_bytes()).is_err());
    }
}
