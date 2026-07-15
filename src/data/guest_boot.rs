//! Persistent custom guest-kernel configuration.
//!
//! User-supplied boot artifacts are copied into a machine's data directory at
//! creation time. Persisted paths are always relative to that directory; the
//! manager resolves them to absolute paths and verifies their checksums before
//! every boot.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Directory below a machine data directory that owns staged boot artifacts.
pub const GUEST_BOOT_DIR: &str = "guest-boot";
/// Stable staged kernel path, relative to the machine data directory.
pub const STAGED_KERNEL_PATH: &str = "guest-boot/kernel";
/// Stable staged initramfs path, relative to the machine data directory.
pub const STAGED_INITRAMFS_PATH: &str = "guest-boot/initramfs";

/// Kernel image format understood by libkrun's `krun_set_kernel` API.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum KernelFormat {
    /// Uncompressed architecture-native image.
    Raw,
    /// ELF executable image.
    Elf,
    /// Gzip-compressed PE image.
    PeGz,
    /// Gzip-compressed Linux Image.
    ImageGz,
    /// Bzip2-compressed Linux Image.
    ImageBz2,
    /// Zstandard-compressed Linux Image.
    ImageZstd,
}

impl KernelFormat {
    /// Numeric format value used by libkrun.
    pub const fn to_krun_u32(self) -> u32 {
        match self {
            Self::Raw => 0,
            Self::Elf => 1,
            Self::PeGz => 2,
            Self::ImageBz2 => 3,
            Self::ImageGz => 4,
            Self::ImageZstd => 5,
        }
    }

    /// Stable CLI/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Elf => "elf",
            Self::PeGz => "pe-gz",
            Self::ImageGz => "image-gz",
            Self::ImageBz2 => "image-bz2",
            Self::ImageZstd => "image-zstd",
        }
    }
}

impl std::fmt::Display for KernelFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Guest compatibility profile associated with a custom kernel.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum, utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum GuestProfile {
    /// Ordinary Linux-compatible kernel behavior.
    #[default]
    Linux,
    /// Asterinas custom-kernel boot contract.
    Asterinas,
}

impl GuestProfile {
    /// Stable CLI/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Asterinas => "asterinas",
        }
    }

    /// Validate resource constraints imposed by the guest implementation.
    ///
    /// Asterinas currently reports one processor on AArch64 and does not boot
    /// secondary vCPUs. Leaving extra libkrun vCPU threads parked before their
    /// PSCI `CPU_ON` handshake makes a fork checkpoint impossible to quiesce,
    /// so reject that configuration instead of creating a machine that only
    /// fails when it is promoted to a golden.
    pub fn validate_vcpu_count(self, cpus: u8) -> crate::Result<()> {
        if self == Self::Asterinas && cpus != 1 {
            return Err(crate::Error::config(
                "--cpus",
                format!(
                    "the Asterinas AArch64 guest profile currently supports exactly 1 vCPU, got {cpus}; use --cpus 1"
                ),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Display for GuestProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A staged boot artifact and its expected SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GuestBootArtifact {
    /// Relative path in a persisted machine record; absolute path at launch.
    #[schema(value_type = String)]
    pub path: PathBuf,
    /// Lowercase hexadecimal SHA-256 digest.
    pub sha256: String,
}

/// Custom guest-kernel configuration stored with a machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GuestBootConfig {
    /// Staged kernel image.
    pub kernel: GuestBootArtifact,
    /// Kernel image format.
    pub kernel_format: KernelFormat,
    /// Optional staged initramfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initramfs: Option<GuestBootArtifact>,
    /// Optional kernel command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_cmdline: Option<String>,
    /// Guest compatibility profile.
    #[serde(default)]
    pub guest_profile: GuestProfile,
}

impl GuestBootConfig {
    /// Resolve persisted relative paths under `data_dir` and verify every
    /// artifact before returning an absolute launch configuration.
    pub fn resolve_and_verify(&self, data_dir: &Path) -> crate::Result<Self> {
        require_staged_path("kernel", &self.kernel.path, STAGED_KERNEL_PATH)?;
        if let Some(initramfs) = &self.initramfs {
            require_staged_path("initramfs", &initramfs.path, STAGED_INITRAMFS_PATH)?;
        }
        let mut resolved = self.clone();
        resolved.kernel.path = resolve_staged_path(data_dir, &self.kernel.path)?;
        if let Some(initramfs) = resolved.initramfs.as_mut() {
            initramfs.path = resolve_staged_path(data_dir, &initramfs.path)?;
        }
        resolved.verify_absolute()?;
        Ok(resolved)
    }

    /// Verify an already-resolved launch configuration.
    pub fn verify_absolute(&self) -> crate::Result<()> {
        verify_artifact("kernel", &self.kernel, true)?;
        if let Some(initramfs) = &self.initramfs {
            verify_artifact("initramfs", initramfs, true)?;
        }
        Ok(())
    }

    /// Apply profile-required command-line defaults without overriding
    /// compatible user options. Asterinas must execute the init blob carried
    /// by its initramfs and use libkrun's explicit virtiofs-root contract.
    pub fn effective_kernel_cmdline(&self) -> crate::Result<Option<String>> {
        if self.guest_profile != GuestProfile::Asterinas {
            return Ok(self.kernel_cmdline.clone());
        }

        let mut tokens: Vec<String> = self
            .kernel_cmdline
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(ToOwned::to_owned)
            .collect();
        require_asterinas_option(&mut tokens, "init=", "init=/init.krun")?;
        require_asterinas_option(&mut tokens, "rootfstype=", "rootfstype=virtiofs")?;
        require_asterinas_option(
            &mut tokens,
            "KRUN_VIRTIOFS_ROOT_DEVICE=",
            "KRUN_VIRTIOFS_ROOT_DEVICE=/dev/root",
        )?;
        require_asterinas_option(
            &mut tokens,
            "KRUN_ALLOW_PRIVATE_ROOT=",
            "KRUN_ALLOW_PRIVATE_ROOT=1",
        )?;
        if !tokens.iter().any(|token| token.starts_with("console=")) {
            tokens.push("console=hvc0".to_string());
        }
        if !tokens.iter().any(|token| token == "earlycon") {
            tokens.push("earlycon".to_string());
        }
        // The Asterinas development kernel defaults to syscall-level debug
        // logging when no level is supplied. Besides producing unbounded host
        // logs, that can make a normal three-second agent health probe time
        // out. Match Asterinas's own Makefile default while preserving an
        // explicit user-selected level.
        if !tokens.iter().any(|token| token.starts_with("loglevel=")) {
            tokens.push("loglevel=error".to_string());
        }
        if !tokens.iter().any(|token| token == "rw" || token == "ro") {
            tokens.push("rw".to_string());
        }
        Ok(Some(tokens.join(" ")))
    }
}

fn require_staged_path(label: &str, path: &Path, expected: &str) -> crate::Result<()> {
    if path != Path::new(expected) {
        return Err(crate::Error::config(
            "custom boot artifact",
            format!(
                "persisted {label} path must be {expected}, found {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn require_asterinas_option(
    tokens: &mut Vec<String>,
    prefix: &str,
    required: &str,
) -> crate::Result<()> {
    let mut found = false;
    for token in tokens.iter().filter(|token| token.starts_with(prefix)) {
        if token != required {
            return Err(crate::Error::config(
                "--kernel-cmdline",
                format!("guest profile 'asterinas' requires {required}, but found {token}"),
            ));
        }
        found = true;
    }
    if !found {
        tokens.push(required.to_string());
    }
    Ok(())
}

/// User-facing source paths before staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBootSource {
    /// Source kernel path.
    pub kernel: PathBuf,
    /// Kernel image format.
    pub kernel_format: KernelFormat,
    /// Optional source initramfs path.
    pub initramfs: Option<PathBuf>,
    /// Optional kernel command line.
    pub kernel_cmdline: Option<String>,
    /// Guest compatibility profile.
    pub guest_profile: GuestProfile,
}

impl GuestBootSource {
    /// Validate CLI/API option relationships and construct a source config.
    pub fn from_options(
        kernel: Option<PathBuf>,
        kernel_format: Option<KernelFormat>,
        initramfs: Option<PathBuf>,
        kernel_cmdline: Option<String>,
        guest_profile: GuestProfile,
    ) -> crate::Result<Option<Self>> {
        let Some(kernel) = kernel else {
            if kernel_format.is_some() || initramfs.is_some() || kernel_cmdline.is_some() {
                return Err(crate::Error::config(
                    "custom kernel",
                    "--kernel-format, --initramfs, and --kernel-cmdline require --kernel",
                ));
            }
            if guest_profile != GuestProfile::Linux {
                return Err(crate::Error::config(
                    "--guest-profile",
                    "guest profile 'asterinas' requires --kernel",
                ));
            }
            return Ok(None);
        };
        let kernel_format = kernel_format.ok_or_else(|| {
            crate::Error::config("--kernel-format", "--kernel requires --kernel-format")
        })?;
        if kernel_cmdline
            .as_ref()
            .is_some_and(|cmdline| cmdline.contains('\0'))
        {
            return Err(crate::Error::config(
                "--kernel-cmdline",
                "kernel command line cannot contain a NUL byte",
            ));
        }
        Ok(Some(Self {
            kernel,
            kernel_format,
            initramfs,
            kernel_cmdline,
            guest_profile,
        }))
    }
}

/// Compute the SHA-256 digest of a file.
pub fn sha256_file(path: &Path) -> crate::Result<String> {
    let mut file = File::open(path).map_err(|e| {
        crate::Error::config(
            "custom boot artifact",
            format!("cannot open {}: {e}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            crate::Error::config(
                "custom boot artifact",
                format!("cannot read {}: {e}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn resolve_staged_path(data_dir: &Path, path: &Path) -> crate::Result<PathBuf> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(crate::Error::config(
            "custom boot artifact",
            format!(
                "persisted artifact path must stay relative to the machine data directory: {}",
                path.display()
            ),
        ));
    }
    Ok(data_dir.join(path))
}

fn verify_artifact(
    label: &str,
    artifact: &GuestBootArtifact,
    require_absolute: bool,
) -> crate::Result<()> {
    if require_absolute && !artifact.path.is_absolute() {
        return Err(crate::Error::config(
            "custom boot artifact",
            format!(
                "resolved {label} path is not absolute: {}",
                artifact.path.display()
            ),
        ));
    }
    let metadata = std::fs::metadata(&artifact.path).map_err(|e| {
        crate::Error::config(
            "custom boot artifact",
            format!(
                "{label} artifact is missing at {}: {e}",
                artifact.path.display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(crate::Error::config(
            "custom boot artifact",
            format!(
                "{label} artifact is not a regular file: {}",
                artifact.path.display()
            ),
        ));
    }
    if metadata.len() == 0 {
        return Err(crate::Error::config(
            "custom boot artifact",
            format!("{label} artifact is empty: {}", artifact.path.display()),
        ));
    }
    let actual = sha256_file(&artifact.path)?;
    if actual != artifact.sha256 {
        return Err(crate::Error::config(
            "custom boot artifact",
            format!(
                "checksum mismatch for {label} at {}: expected {}, got {}",
                artifact.path.display(),
                artifact.sha256,
                actual
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_formats_match_libkrun_constants() {
        assert_eq!(KernelFormat::Raw.to_krun_u32(), 0);
        assert_eq!(KernelFormat::Elf.to_krun_u32(), 1);
        assert_eq!(KernelFormat::PeGz.to_krun_u32(), 2);
        assert_eq!(KernelFormat::ImageBz2.to_krun_u32(), 3);
        assert_eq!(KernelFormat::ImageGz.to_krun_u32(), 4);
        assert_eq!(KernelFormat::ImageZstd.to_krun_u32(), 5);
    }

    #[test]
    fn asterinas_profile_requires_one_vcpu() {
        GuestProfile::Asterinas.validate_vcpu_count(1).unwrap();
        let error = GuestProfile::Asterinas.validate_vcpu_count(2).unwrap_err();
        assert!(error.to_string().contains("exactly 1 vCPU"));
        assert!(error.to_string().contains("--cpus 1"));

        GuestProfile::Linux.validate_vcpu_count(2).unwrap();
    }

    #[test]
    fn asterinas_cmdline_preserves_user_values_and_requires_init_krun() {
        let config = GuestBootConfig {
            kernel: GuestBootArtifact {
                path: PathBuf::from("guest-boot/kernel"),
                sha256: "00".repeat(32),
            },
            kernel_format: KernelFormat::Raw,
            initramfs: None,
            kernel_cmdline: Some("loglevel=4".into()),
            guest_profile: GuestProfile::Asterinas,
        };
        let cmdline = config.effective_kernel_cmdline().unwrap().unwrap();
        assert!(cmdline.contains("loglevel=4"));
        assert!(cmdline.contains("init=/init.krun"));
        assert!(cmdline.contains("console=hvc0"));
        assert!(cmdline.contains("KRUN_VIRTIOFS_ROOT_DEVICE=/dev/root"));

        let mut defaults = config.clone();
        defaults.kernel_cmdline = None;
        assert!(defaults
            .effective_kernel_cmdline()
            .unwrap()
            .unwrap()
            .contains("loglevel=error"));

        for conflicting in [
            "init=/bin/sh",
            "rootfstype=ext4",
            "KRUN_VIRTIOFS_ROOT_DEVICE=/evil",
            "KRUN_ALLOW_PRIVATE_ROOT=0",
        ] {
            let mut invalid = config.clone();
            invalid.kernel_cmdline = Some(conflicting.into());
            let error = invalid.effective_kernel_cmdline().unwrap_err();
            assert!(error.to_string().contains(conflicting));
        }
    }

    #[test]
    fn source_options_require_a_kernel_and_format() {
        assert!(GuestBootSource::from_options(
            None,
            Some(KernelFormat::Raw),
            None,
            None,
            GuestProfile::Linux,
        )
        .is_err());
        assert!(GuestBootSource::from_options(
            Some(PathBuf::from("kernel")),
            None,
            None,
            None,
            GuestProfile::Linux,
        )
        .is_err());
        assert!(
            GuestBootSource::from_options(None, None, None, None, GuestProfile::Asterinas,)
                .is_err()
        );
    }

    #[test]
    fn resolve_reports_missing_and_checksum_mismatched_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let mut config = GuestBootConfig {
            kernel: GuestBootArtifact {
                path: PathBuf::from(STAGED_KERNEL_PATH),
                sha256: "00".repeat(32),
            },
            kernel_format: KernelFormat::Raw,
            initramfs: None,
            kernel_cmdline: None,
            guest_profile: GuestProfile::Linux,
        };

        let missing = config.resolve_and_verify(root.path()).unwrap_err();
        assert!(missing.to_string().contains("kernel artifact is missing"));

        let kernel = root.path().join(STAGED_KERNEL_PATH);
        std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
        std::fs::write(&kernel, b"kernel-v1").unwrap();
        let mismatch = config.resolve_and_verify(root.path()).unwrap_err();
        assert!(mismatch
            .to_string()
            .contains("checksum mismatch for kernel"));

        config.kernel.sha256 = sha256_file(&kernel).unwrap();
        assert_eq!(
            config.resolve_and_verify(root.path()).unwrap().kernel.path,
            kernel
        );
    }

    #[test]
    fn resolve_rejects_absolute_and_parent_paths() {
        let root = tempfile::tempdir().unwrap();
        assert!(resolve_staged_path(root.path(), Path::new("/tmp/kernel")).is_err());
        assert!(resolve_staged_path(root.path(), Path::new("../kernel")).is_err());
        assert_eq!(
            resolve_staged_path(root.path(), Path::new(STAGED_KERNEL_PATH)).unwrap(),
            root.path().join(STAGED_KERNEL_PATH)
        );
    }

    #[test]
    fn resolve_requires_machine_owned_staged_names() {
        let root = tempfile::tempdir().unwrap();
        let config = GuestBootConfig {
            kernel: GuestBootArtifact {
                path: PathBuf::from("storage.raw"),
                sha256: "00".repeat(32),
            },
            kernel_format: KernelFormat::Raw,
            initramfs: None,
            kernel_cmdline: None,
            guest_profile: GuestProfile::Linux,
        };
        let error = config.resolve_and_verify(root.path()).unwrap_err();
        assert!(error
            .to_string()
            .contains("persisted kernel path must be guest-boot/kernel"));
    }
}
