//! Staging and initramfs helpers for custom guest kernels.

use crate::agent::{find_lib_dir, KrunFunctions};
use crate::data::guest_boot::{
    sha256_file, GuestBootArtifact, GuestBootConfig, GuestBootSource, GuestProfile, GUEST_BOOT_DIR,
    STAGED_INITRAMFS_PATH, STAGED_KERNEL_PATH,
};
use crate::{Error, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CPIO_HEADER_LEN: usize = 110;
const CPIO_NEWC_MAGIC: &[u8; 6] = b"070701";
const CPIO_CRC_MAGIC: &[u8; 6] = b"070702";
const CPIO_TRAILER: &str = "TRAILER!!!";
const ASTERINAS_INITRAMFS_DIRS: [&str; 4] = ["dev", "proc", "sys", "newroot"];

/// Copy user-supplied boot artifacts into a machine data directory and return
/// the relative, checksummed configuration that can safely be persisted.
///
/// Asterinas machines always receive libkrun's current `/init.krun`. If the
/// caller supplies an initramfs, it must be a raw or gzip-compressed newc CPIO;
/// the init binary is added without discarding the caller's other entries.
pub fn stage_guest_boot(source: &GuestBootSource, data_dir: &Path) -> Result<GuestBootConfig> {
    validate_source_file("kernel", &source.kernel)?;
    if let Some(initramfs) = source.initramfs.as_deref() {
        validate_source_file("initramfs", initramfs)?;
    }

    fs::create_dir_all(data_dir).map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("create {}: {e}", data_dir.display()),
        )
    })?;

    let target_dir = data_dir.join(GUEST_BOOT_DIR);
    if target_dir.exists() {
        return Err(Error::agent(
            "stage custom boot artifacts",
            format!(
                "machine boot-artifact directory already exists: {}",
                target_dir.display()
            ),
        ));
    }
    let partial_dir = data_dir.join(format!(
        ".{GUEST_BOOT_DIR}.partial-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir(&partial_dir).map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("create {}: {e}", partial_dir.display()),
        )
    })?;

    let result = (|| {
        let staged_kernel = partial_dir.join("kernel");
        copy_new_file(&source.kernel, &staged_kernel)?;

        let staged_initramfs = if source.guest_profile == GuestProfile::Asterinas {
            let default_init = load_default_init()?;
            let bytes = build_asterinas_initramfs(source.initramfs.as_deref(), &default_init)?;
            let path = partial_dir.join("initramfs");
            write_new_file(&path, &bytes)?;
            Some(path)
        } else if let Some(initramfs) = source.initramfs.as_deref() {
            let path = partial_dir.join("initramfs");
            copy_new_file(initramfs, &path)?;
            Some(path)
        } else {
            None
        };

        let kernel_sha256 = sha256_file(&staged_kernel)?;
        let initramfs_sha256 = staged_initramfs.as_deref().map(sha256_file).transpose()?;

        let mut config = GuestBootConfig {
            kernel: GuestBootArtifact {
                path: PathBuf::from(STAGED_KERNEL_PATH),
                sha256: kernel_sha256,
            },
            kernel_format: source.kernel_format,
            initramfs: initramfs_sha256.map(|sha256| GuestBootArtifact {
                path: PathBuf::from(STAGED_INITRAMFS_PATH),
                sha256,
            }),
            kernel_cmdline: source.kernel_cmdline.clone(),
            guest_profile: source.guest_profile,
        };
        config.kernel_cmdline = config.effective_kernel_cmdline()?;

        fs::rename(&partial_dir, &target_dir).map_err(|e| {
            Error::agent(
                "stage custom boot artifacts",
                format!(
                    "commit {} to {}: {e}",
                    partial_dir.display(),
                    target_dir.display()
                ),
            )
        })?;
        config.resolve_and_verify(data_dir)?;
        Ok(config)
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&partial_dir);
        // The rename may have succeeded before final verification failed.
        let _ = fs::remove_dir_all(&target_dir);
    }
    result
}

/// Copy an existing machine's already-verified boot artifacts into a clone.
/// The bytes and persisted checksums remain identical to the golden machine.
pub fn clone_guest_boot(
    config: &GuestBootConfig,
    source_data_dir: &Path,
    target_data_dir: &Path,
) -> Result<GuestBootConfig> {
    let source = config.resolve_and_verify(source_data_dir)?;
    fs::create_dir_all(target_data_dir).map_err(|e| {
        Error::agent(
            "clone custom boot artifacts",
            format!("create {}: {e}", target_data_dir.display()),
        )
    })?;
    let target_dir = target_data_dir.join(GUEST_BOOT_DIR);
    if target_dir.exists() {
        return Err(Error::agent(
            "clone custom boot artifacts",
            format!("target already exists: {}", target_dir.display()),
        ));
    }
    let partial_dir = target_data_dir.join(format!(
        ".{GUEST_BOOT_DIR}.clone-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir(&partial_dir).map_err(|e| {
        Error::agent(
            "clone custom boot artifacts",
            format!("create {}: {e}", partial_dir.display()),
        )
    })?;

    let result = (|| {
        copy_new_file(&source.kernel.path, &partial_dir.join("kernel"))?;
        if let Some(initramfs) = source.initramfs.as_ref() {
            copy_new_file(&initramfs.path, &partial_dir.join("initramfs"))?;
        }
        fs::rename(&partial_dir, &target_dir).map_err(|e| {
            Error::agent(
                "clone custom boot artifacts",
                format!("commit {}: {e}", target_dir.display()),
            )
        })?;
        config.resolve_and_verify(target_data_dir)?;
        Ok(config.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&partial_dir);
        let _ = fs::remove_dir_all(&target_dir);
    }
    result
}

fn load_default_init() -> Result<Vec<u8>> {
    let lib_dir = find_lib_dir().ok_or_else(|| {
        Error::agent(
            "prepare asterinas initramfs",
            "libkrun is not installed; run `smolvm setup` first",
        )
    })?;
    // SAFETY: the loader validates and owns both dynamic library handles for
    // the lifetime of the returned function table.
    let krun = unsafe { KrunFunctions::load(&lib_dir) }
        .map_err(|e| Error::agent("prepare asterinas initramfs", e))?;
    krun.default_init_bytes()
        .map_err(|e| Error::agent("prepare asterinas initramfs", e))
}

fn build_asterinas_initramfs(source: Option<&Path>, init: &[u8]) -> Result<Vec<u8>> {
    let (raw, compressed) = if let Some(path) = source {
        let input = fs::read(path).map_err(|e| {
            Error::agent(
                "prepare asterinas initramfs",
                format!("read {}: {e}", path.display()),
            )
        })?;
        if input.starts_with(&[0x1f, 0x8b]) {
            let mut decoder = GzDecoder::new(input.as_slice());
            let mut raw = Vec::new();
            decoder.read_to_end(&mut raw).map_err(|e| {
                Error::agent(
                    "prepare asterinas initramfs",
                    format!("decompress {}: {e}", path.display()),
                )
            })?;
            (raw, true)
        } else {
            (input, false)
        }
    } else {
        (newc_archive(&[]), false)
    };

    let augmented = augment_newc_with_init(raw, init)?;
    if compressed {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&augmented).map_err(|e| {
            Error::agent("prepare asterinas initramfs", format!("compress CPIO: {e}"))
        })?;
        encoder
            .finish()
            .map_err(|e| Error::agent("prepare asterinas initramfs", format!("finish gzip: {e}")))
    } else {
        Ok(augmented)
    }
}

fn augment_newc_with_init(mut archive: Vec<u8>, init: &[u8]) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let mut found_init = false;
    let mut found_dirs = [false; ASTERINAS_INITRAMFS_DIRS.len()];
    loop {
        let header = archive
            .get(offset..offset + CPIO_HEADER_LEN)
            .ok_or_else(|| {
                Error::agent(
                    "prepare asterinas initramfs",
                    "initramfs is not a complete newc CPIO archive",
                )
            })?;
        if &header[..6] != CPIO_NEWC_MAGIC && &header[..6] != CPIO_CRC_MAGIC {
            return Err(Error::agent(
                "prepare asterinas initramfs",
                "asterinas initramfs must use the raw or gzip-compressed newc CPIO format",
            ));
        }
        let file_size = parse_hex_field(&header[54..62])?;
        let name_size = parse_hex_field(&header[94..102])?;
        if name_size == 0 {
            return Err(Error::agent(
                "prepare asterinas initramfs",
                "newc CPIO entry has an empty filename",
            ));
        }
        let name_start = offset + CPIO_HEADER_LEN;
        let name_end = name_start
            .checked_add(name_size)
            .ok_or_else(cpio_overflow)?;
        let name_bytes = archive
            .get(name_start..name_end)
            .ok_or_else(cpio_overflow)?;
        let name = name_bytes.strip_suffix(&[0]).ok_or_else(|| {
            Error::agent(
                "prepare asterinas initramfs",
                "CPIO filename is not NUL-terminated",
            )
        })?;
        let name = std::str::from_utf8(name).map_err(|e| {
            Error::agent(
                "prepare asterinas initramfs",
                format!("CPIO filename is not UTF-8: {e}"),
            )
        })?;
        let data_start = align4(name_end);
        let data_end = data_start
            .checked_add(file_size)
            .ok_or_else(cpio_overflow)?;
        let data = archive
            .get(data_start..data_end)
            .ok_or_else(cpio_overflow)?;

        let normalized_name = name.trim_start_matches('/');
        if name == CPIO_TRAILER {
            archive.truncate(offset);
            for (name, found) in ASTERINAS_INITRAMFS_DIRS.iter().zip(found_dirs) {
                if !found {
                    append_newc_entry(&mut archive, name, 0o040755, &[]);
                }
            }
            if !found_init {
                append_newc_entry(&mut archive, "init.krun", 0o100755, init);
            }
            append_newc_entry(&mut archive, CPIO_TRAILER, 0, &[]);
            return Ok(archive);
        }
        if normalized_name == "init.krun" {
            if data == init {
                found_init = true;
            } else {
                return Err(Error::agent(
                    "prepare asterinas initramfs",
                    "supplied initramfs contains a different /init.krun; remove it or omit --initramfs so SmolVM can inject libkrun's compatible init",
                ));
            }
        }
        if let Some(index) = ASTERINAS_INITRAMFS_DIRS
            .iter()
            .position(|candidate| *candidate == normalized_name)
        {
            found_dirs[index] = true;
        }
        offset = align4(data_end);
    }
}

fn newc_archive(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, mode, data) in entries {
        append_newc_entry(&mut archive, name, *mode, data);
    }
    append_newc_entry(&mut archive, CPIO_TRAILER, 0, &[]);
    archive
}

fn append_newc_entry(output: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
    let namesize = name.len() + 1;
    let fields = [
        1u32,
        mode,
        0,
        0,
        1,
        0,
        u32::try_from(data.len()).expect("initramfs entry exceeds newc limit"),
        0,
        0,
        0,
        0,
        u32::try_from(namesize).expect("initramfs filename exceeds newc limit"),
        0,
    ];
    output.extend_from_slice(CPIO_NEWC_MAGIC);
    for field in fields {
        write!(output, "{field:08x}").expect("write to Vec cannot fail");
    }
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    pad4(output);
    output.extend_from_slice(data);
    pad4(output);
}

fn parse_hex_field(bytes: &[u8]) -> Result<usize> {
    let value = std::str::from_utf8(bytes).map_err(|e| {
        Error::agent(
            "prepare asterinas initramfs",
            format!("invalid CPIO header: {e}"),
        )
    })?;
    usize::from_str_radix(value, 16).map_err(|e| {
        Error::agent(
            "prepare asterinas initramfs",
            format!("invalid CPIO hexadecimal field: {e}"),
        )
    })
}

fn cpio_overflow() -> Error {
    Error::agent(
        "prepare asterinas initramfs",
        "newc CPIO entry extends past the end of the initramfs",
    )
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn pad4(output: &mut Vec<u8>) {
    output.resize(align4(output.len()), 0);
}

fn validate_source_file(label: &str, path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("{label} {} is not accessible: {e}", path.display()),
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(Error::agent(
            "stage custom boot artifacts",
            format!(
                "{label} must be a non-empty regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn copy_new_file(source: &Path, target: &Path) -> Result<()> {
    let mut input = File::open(source).map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("open {}: {e}", source.display()),
        )
    })?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|e| {
            Error::agent(
                "stage custom boot artifacts",
                format!("create {}: {e}", target.display()),
            )
        })?;
    std::io::copy(&mut input, &mut output).map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("copy {} to {}: {e}", source.display(), target.display()),
        )
    })?;
    output.sync_all().map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("sync {}: {e}", target.display()),
        )
    })?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            Error::agent(
                "stage custom boot artifacts",
                format!("create {}: {e}", path.display()),
            )
        })?;
    file.write_all(bytes).map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("write {}: {e}", path.display()),
        )
    })?;
    file.sync_all().map_err(|e| {
        Error::agent(
            "stage custom boot artifacts",
            format!("sync {}: {e}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_archive_contains_init_and_mount_points() {
        let init = b"fake-static-init";
        let archive = build_asterinas_initramfs(None, init).unwrap();
        for name in ASTERINAS_INITRAMFS_DIRS.into_iter().chain(["init.krun"]) {
            assert!(contains_cpio_name(&archive, name));
        }
        assert_eq!(
            augment_newc_with_init(archive.clone(), init).unwrap(),
            archive
        );
    }

    #[test]
    fn supplied_archive_is_augmented_without_losing_entries() {
        let archive = newc_archive(&[("etc/config", 0o100644, b"hello")]);
        let augmented = augment_newc_with_init(archive, b"init").unwrap();
        assert!(augmented.windows(5).any(|window| window == b"hello"));
        for name in ASTERINAS_INITRAMFS_DIRS {
            assert!(contains_cpio_name(&augmented, name));
        }
        assert_eq!(
            augment_newc_with_init(augmented.clone(), b"init").unwrap(),
            augmented
        );
    }

    #[test]
    fn conflicting_init_is_rejected() {
        let archive = newc_archive(&[("init.krun", 0o100755, b"old")]);
        assert!(augment_newc_with_init(archive, b"new").is_err());
    }

    #[test]
    fn clone_copies_and_reverifies_boot_artifacts() {
        let source_root = tempfile::tempdir().unwrap();
        let target_root = tempfile::tempdir().unwrap();
        let source_boot = source_root.path().join(GUEST_BOOT_DIR);
        fs::create_dir(&source_boot).unwrap();
        fs::write(source_boot.join("kernel"), b"kernel-bytes").unwrap();
        fs::write(source_boot.join("initramfs"), b"initramfs-bytes").unwrap();

        let config = GuestBootConfig {
            kernel: GuestBootArtifact {
                path: PathBuf::from(STAGED_KERNEL_PATH),
                sha256: sha256_file(&source_boot.join("kernel")).unwrap(),
            },
            kernel_format: crate::data::guest_boot::KernelFormat::Raw,
            initramfs: Some(GuestBootArtifact {
                path: PathBuf::from(STAGED_INITRAMFS_PATH),
                sha256: sha256_file(&source_boot.join("initramfs")).unwrap(),
            }),
            kernel_cmdline: Some("console=hvc0".into()),
            guest_profile: GuestProfile::Linux,
        };

        let cloned = clone_guest_boot(&config, source_root.path(), target_root.path()).unwrap();
        assert_eq!(cloned, config);
        assert_eq!(
            fs::read(target_root.path().join(STAGED_KERNEL_PATH)).unwrap(),
            b"kernel-bytes"
        );
        assert_eq!(
            fs::read(target_root.path().join(STAGED_INITRAMFS_PATH)).unwrap(),
            b"initramfs-bytes"
        );
        cloned.resolve_and_verify(target_root.path()).unwrap();
    }

    fn contains_cpio_name(archive: &[u8], name: &str) -> bool {
        archive
            .windows(name.len() + 1)
            .any(|window| window[..name.len()] == *name.as_bytes() && window[name.len()] == 0)
    }
}
