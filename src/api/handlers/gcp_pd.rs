//! GCP persistent-disk backend for `pd` volumes (D3a failover).
//!
//! A `pd` volume's bytes live on a Google **persistent disk** that can detach
//! from a dead worker and re-attach to a live one — unlike a `local` dir, which
//! dies with its host. This module drives that via `gcloud` (already on the
//! worker, auto-authenticated by the instance service account) + `mount`:
//!
//! - [`provision`] — create a fresh PD, attach it to THIS instance, format, mount.
//! - [`attach`] — attach an EXISTING PD (the failover re-home) and mount, no format.
//!
//! Both return the host mount path, which becomes a workload virtiofs `source`.
//! See smolfleet docs/d3-replicated-volumes.md.

use crate::api::error::ApiError;
use tokio::process::Command;

/// Where PD volumes are mounted on the worker: `<data_local_dir>/smolvm/pd-volumes/<id>`.
/// Distinct from the `local` backend's `volumes/` (those are plain dirs, not mountpoints).
fn mount_path_for(id: &str) -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib"))
        .join("smolvm")
        .join("pd-volumes")
        .join(id)
}

/// Deterministic GCP disk name for a volume id. GCP disk names are ≤63 chars,
/// lowercase `[a-z0-9-]`, starting with a letter — `vol-<hex>` already complies,
/// and the `smolvol-` prefix namespaces our disks.
fn disk_name_for(id: &str) -> String {
    format!("smolvol-{id}")
}

/// Fetch a value from the GCE metadata server via `curl` (the lib has no HTTP
/// client; the rest of this module shells out anyway).
async fn metadata(path: &str) -> Result<String, ApiError> {
    let url = format!("http://metadata.google.internal/computeMetadata/v1/{path}");
    let out = Command::new("curl")
        .args(["-sf", "-H", "Metadata-Flavor: Google", &url])
        .output()
        .await
        .map_err(|e| ApiError::internal(format!("spawn curl (metadata {path}): {e}")))?;
    if !out.status.success() {
        return Err(ApiError::internal(format!(
            "metadata fetch {path} failed: {}",
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// This instance's GCP zone + name, from the metadata server.
async fn instance_identity() -> Result<(String, String), ApiError> {
    // zone comes back as `projects/<num>/zones/<zone>` — keep the last segment.
    let zone_raw = metadata("instance/zone").await?;
    let zone = zone_raw.rsplit('/').next().unwrap_or(&zone_raw).to_string();
    let name = metadata("instance/name").await?;
    Ok((zone, name))
}

/// Run a command, mapping a non-zero exit (or spawn failure) to a 500 with the
/// captured stderr — never echo stdout (may be large).
async fn run(bin: &str, args: &[&str]) -> Result<(), ApiError> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .await
        .map_err(|e| ApiError::internal(format!("spawn {bin}: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(ApiError::internal(format!(
            "{bin} {} failed ({}): {}",
            args.first().copied().unwrap_or(""),
            out.status,
            stderr.trim()
        )));
    }
    Ok(())
}

/// Attach `disk_name` to this instance (device-name = disk name so it lands at a
/// predictable `/dev/disk/by-id/google-<name>`), then mount it at `mount_path`,
/// formatting first only when `format` (a fresh disk). Idempotent-ish: a disk
/// already attached + mounted here returns Ok.
async fn attach_and_mount(
    zone: &str,
    instance: &str,
    disk_name: &str,
    mount_path: &std::path::Path,
    format: bool,
) -> Result<String, ApiError> {
    let device_path = format!("/dev/disk/by-id/google-{disk_name}");
    let mp = mount_path.to_string_lossy().to_string();

    // Attach only if the device isn't already present (gcloud attach-disk is not
    // idempotent — re-attaching an already-attached disk errors).
    if !std::path::Path::new(&device_path).exists() {
        run(
            "gcloud",
            &[
                "compute",
                "instances",
                "attach-disk",
                instance,
                "--disk",
                disk_name,
                "--device-name",
                disk_name,
                "--zone",
                zone,
                "--quiet",
            ],
        )
        .await?;
        // Give udev a moment to create the by-id symlink.
        for _ in 0..20 {
            if std::path::Path::new(&device_path).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    if format {
        run("mkfs.ext4", &["-F", "-q", &device_path]).await?;
    }
    run("mkdir", &["-p", &mp]).await?;
    // Mount only if not already mounted at mp.
    let mounted = Command::new("mountpoint")
        .args(["-q", &mp])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if !mounted {
        run("mount", &[&device_path, &mp]).await?;
    }
    Ok(mp)
}

/// Create a fresh PD, attach + format + mount it. Returns `(node_path, disk_name)`
/// — the control plane stores `disk_name` as the volume's failover handle.
pub async fn provision(id: &str, size_gb: u64) -> Result<(String, String), ApiError> {
    let (zone, instance) = instance_identity().await?;
    let disk_name = disk_name_for(id);
    let size = size_gb.max(10); // GCP pd-balanced minimum is 10 GiB

    run(
        "gcloud",
        &[
            "compute",
            "disks",
            "create",
            &disk_name,
            "--size",
            &format!("{size}GB"),
            "--type",
            "pd-balanced",
            "--zone",
            &zone,
            "--quiet",
        ],
    )
    .await?;

    let node_path =
        attach_and_mount(&zone, &instance, &disk_name, &mount_path_for(id), true).await?;
    tracing::info!(volume_id = %id, disk = %disk_name, node_path = %node_path, "provisioned pd volume");
    Ok((node_path, disk_name))
}

/// Attach an EXISTING disk (`handle`) and mount it (no format — data is intact).
/// The failover re-home primitive. Returns the host mount path.
pub async fn attach(handle: &str, id: &str) -> Result<String, ApiError> {
    let (zone, instance) = instance_identity().await?;
    let node_path = attach_and_mount(&zone, &instance, handle, &mount_path_for(id), false).await?;
    tracing::info!(volume_id = %id, disk = %handle, node_path = %node_path, "attached pd volume (re-home)");
    Ok(node_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_name_namespaced_and_valid() {
        let n = disk_name_for("vol-abc123");
        assert_eq!(n, "smolvol-vol-abc123");
        assert!(n.len() <= 63);
        assert!(n
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn mount_path_under_pd_volumes() {
        let p = mount_path_for("vol-x");
        assert!(p.ends_with("smolvm/pd-volumes/vol-x"), "got {p:?}");
    }
}
