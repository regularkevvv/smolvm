//! Volume provisioning endpoints — node-side storage for the control plane.
//!
//! smolfleet's `create_volume`/`delete_volume` call these to materialize a volume
//! ON the worker (not on the control plane's own disk, which the worker can't
//! see). For the `local` backend a volume is simply a directory under the smolvm
//! data dir; the worker virtiofs-shares it into a guest at mount time. Future
//! backends (PD, NFS) attach real storage here. See smolfleet
//! docs/d3-replicated-volumes.md.

use axum::{extract::Path, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;

/// Request body for `POST /api/v1/volumes`.
#[derive(Deserialize)]
pub struct ProvisionVolumeRequest {
    /// Control-plane volume id (e.g. `vol-<hex>`); names the on-node directory.
    pub id: String,
    /// Requested size. Advisory for the `local` backend (a plain directory has no
    /// hard quota); the disk size for `pd`.
    #[serde(default)]
    pub size_gb: u64,
    /// Storage backend: `local` (default — a worker dir) or `pd` (a GCP
    /// persistent disk that survives node loss and can re-attach elsewhere).
    #[serde(default)]
    pub backend: Option<String>,
}

/// Response body for `POST /api/v1/volumes`.
#[derive(Serialize)]
pub struct ProvisionVolumeResponse {
    /// Host path the volume is mounted at on this node — becomes a workload mount
    /// `source`.
    pub node_path: String,
    /// Backend storage handle (the GCP disk name for `pd`); the control plane
    /// stores it to re-attach the disk on failover. `None` for `local`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// Request body for `POST /api/v1/volumes/attach` (failover re-home).
#[derive(Deserialize)]
pub struct AttachVolumeRequest {
    /// Control-plane volume id.
    pub id: String,
    /// Backend storage handle to re-attach (the GCP disk name).
    pub handle: String,
}

/// Base directory for node-local volumes: `<data_local_dir>/smolvm/volumes`.
fn volumes_base() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("smolvm")
        .join("volumes")
}

/// Reject ids that could escape the volumes base (path traversal / separators).
/// The control plane generates `vol-<hex>`; this is defense in depth.
fn safe_volume_id(id: &str) -> Result<(), ApiError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!("invalid volume id: {id:?}")))
    }
}

/// `POST /api/v1/volumes` — create the backing storage and return its host path.
pub async fn provision_volume(
    Json(req): Json<ProvisionVolumeRequest>,
) -> Result<Json<ProvisionVolumeResponse>, ApiError> {
    safe_volume_id(&req.id)?;
    match req.backend.as_deref().unwrap_or("local") {
        "local" => {
            let path = volumes_base().join(&req.id);
            std::fs::create_dir_all(&path).map_err(ApiError::internal)?;
            let node_path = path.to_string_lossy().to_string();
            tracing::info!(volume_id = %req.id, node_path = %node_path, size_gb = req.size_gb, "provisioned local volume");
            Ok(Json(ProvisionVolumeResponse {
                node_path,
                handle: None,
            }))
        }
        "pd" => {
            let (node_path, handle) = super::gcp_pd::provision(&req.id, req.size_gb).await?;
            Ok(Json(ProvisionVolumeResponse {
                node_path,
                handle: Some(handle),
            }))
        }
        other => Err(ApiError::BadRequest(format!(
            "unsupported volume backend: {other:?}"
        ))),
    }
}

/// `POST /api/v1/volumes/attach` — attach an existing PD (the failover re-home)
/// onto this node and mount it, returning the host path. No format (data intact).
pub async fn attach_volume(
    Json(req): Json<AttachVolumeRequest>,
) -> Result<Json<ProvisionVolumeResponse>, ApiError> {
    safe_volume_id(&req.id)?;
    let node_path = super::gcp_pd::attach(&req.handle, &req.id).await?;
    Ok(Json(ProvisionVolumeResponse {
        node_path,
        handle: Some(req.handle),
    }))
}

/// `DELETE /api/v1/volumes/{id}` — tear down the backing storage. Idempotent:
/// deleting an already-absent volume succeeds.
pub async fn deprovision_volume(Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    safe_volume_id(&id)?;
    let path = volumes_base().join(&id);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // already gone
        Err(e) => return Err(ApiError::internal(e)),
    }
    tracing::info!(volume_id = %id, "deprovisioned local volume");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_ids() {
        assert!(safe_volume_id("vol-abc123").is_ok());
        assert!(safe_volume_id("vol_1").is_ok());
        assert!(safe_volume_id("../etc").is_err());
        assert!(safe_volume_id("a/b").is_err());
        assert!(safe_volume_id("").is_err());
        assert!(safe_volume_id(&"x".repeat(200)).is_err());
    }

    #[test]
    fn volumes_base_is_under_smolvm() {
        let b = volumes_base();
        assert!(b.ends_with("smolvm/volumes"), "got {b:?}");
    }
}
