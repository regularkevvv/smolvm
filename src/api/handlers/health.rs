//! Health check endpoint.

use axum::{extract::State, Json};
use std::sync::Arc;

use crate::api::state::ApiState;
use crate::api::types::{HealthResponse, MachineCountsResponse};

/// Server start time for uptime calculation.
static SERVER_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Record the server start time. Call once at startup.
pub fn mark_server_start() {
    let _ = SERVER_START.set(std::time::Instant::now());
}

/// Health check endpoint.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Server is healthy", body = HealthResponse)
    )
)]
pub async fn health(State(state): State<Arc<ApiState>>) -> Json<HealthResponse> {
    // Count from the authoritative DB (off-reactor), the same source `/machines`
    // reads. The in-memory machine map retains entries for VMs removed
    // out-of-band — an ephemeral cleanup or a CLI/other-process delete — which
    // made `/health.machines.total` report a stale count that diverged from
    // `/machines` and the DB (a monitoring/scheduling consumer then saw ghost
    // machines). Falls back to `None` if the DB read fails.
    let machines = state.list_vm_records().await.ok().map(|vms| {
        let total = vms.len();
        let running = vms.iter().filter(|(_, r)| r.is_process_alive()).count();
        MachineCountsResponse { total, running }
    });
    let uptime = SERVER_START.get().map(|t| t.elapsed().as_secs());

    Json(HealthResponse {
        status: "ok",
        version: crate::VERSION,
        machines,
        uptime_seconds: uptime,
    })
}
