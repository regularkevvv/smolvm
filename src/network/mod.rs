//! Network configuration and backend selection.

/// Backend selection and serialization helpers.
pub mod backend;
/// Launch-time backend planning and request validation rules.
pub mod launch;
pub mod policy;

pub use backend::NetworkBackend;
pub use launch::{
    plan_launch_network, plan_launch_network_for_guest_profile, validate_requested_network_backend,
    validate_requested_network_backend_for_guest_profile, EffectiveNetworkBackend,
    LaunchNetworkPlan,
};
pub use policy::get_dns_server;
