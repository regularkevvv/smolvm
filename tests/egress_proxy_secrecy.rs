//! Structural regression checks for the launch-only egress-proxy contract.

use smolvm::network::EgressProxy;

#[test]
fn proxy_credentials_are_redacted_from_user_facing_formatting() {
    let proxy: EgressProxy = "socks5://secrecy-user:secrecy-pass@127.0.0.1:1080"
        .parse()
        .unwrap();
    for rendered in [format!("{proxy}"), format!("{proxy:?}")] {
        assert!(!rendered.contains("secrecy-user"));
        assert!(!rendered.contains("secrecy-pass"));
    }
}

#[test]
fn persistent_schemas_do_not_contain_an_egress_proxy_field() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "src/agent/boot_config.rs",
        "src/config.rs",
        "crates/smolvm-pack/src/format.rs",
    ] {
        let source = std::fs::read_to_string(root.join(relative)).unwrap();
        assert!(
            !source.contains("egress_proxy") && !source.contains("SMOLVM_EGRESS_PROXY"),
            "launch-only proxy leaked into persistent schema source {relative}"
        );
    }
}

#[test]
fn boot_subprocess_uses_environment_not_arguments_or_logs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manager = std::fs::read_to_string(root.join("src/agent/manager.rs")).unwrap();
    assert!(manager.contains(".envs(launch_env)"));
    assert!(manager.contains("SMOLVM_EGRESS_PROXY"));
    for line in manager
        .lines()
        .filter(|line| line.contains("SMOLVM_EGRESS_PROXY"))
    {
        assert!(!line.contains(".args("));
        assert!(!line.contains("tracing::"));
        assert!(!line.contains("println!"));
    }

    let boot = std::fs::read_to_string(root.join("src/cli/internal_boot.rs")).unwrap();
    assert!(boot.contains("remove_var(\"SMOLVM_EGRESS_PROXY\")"));
}
