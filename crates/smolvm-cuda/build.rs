//! Emit `SMOLVM_PROTO_HASH`: a fingerprint of the wire-defining source, so a
//! shim and a server built from different source (the classic "rebuilt one
//! binary, not the other" stale-binary trap that silently corrupts results)
//! fail the connect handshake loudly instead. The hash covers only files both
//! the client (shim) and the host (server) compile, i.e. the wire contract —
//! not host-only backend code, which doesn't change the byte protocol.
//!
//! FNV-1a (not `DefaultHasher`) so the value is reproducible across toolchains
//! and platforms: a guest-built shim and a host-built server must agree.

fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = seed;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn main() {
    let files = [
        "src/proto.rs",
        "src/client.rs",
        "src/ring.rs",
        "src/generated/cublas_guest.rs",
        "src/generated/cudnn_guest.rs",
    ];
    // A manual epoch to force a bump on wire changes the file set misses.
    const PROTO_EPOCH: &[u8] = b"epoch-1";
    let mut h = fnv1a(0xcbf2_9ce4_8422_2325, PROTO_EPOCH);
    for f in files {
        println!("cargo:rerun-if-changed={f}");
        let bytes = std::fs::read(f).unwrap_or_default();
        h = fnv1a(h, &bytes);
    }
    println!("cargo:rustc-env=SMOLVM_PROTO_HASH={h:016x}");
}
