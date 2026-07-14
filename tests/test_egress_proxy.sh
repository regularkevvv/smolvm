#!/usr/bin/env bash
# End-to-end gate for launch-only, hostname-preserving SOCKS5 egress.

set -euo pipefail

source "$(dirname "$0")/common.sh"
init_smolvm

if [[ -z "${SMOLVM_AGENT_ROOTFS:-}" || ! -x "$SMOLVM_AGENT_ROOTFS/usr/local/bin/smolvm-agent" ]]; then
    echo "SMOLVM_AGENT_ROOTFS must point at a source-matched guest rootfs" >&2
    exit 1
fi

# Keep HOME short: libkrun's vsock bridge uses AF_UNIX paths, whose macOS
# sockaddr limit is easy to exceed under the long default /var/folders tmpdir.
TEST_DIR=$(mktemp -d /private/tmp/smolvm-egress.XXXXXX)
HOST_HOME="$HOME"
GOLDEN="egress-proxy-golden-$$"
CLONE="egress-proxy-clone-$$"
PROXY1_PORT=$((43000 + ($$ % 1000)))
PROXY2_PORT=$((44000 + ($$ % 1000)))
PROXY1_PID=""
PROXY2_PID=""
export HOME="$TEST_DIR/home"
mkdir -p "$HOME/.smolvm"
for template in storage-template.ext4 overlay-template.ext4; do
    if [[ -f "$HOST_HOME/.smolvm/$template" ]]; then
        cp "$HOST_HOME/.smolvm/$template" "$HOME/.smolvm/$template"
    fi
done
export SMOLVM_DATA_DIR="$TEST_DIR/data"
export SMOLVM_CONFIG="$TEST_DIR/config.toml"

cleanup() {
    local status=$?
    [[ -z "$PROXY1_PID" ]] || kill "$PROXY1_PID" >/dev/null 2>&1 || true
    [[ -z "$PROXY2_PID" ]] || kill "$PROXY2_PID" >/dev/null 2>&1 || true
    if [[ "${KEEP_EGRESS_TEST_DIR:-0}" == "1" && $status -ne 0 ]]; then
        echo "preserving failed egress test state at $TEST_DIR" >&2
    else
        "$SMOLVM" machine delete --name "$CLONE" -f >/dev/null 2>&1 || true
        "$SMOLVM" machine delete --name "$GOLDEN" -f >/dev/null 2>&1 || true
        rm -rf "$TEST_DIR"
    fi
}
trap cleanup EXIT

start_proxy() {
    local port="$1" password="$2" log="$3"
    SOCKS5_USERNAME=phase1 SOCKS5_PASSWORD="$password" \
        python3 "$SCRIPT_DIR/support/socks5_forwarder.py" --port "$port" >"$log" 2>&1 &
    local pid=$!
    for _ in $(seq 1 50); do
        if grep -q '^READY ' "$log" 2>/dev/null; then
            printf '%s' "$pid"
            return 0
        fi
        sleep 0.1
    done
    cat "$log" >&2
    return 1
}

PROXY1_PID=$(start_proxy "$PROXY1_PORT" golden-pass "$TEST_DIR/proxy1.log")

"$SMOLVM" machine create \
    --name "$GOLDEN" \
    --image alpine:latest \
    --net \
    --net-backend virtio-net
"$SMOLVM" machine start \
    --name "$GOLDEN" \
    --forkable \
    --egress-proxy "socks5://phase1:golden-pass@127.0.0.1:$PROXY1_PORT"
grep -q '^CONNECT ' "$TEST_DIR/proxy1.log"

# A clone must use the endpoint supplied at fork time, not the golden's old one.
PROXY2_PID=$(start_proxy "$PROXY2_PORT" clone-pass "$TEST_DIR/proxy2.log")
"$SMOLVM" machine fork \
    --golden "$GOLDEN" \
    --name "$CLONE" \
    --egress-proxy "socks5://phase1:clone-pass@127.0.0.1:$PROXY2_PORT"

"$SMOLVM" machine exec --name "$CLONE" -- sh -c '
    test -d /sys/class/net/eth0 &&
    test ! -d /sys/class/net/tun0 &&
    wget -qO- https://example.com | grep -qi "Example Domain"
'

grep -q '^CONNECT example.com:443$' "$TEST_DIR/proxy2.log"
if rg -a -l 'golden-pass|clone-pass' "$TEST_DIR"; then
    echo "proxy credentials leaked into persistent SmolVM state" >&2
    exit 1
fi

echo "egress-proxy-fork-https-ok"
