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
MISSING="egress-proxy-missing-$$"
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
        "$SMOLVM" machine delete --name "$MISSING" -f >/dev/null 2>&1 || true
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

expect_guest_https_failure_bounded() {
    local machine="$1" url="$2" failure="$3" pid done=0
    "$SMOLVM" machine exec --name "$machine" -- sh -c \
        'wget -T 3 -qO- "$1" >/dev/null' sh "$url" &
    pid=$!
    for _ in $(seq 1 100); do
        if ! kill -0 "$pid" 2>/dev/null; then
            done=1
            break
        fi
        sleep 0.1
    done
    if [[ $done -ne 1 ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        echo "$failure did not fail within the 10s host deadline" >&2
        return 1
    fi
    if wait "$pid"; then
        echo "$failure unexpectedly bypassed the configured egress proxy" >&2
        return 1
    fi
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

# A proxy that is absent from launch must also fail closed and promptly. This
# is distinct from terminating a previously healthy endpoint below.
MISSING_PORT=$(python3 -c \
    'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
"$SMOLVM" machine fork \
    --golden "$GOLDEN" \
    --name "$MISSING" \
    --egress-proxy "socks5://phase1:missing-pass@127.0.0.1:$MISSING_PORT"
expect_guest_https_failure_bounded \
    "$MISSING" https://www.iana.org "missing launch proxy"

if rg -a -l 'golden-pass|clone-pass|missing-pass' "$TEST_DIR"; then
    echo "proxy credentials leaked into persistent SmolVM state" >&2
    exit 1
fi

# Killing the launch-only proxy must fail a fresh guest connection promptly.
# The host deadline is intentional: BusyBox wget delegates TLS to ssl_client,
# which does not reliably honor wget's own -T timeout if the guest TCP socket
# never receives a reset.
kill "$PROXY2_PID"
wait "$PROXY2_PID" 2>/dev/null || true
PROXY2_PID=""
expect_guest_https_failure_bounded \
    "$CLONE" https://www.iana.org "connection after egress proxy exit"

echo "egress-proxy-fork-https-ok"
