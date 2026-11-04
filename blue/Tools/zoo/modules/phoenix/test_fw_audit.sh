#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MOCK_BIN="$(mktemp -d)"
MOCK_HOME_ROOT="$(mktemp -d)"
MOCK_HOME="$MOCK_HOME_ROOT/remote user's home"
mkdir -p "$MOCK_HOME"
trap 'rm -rf "$MOCK_BIN" "$MOCK_HOME_ROOT"' EXIT
HOME="$MOCK_HOME"
export HOME

cat >"$MOCK_BIN/sshd" <<'EOF'
#!/bin/sh
printf 'port %s\n' "${MOCK_SSHD_PORT:-2222}"
EOF

cat >"$MOCK_BIN/ss" <<'EOF'
#!/bin/sh
printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n' \
        "${MOCK_LISTENER_PORT:-2222}"
EOF

cat >"$MOCK_BIN/nft" <<'EOF'
#!/bin/sh
if [ "$1" = list ] && [ "$2" = ruleset ]; then
        [ "${MOCK_NFT_FAIL:-0}" = 0 ] || exit 1
        [ "${MOCK_NFT_MODE:-active}" = active ] || exit 0
        i=1
        while [ "$i" -le 55 ]; do
                printf 'nft-row-%s\n' "$i"
                i=$((i + 1))
        done
elif [ "$1" = -f ] && [ -n "${MOCK_NFT_CAPTURE:-}" ]; then
        [ "${MOCK_NFT_RESTORE_FAIL:-0}" = 0 ] || exit 1
        cp "$2" "$MOCK_NFT_CAPTURE"
else
        exit 2
fi
EOF

cat >"$MOCK_BIN/sudo" <<'EOF'
#!/bin/sh
[ "$1" = -n ] && shift
exec "$@"
EOF

cat >"$MOCK_BIN/iptables" <<'EOF'
#!/bin/sh
[ "$1" = -S ] || exit 2
printf '%s\n' '-P INPUT ACCEPT' '-P FORWARD ACCEPT' '-P OUTPUT ACCEPT'
EOF

cat >"$MOCK_BIN/iptables-save" <<'EOF'
#!/bin/sh
[ "${MOCK_IPTABLES_FAIL:-0}" = 0 ] || exit 1
case "${MOCK_IPTABLES_MODE:-empty}" in
        active)
                printf '%s\n' \
                        '*filter' ':INPUT ACCEPT [0:0]' \
                        '-A INPUT -p tcp --dport 443 -j ACCEPT' 'COMMIT'
                ;;
        empty)
                printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' \
                        ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
                ;;
        *) exit 2 ;;
esac
EOF

cat >"$MOCK_BIN/ip6tables" <<'EOF'
#!/bin/sh
[ "$1" = -S ] || exit 2
printf '%s\n' '-P INPUT ACCEPT' '-P FORWARD ACCEPT' '-P OUTPUT ACCEPT'
EOF

cat >"$MOCK_BIN/ip6tables-save" <<'EOF'
#!/bin/sh
[ "${MOCK_IP6TABLES_FAIL:-0}" = 0 ] || exit 1
case "${MOCK_IP6TABLES_MODE:-empty}" in
        active)
                printf '%s\n' \
                        '*filter' ':INPUT ACCEPT [0:0]' \
                        '-A INPUT -p tcp --dport 443 -j ACCEPT' 'COMMIT'
                ;;
        empty)
                printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' \
                        ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
                ;;
        *) exit 2 ;;
esac
EOF

cat >"$MOCK_BIN/ufw" <<'EOF'
#!/bin/sh
[ "$1" = status ] || exit 2
[ "${MOCK_UFW_FAIL:-0}" = 0 ] || exit 1
printf 'Status: %s\n' "${MOCK_UFW_STATUS:-inactive}"
EOF

chmod +x "$MOCK_BIN/sshd" "$MOCK_BIN/ss" "$MOCK_BIN/nft" \
        "$MOCK_BIN/sudo" \
        "$MOCK_BIN/iptables" "$MOCK_BIN/iptables-save" \
        "$MOCK_BIN/ip6tables" "$MOCK_BIN/ip6tables-save" "$MOCK_BIN/ufw"
PATH="$MOCK_BIN:/usr/bin:/bin"
export PATH

assert_contains() {
        local output="$1" expected="$2"
        if ! grep -Fq "$expected" <<<"$output"; then
                printf "Expected audit output to contain: %s\n" "$expected" >&2
                return 1
        fi
}

output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'Server: 192.0.2.20:2222'
assert_contains "$output" 'Live SSH session uses port 2222.'
assert_contains "$output" 'A TCP listener exists on the live SSH port.'
assert_contains "$output" "The live SSH port appears in sshd's effective port list."
assert_contains "$output" 'nftables: active'
assert_contains "$output" 'iptables: empty'
assert_contains "$output" 'ip6tables: empty'
assert_contains "$output" 'ufw: inactive'
assert_contains "$output" 'BACKEND_OK=yes'
state_file=$(sed -n 's/^Sourceable preflight state: //p' <<<"$output")
[ -n "$state_file" ] || { printf 'Missing preflight state path.\n' >&2; exit 1; }
nft_snapshot=$(sed -n 's/^Full nft ruleset snapshot (rollback source): //p' <<<"$output")
[ -n "$nft_snapshot" ] || { printf 'Missing nftables snapshot path.\n' >&2; exit 1; }
[ "$(stat -c '%a' "$state_file")" = 600 ] ||
        { printf 'Expected restrictive preflight state permissions.\n' >&2; exit 1; }
[ "$(stat -c '%a' "$(dirname "$state_file")")" = 700 ] ||
        { printf 'Expected private preflight state directory.\n' >&2; exit 1; }
if grep -Ev "^(live_ssh_port|backend_ok|nft_snapshot_path)='" "$state_file"; then
        printf 'Unexpected data in preflight state file.\n' >&2
        exit 1
fi
[ "$(wc -l <"$state_file")" -eq 3 ] ||
        { printf 'Expected exactly three preflight state entries.\n' >&2; exit 1; }
(
        unset live_ssh_port backend_ok nft_snapshot_path
        . "$state_file"
        [ "$live_ssh_port" = 2222 ]
        [ "$backend_ok" = yes ]
        [ "$nft_snapshot_path" = "$nft_snapshot" ]
)
if grep -E 'LISTEN|nft-row-' "$state_file"; then
        printf 'Preflight state must not contain audit output.\n' >&2
        exit 1
fi
[ "$(wc -l <"$nft_snapshot")" -eq 55 ] ||
        { printf 'Expected full 55-line nftables snapshot.\n' >&2; exit 1; }
[ "$(stat -c '%a' "$nft_snapshot")" = 600 ] ||
        { printf 'Expected restrictive nftables snapshot permissions.\n' >&2; exit 1; }
[ "$(grep -c '^nft-row-' <<<"$output")" -eq 40 ] ||
        { printf 'Expected audit display to contain only 40 nftables lines.\n' >&2; exit 1; }
assert_contains "$output" 'nft-row-40'
if grep -Fq 'nft-row-41' <<<"$output"; then
        printf 'Audit display was not truncated to 40 nftables lines.\n' >&2
        exit 1
fi
rm -f "$nft_snapshot"

output=$(MOCK_NFT_FAIL=1 SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/fw_audit.sh")
assert_contains "$output" '(nft ruleset unreadable; no snapshot saved)'
assert_contains "$output" 'BACKEND_OK=no'
if find "$MOCK_HOME" -name '*.ruleset' -type f | grep -q .; then
        printf 'Failed nftables snapshot should not leave a file.\n' >&2
        exit 1
fi

output=$(MOCK_NFT_MODE=empty SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/fw_audit.sh")
assert_contains "$output" 'nftables: empty'
assert_contains "$output" 'BACKEND_OK=no'

output=$(MOCK_IPTABLES_MODE=active \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'iptables: active'
assert_contains "$output" 'BACKEND_OK=no'

output=$(MOCK_IP6TABLES_MODE=active \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'ip6tables: active'
assert_contains "$output" 'BACKEND_OK=no'

output=$(MOCK_UFW_STATUS=active \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'ufw: active'
assert_contains "$output" 'BACKEND_OK=no'

output=$(MOCK_IPTABLES_FAIL=1 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'iptables: unreadable'
assert_contains "$output" 'BACKEND_OK=no'

mv "$MOCK_BIN/iptables" "$MOCK_BIN/iptables.off"
mv "$MOCK_BIN/iptables-save" "$MOCK_BIN/iptables-save.off"
output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'iptables: absent'
assert_contains "$output" 'BACKEND_OK=yes'
mv "$MOCK_BIN/iptables.off" "$MOCK_BIN/iptables"
mv "$MOCK_BIN/iptables-save.off" "$MOCK_BIN/iptables-save"
mv "$MOCK_BIN/ip6tables" "$MOCK_BIN/ip6tables.off"
mv "$MOCK_BIN/ip6tables-save" "$MOCK_BIN/ip6tables-save.off"
output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'ip6tables: absent'
assert_contains "$output" 'BACKEND_OK=yes'
mv "$MOCK_BIN/ip6tables.off" "$MOCK_BIN/ip6tables"
mv "$MOCK_BIN/ip6tables-save.off" "$MOCK_BIN/ip6tables-save"

mv "$MOCK_BIN/ufw" "$MOCK_BIN/ufw.off"
output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'ufw: absent'
assert_contains "$output" 'BACKEND_OK=yes'
mv "$MOCK_BIN/ufw.off" "$MOCK_BIN/ufw"

mv "$MOCK_BIN/nft" "$MOCK_BIN/nft.off"
output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'nftables: absent'
assert_contains "$output" 'BACKEND_OK=no'
mv "$MOCK_BIN/nft.off" "$MOCK_BIN/nft"

output=$(MOCK_LISTENER_PORT=22 MOCK_SSHD_PORT=22 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'WARNING: no TCP listener was confirmed on the live SSH port.'
assert_contains "$output" "WARNING: the live SSH port is not in sshd's effective port list."

output=$(SSH_CONNECTION='bad 0 host nope trailing' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'SSH_CONNECTION is malformed; live SSH port is unknown.'
assert_contains "$output" 'Cannot cross-check: live SSH port is unknown.'

output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 70000' sh "$HERE/fw_audit.sh")
assert_contains "$output" 'SSH_CONNECTION is malformed; live SSH port is unknown.'

output=$(env -u SSH_CONNECTION sh "$HERE/fw_audit.sh")
assert_contains "$output" 'SSH_CONNECTION is unavailable; live SSH port is unknown.'

output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" preflight)
assert_contains "$output" 'BACKEND_OK=yes'
assert_contains "$output" 'Sourceable preflight state:'

rollback_capture="$MOCK_HOME_ROOT/rollback-transaction.nft"
output=$(MOCK_NFT_CAPTURE="$rollback_capture" \
        sh "$HERE/phoenix_dispatch.sh" rollback)
assert_contains "$output" 'Restored nftables from full Phoenix snapshot:'
[ "$(wc -l <"$rollback_capture")" -eq 56 ] ||
        { printf 'Rollback should include flush plus all 55 snapshot lines.\n' >&2; exit 1; }
[ "$(head -n 1 "$rollback_capture")" = 'flush ruleset' ] ||
        { printf 'Rollback transaction must flush before restoring the snapshot.\n' >&2; exit 1; }
grep -Fxq 'nft-row-55' "$rollback_capture" ||
        { printf 'Rollback transaction is missing the end of the full snapshot.\n' >&2; exit 1; }
if output=$(MOCK_NFT_CAPTURE="$MOCK_HOME_ROOT/failed-rollback.nft" \
        MOCK_NFT_RESTORE_FAIL=1 sh "$HERE/phoenix_dispatch.sh" rollback 2>&1); then
        printf 'Rejected nftables rollback unexpectedly succeeded.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected nftables rollback failure status.\n' >&2; exit 1; }
assert_contains "$output" 'nftables rejected rollback transaction'
if find "$MOCK_HOME" -maxdepth 1 -name '.phoenix-rollback-*.nft' | grep -q .; then
        printf 'Temporary rollback transaction was not cleaned up.\n' >&2
        exit 1
fi

output=$(sh "$HERE/phoenix_dispatch.sh" plan 80 443 2222)
assert_contains "$output" 'Phoenix inbound allow-list proposal (NOT APPLIED)'
assert_contains "$output" 'Live SSH TCP port (always included): 2222'
assert_contains "$output" 'Operator-requested TCP ports: 80 443 2222'
assert_contains "$output" 'Existing established-session replies and loopback must remain allowed.'
plan_file=$(sed -n 's/^Allow-list proposal saved: //p' <<<"$output")
[ -n "$plan_file" ] || { printf 'Missing allow-list proposal path.\n' >&2; exit 1; }
[ "$(stat -c '%a' "$plan_file")" = 600 ] ||
        { printf 'Expected private allow-list proposal permissions.\n' >&2; exit 1; }
if output=$(sh "$HERE/phoenix_dispatch.sh" plan '443; echo unsafe' 2>&1); then
        printf 'Invalid plan port unexpectedly succeeded.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -eq 2 ] || { printf 'Expected status 2 for invalid port.\n' >&2; exit 1; }
assert_contains "$output" 'Invalid TCP port: 443; echo unsafe'

for operation in port-fix outbound-block outbound-unlock; do
        if output=$(sh "$HERE/phoenix_dispatch.sh" "$operation" 2>&1); then
                printf "Unimplemented operation unexpectedly succeeded: %s\n" "$operation" >&2
                exit 1
        else
                status=$?
        fi
        [ "$status" -eq 3 ] ||
                { printf "Expected status 3 for %s, got %s\n" "$operation" "$status" >&2; exit 1; }
        assert_contains "$output" "Operation '$operation' is not implemented; no changes were made."
done

printf 'Phoenix audit tests passed.\n'
