#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MOCK_ROOT="$(mktemp -d)"
MOCK_HOME="$MOCK_ROOT/home"
MOCK_BIN="$MOCK_ROOT/bin"
mkdir -p "$MOCK_HOME" "$MOCK_BIN"
chmod 700 "$MOCK_HOME"
trap 'rm -rf "$MOCK_ROOT"' EXIT

cat >"$MOCK_BIN/sshd" <<'EOF'
#!/bin/sh
printf 'port %s\n' "${MOCK_SSHD_PORT:-2222}"
EOF

cat >"$MOCK_BIN/ss" <<'EOF'
#!/bin/sh
port=${MOCK_LISTENER_PORT:-2222}
case "$*" in
        *'state established'*) exit 0 ;;
        *'-lntu'*) printf 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n' ;;
        *'-H -lntp'*) printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n' "$port" ;;
        *) exit 0 ;;
esac
EOF

cat >"$MOCK_BIN/nft" <<'EOF'
#!/bin/sh
if [ "$1" = list ] && [ "$2" = ruleset ]; then
        printf '%s\n' \
                'table inet filter {' \
                ' chain input {' \
                '  type filter hook input priority filter; policy accept;' \
                '  tcp dport 2222 accept' \
                ' }' \
                '}'
elif [ "$1" = -f ]; then
        [ "${MOCK_NFT_APPLY_FAIL:-0}" = 0 ] || exit 1
        printf 'apply\n' >>"$MOCK_NFT_CALLS"
        if [ -n "${MOCK_NFT_CAPTURE:-}" ]; then
                cp "$2" "$MOCK_NFT_CAPTURE"
        fi
elif [ "$1" = -c ] && [ "$2" = -f ]; then
        [ "${MOCK_NFT_CHECK_FAIL:-0}" = 0 ] || exit 1
        printf 'check\n' >>"$MOCK_NFT_CALLS"
        cp "$3" "$MOCK_NFT_CHECK_CAPTURE"
elif [ "$1" = list ] && [ "$2" = table ] && [ "$3" = inet ] && [ "$4" = phoenix ]; then
        [ "${MOCK_PHOENIX_TABLE_EXISTS:-0}" = 1 ]
else
        exit 2
fi
EOF

cat >"$MOCK_BIN/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' '-P INPUT ACCEPT' '-P FORWARD ACCEPT' '-P OUTPUT ACCEPT'
EOF

cat >"$MOCK_BIN/iptables-save" <<'EOF'
#!/bin/sh
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' \
        ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
EOF

cat >"$MOCK_BIN/ip6tables" <<'EOF'
#!/bin/sh
printf '%s\n' '-P INPUT ACCEPT' '-P FORWARD ACCEPT' '-P OUTPUT ACCEPT'
EOF

cat >"$MOCK_BIN/ip6tables-save" <<'EOF'
#!/bin/sh
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' \
        ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
EOF

cat >"$MOCK_BIN/ufw" <<'EOF'
#!/bin/sh
printf 'Status: inactive\n'
EOF

cat >"$MOCK_BIN/sudo" <<'EOF'
#!/bin/sh
[ "${MOCK_SUDO_DENY:-0}" = 0 ] || {
        printf 'sudo: a password is required\n' >&2
        exit 1
}
[ "$1" = -n ] && shift
if [ "$1" = id ] && [ "$2" = -u ]; then
        printf '0\n'
        exit 0
fi
exec "$@"
EOF

cat >"$MOCK_BIN/id" <<'EOF'
#!/bin/sh
if [ "$1" = -u ] && [ -n "${MOCK_ID_NONROOT_AFTER:-}" ]; then
        count=0
        [ ! -f "$MOCK_ID_CALLS" ] || read -r count <"$MOCK_ID_CALLS"
        count=$((count + 1))
        printf '%s\n' "$count" >"$MOCK_ID_CALLS"
        if [ "$count" -gt "$MOCK_ID_NONROOT_AFTER" ]; then
                printf '1000\n'
                exit 0
        fi
fi
exec /usr/bin/id "$@"
EOF

cat >"$MOCK_BIN/systemd-run" <<'EOF'
#!/bin/sh
[ "${MOCK_SYSTEMD_RUN_FAIL:-0}" = 0 ] || exit 1
printf 'schedule\n' >>"$MOCK_NFT_CALLS"
printf '%s\n' "$@" >>"$MOCK_SYSTEMD_RUN_CAPTURE"
for arg do
        case "$arg" in
                --unit=*) unit=${arg#--unit=} ;;
        esac
done
[ -n "${unit:-}" ] || exit 2
touch "$MOCK_TIMER_STATE/$unit.timer"
EOF

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/bin/sh
if [ "$1" = is-active ] && [ "$2" = --quiet ]; then
        [ "${MOCK_TIMER_UNVERIFIED:-0}" = 0 ] || exit 1
        [ -f "$MOCK_TIMER_STATE/$3" ]
elif [ "$1" = stop ]; then
        rm -f "$MOCK_TIMER_STATE/$2"
else
        exit 2
fi
EOF

chmod +x "$MOCK_BIN"/*
PATH="$MOCK_BIN:/usr/bin:/bin"
HOME="$MOCK_HOME"
MOCK_NFT_CALLS="$MOCK_ROOT/nft-calls"
MOCK_NFT_CHECK_CAPTURE="$MOCK_ROOT/nft-check-transaction.nft"
MOCK_SYSTEMD_RUN_CAPTURE="$MOCK_ROOT/systemd-run-args"
MOCK_TIMER_STATE="$MOCK_ROOT/timers"
mkdir -p "$MOCK_TIMER_STATE"
export PATH HOME MOCK_NFT_CALLS MOCK_NFT_CHECK_CAPTURE \
        MOCK_SYSTEMD_RUN_CAPTURE MOCK_TIMER_STATE
touch "$MOCK_NFT_CALLS"
touch "$MOCK_SYSTEMD_RUN_CAPTURE"

host=$(printf '%s' "$(hostname -s)" | tr -c 'A-Za-z0-9._-' '_')
STATE_DIR="$HOME/phoenix_state_host"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
fixture_number=0

write_state() {
        local port="$1" backend="$2" snapshot_host="$3"
        fixture_number=$((fixture_number + 1))
        local stamp pid snapshot state
        stamp=$(date +%Y%m%d_%H%M%S)
        pid=$((10000 + fixture_number))
        snapshot="$HOME/phoenix_nftables_${snapshot_host}_${stamp}_${pid}.ruleset"
        state="$STATE_DIR/${host}_${stamp}_${pid}.env"
        printf 'table inet filter { }\n' >"$snapshot"
        chmod 600 "$snapshot"
        {
                printf "live_ssh_port='%s'\n" "$port"
                printf "backend_ok='%s'\n" "$backend"
                printf "nft_snapshot_path='%s'\n" "$snapshot"
        } >"$state"
        chmod 600 "$state"
}

assert_contains() {
        local output="$1" expected="$2"
        if ! grep -Fq "$expected" <<<"$output"; then
                printf "Expected output to contain: %s\n" "$expected" >&2
                return 1
        fi
}

run_rejected() {
        local expected="$1"
        shift
        local output status
        if output=$("$@" 2>&1); then
                printf 'Command unexpectedly succeeded: %s\n' "$*" >&2
                exit 1
        else
                status=$?
        fi
        [ "$status" -ne 0 ] || { printf 'Expected nonzero status.\n' >&2; exit 1; }
        assert_contains "$output" "$expected"
}

# A snapshot tagged for another host must be rejected before nft is invoked.
write_state 2222 yes foreign-host
run_rejected 'nftables snapshot host does not match the preflight state host.' \
        sh "$HERE/phoenix_dispatch.sh" rollback
[ ! -s "$MOCK_NFT_CALLS" ] ||
        { printf 'Mismatched-host rollback reached nft.\n' >&2; exit 1; }

# The planner fails closed for backend rejection and unknown SSH-port evidence.
write_state 2222 no "$host"
run_rejected 'preflight did not approve nftables' \
        sh "$HERE/phoenix_dispatch.sh" plan 80

write_state '' yes "$host"
run_rejected 'live SSH port is unknown' \
        sh "$HERE/phoenix_dispatch.sh" plan 80

# Conflicting SSH evidence in a real audit produces unusable (empty) state.
rm -f "$STATE_DIR"/*.env
MOCK_LISTENER_PORT=22 MOCK_SSHD_PORT=22 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/fw_audit.sh" >"$MOCK_ROOT/conflicting-audit.out"
run_rejected 'live SSH port is unknown' \
        sh "$HERE/phoenix_dispatch.sh" plan 80

# A valid proposal includes the live SSH port even when it was not requested.
rm -f "$STATE_DIR"/*.env
write_state 2222 yes "$host"
plan_output=$(sh "$HERE/phoenix_dispatch.sh" plan 80 443)
assert_contains "$plan_output" 'Live SSH TCP port (always included): 2222'
assert_contains "$plan_output" 'Operator-requested TCP ports: 80 443'
reviewed_plan=$(sed -n 's/^Allow-list proposal saved: //p' <<<"$plan_output")
[ -n "$reviewed_plan" ] || { printf 'Missing reviewed plan path.\n' >&2; exit 1; }

schedule_output=$(sh "$HERE/phoenix_dispatch.sh" schedule-rollback 90)
assert_contains "$schedule_output" 'Rollback timer active: phoenix-rollback-'
assert_contains "$schedule_output" 'Rollback delay: 90 seconds'
grep -Fxq -- '--on-active=90s' "$MOCK_SYSTEMD_RUN_CAPTURE" ||
        { printf 'Rollback timer did not receive the requested delay.\n' >&2; exit 1; }
grep -Fxq -- '--timer-property=AccuracySec=1s' "$MOCK_SYSTEMD_RUN_CAPTURE" ||
        { printf 'Expected a systemd timer with bounded trigger accuracy.\n' >&2; exit 1; }
grep -Fxq -- "$MOCK_BIN/nft" "$MOCK_SYSTEMD_RUN_CAPTURE" ||
        { printf 'Expected rollback service to execute nft directly.\n' >&2; exit 1; }
if grep -Fxq -- '--user' "$MOCK_SYSTEMD_RUN_CAPTURE"; then
        printf 'Rollback timer must use the system manager, not a user manager.\n' >&2
        exit 1
fi
transaction=$(sed -n '/^-f$/{n;p;}' "$MOCK_SYSTEMD_RUN_CAPTURE" | tail -n 1)
[ -n "$transaction" ] && [ -f "$transaction" ] ||
        { printf 'Scheduled rollback transaction is missing.\n' >&2; exit 1; }
grep -Fxq 'flush ruleset' "$transaction" ||
        { printf 'Scheduled transaction is missing nftables flush.\n' >&2; exit 1; }
grep -Fxq 'table inet filter { }' "$transaction" ||
        { printf 'Scheduled transaction is missing saved ruleset.\n' >&2; exit 1; }

printf '' >"$MOCK_NFT_CALLS"
: >"$MOCK_ROOT/id-calls"
MOCK_ID_CALLS="$MOCK_ROOT/id-calls"
export MOCK_ID_CALLS
if output=$(MOCK_ID_NONROOT_AFTER=2 MOCK_SUDO_DENY=1 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan" 2>&1); then
        printf 'Apply unexpectedly succeeded after non-root sudo denial.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected privilege failure.\n' >&2; exit 1; }
assert_contains "$output" 'Root privileges are required to apply firewall changes; non-interactive sudo failed.'
assert_contains "$output" 'sudo: a password is required'
[ ! -s "$MOCK_NFT_CALLS" ] ||
        { printf 'Firewall validation, scheduling, or apply ran without privileges.\n' >&2; exit 1; }

printf '' >"$MOCK_NFT_CALLS"
apply_output=$(SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan")
assert_contains "$apply_output" 'Inbound allow-list applied; outbound policy is unchanged.'
assert_contains "$apply_output" 'Allowed TCP ports: 2222 80 443'
assert_contains "$apply_output" 'Rollback remains armed: phoenix-rollback-'
assert_contains "$apply_output" 'Open a new SSH connection to verify access, then cancel rollback with:'
[ "$(cat "$MOCK_NFT_CALLS")" = "$(printf 'check\nschedule\napply')" ] ||
        { printf 'Expected nft check, rollback scheduling, then atomic policy apply.\n' >&2; exit 1; }
for expected in \
        'add table inet phoenix' \
        'add chain inet phoenix input { type filter hook input priority 10; policy drop; }' \
        'add rule inet phoenix input iifname "lo" accept' \
        'add rule inet phoenix input ct state established,related accept' \
        'add rule inet phoenix input ip protocol icmp accept' \
        'add rule inet phoenix input meta l4proto ipv6-icmp accept' \
        'add rule inet phoenix input tcp dport 2222 accept' \
        'add rule inet phoenix input tcp dport 80 accept' \
        'add rule inet phoenix input tcp dport 443 accept'; do
        grep -Fxq "$expected" "$MOCK_NFT_CHECK_CAPTURE" ||
                { printf 'Allow-list transaction missing: %s\n' "$expected" >&2; exit 1; }
done
apply_unit=$(sed -n 's/^Rollback remains armed: \(.*\)\.timer$/\1/p' <<<"$apply_output")
[ -n "$apply_unit" ] || { printf 'Apply did not expose rollback unit.\n' >&2; exit 1; }
cancel_output=$(sh "$HERE/phoenix_dispatch.sh" cancel-rollback "$apply_unit")
assert_contains "$cancel_output" "Rollback timer canceled: $apply_unit.timer"
[ ! -f "$MOCK_TIMER_STATE/$apply_unit.timer" ] ||
        { printf 'Rollback timer remained active after cancellation.\n' >&2; exit 1; }

if output=$(MOCK_LISTENER_PORT=2223 MOCK_SSHD_PORT=2223 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2223' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan" 2>&1); then
        printf 'Stale SSH-port proposal unexpectedly succeeded.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected stale proposal rejection.\n' >&2; exit 1; }
assert_contains "$output" 'Reviewed plan does not match the fresh host, SSH port, or approved backend.'

printf '' >"$MOCK_NFT_CALLS"
if output=$(MOCK_NFT_CHECK_FAIL=1 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan" 2>&1); then
        printf 'Invalid nft apply transaction unexpectedly succeeded.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected nft validation failure.\n' >&2; exit 1; }
assert_contains "$output" 'nft rejected the allow-list transaction during validation.'
[ ! -s "$MOCK_NFT_CALLS" ] ||
        { printf 'Policy apply ran despite failed nft validation.\n' >&2; exit 1; }

if output=$(MOCK_PHOENIX_TABLE_EXISTS=1 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan" 2>&1); then
        printf 'Existing Phoenix table unexpectedly allowed apply.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected duplicate table rejection.\n' >&2; exit 1; }
assert_contains "$output" 'inet phoenix table already exists'

printf '' >"$MOCK_NFT_CALLS"
if output=$(MOCK_SYSTEMD_RUN_FAIL=1 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan" 2>&1); then
        printf 'Apply unexpectedly succeeded without rollback scheduling.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected rollback scheduling failure.\n' >&2; exit 1; }
assert_contains "$output" 'Rollback scheduling failed; allow-list was not applied.'
[ "$(cat "$MOCK_NFT_CALLS")" = check ] ||
        { printf 'Policy apply ran despite rollback scheduling failure.\n' >&2; exit 1; }

printf '' >"$MOCK_NFT_CALLS"
if output=$(MOCK_NFT_APPLY_FAIL=1 \
        SSH_CONNECTION='192.0.2.10 53000 192.0.2.20 2222' \
        sh "$HERE/phoenix_dispatch.sh" apply-allowlist 90 --confirm "$reviewed_plan" 2>&1); then
        printf 'Failed nft apply unexpectedly succeeded.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected nft apply failure.\n' >&2; exit 1; }
assert_contains "$output" 'nft failed to apply the policy. Rollback remains armed:'
[ "$(cat "$MOCK_NFT_CALLS" | sed -n '2p')" = schedule ] ||
        { printf 'Rollback was not scheduled before a failed nft apply.\n' >&2; exit 1; }
failed_apply_unit=$(sed -n 's/.*Rollback remains armed: \(phoenix-rollback-[A-Za-z0-9._-]*\)\.timer$/\1/p' \
        <<<"$output")
[ -n "$failed_apply_unit" ] && [ -f "$MOCK_TIMER_STATE/$failed_apply_unit.timer" ] ||
        { printf 'Rollback timer was not left armed after failed apply.\n' >&2; exit 1; }

if output=$(MOCK_TIMER_UNVERIFIED=1 \
        sh "$HERE/phoenix_dispatch.sh" schedule-rollback 90 2>&1); then
        printf 'Unverified rollback timer unexpectedly reported success.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -ne 0 ] || { printf 'Expected timer-verification failure.\n' >&2; exit 1; }
assert_contains "$output" 'timer is not confirmed active'

if output=$(sh "$HERE/phoenix_dispatch.sh" schedule-rollback 5 2>&1); then
        printf 'Out-of-range rollback delay unexpectedly succeeded.\n' >&2
        exit 1
else
        status=$?
fi
[ "$status" -eq 2 ] || { printf 'Expected invalid delay status 2.\n' >&2; exit 1; }
assert_contains "$output" 'Rollback delay must be an integer from 30 to 3600 seconds.'

printf 'Phoenix dispatcher tests passed.\n'
