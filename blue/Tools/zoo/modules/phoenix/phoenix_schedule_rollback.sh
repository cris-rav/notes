#!/bin/sh
# Arm a system-level transient timer to restore a saved nftables snapshot.
umask 077

if [ "$#" -ne 2 ]; then
        printf 'Usage: %s <snapshot> <delay-seconds>\n' "$0" >&2
        exit 2
fi

snapshot=$1
delay=$2
case "$delay" in
        ''|*[!0-9]*|??????*)
                printf 'Rollback delay must be an integer from 30 to 3600 seconds.\n' >&2
                exit 2
                ;;
esac
if [ "$delay" -lt 30 ] || [ "$delay" -gt 3600 ]; then
        printf 'Rollback delay must be an integer from 30 to 3600 seconds.\n' >&2
        exit 2
fi

case "$snapshot" in
        "${HOME:-.}"/phoenix_nftables_*.ruleset) ;;
        *)
                printf 'Snapshot is outside the Phoenix home-directory namespace.\n' >&2
                exit 1
                ;;
esac
if [ ! -f "$snapshot" ] || [ -L "$snapshot" ] || [ ! -s "$snapshot" ]; then
        printf 'Snapshot is missing, unsafe, or empty: %s\n' "$snapshot" >&2
        exit 1
fi

nft_bin=$(command -v nft 2>/dev/null) || {
        printf 'nft is unavailable; rollback was not scheduled.\n' >&2
        exit 1
}
systemd_run=$(command -v systemd-run 2>/dev/null) || {
        printf 'systemd-run is unavailable; rollback was not scheduled.\n' >&2
        exit 1
}
systemctl_bin=$(command -v systemctl 2>/dev/null) || {
        printf 'systemctl is unavailable; rollback timer cannot be verified.\n' >&2
        exit 1
}

run_root() {
        if [ "$(id -u)" -eq 0 ]; then
                "$@"
        elif command -v sudo >/dev/null 2>&1; then
                sudo -n "$@"
        else
                printf 'Root access is required to schedule firewall rollback.\n' >&2
                return 1
        fi
}

state_dir="${HOME:-.}/phoenix_state_host"
if [ ! -d "$state_dir" ] || [ -L "$state_dir" ]; then
        printf 'Private Phoenix state directory is unavailable.\n' >&2
        exit 1
fi

host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'unknown')
host=$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '_')
[ -n "$host" ] || host=unknown
stamp=$(date -u +%Y%m%dT%H%M%SZ)
unit="phoenix-rollback-${host}-${stamp}-$$"
transaction=$(mktemp "$state_dir/${unit}.nft.XXXXXX") || {
        printf 'Could not create rollback transaction in the private state directory.\n' >&2
        exit 1
}
if ! {
        printf 'flush ruleset\n'
        cat "$snapshot"
} >"$transaction"; then
        rm -f "$transaction"
        printf 'Could not prepare full nftables rollback transaction.\n' >&2
        exit 1
fi
chmod 600 "$transaction" || {
        rm -f "$transaction"
        printf 'Could not restrict rollback transaction permissions.\n' >&2
        exit 1
}

if ! run_root "$systemd_run" --quiet "--unit=$unit" \
        "--on-active=${delay}s" --timer-property=AccuracySec=1s \
        "$nft_bin" -f "$transaction"; then
        printf "Could not submit independent system rollback timer. Transaction retained: %s\n" \
                "$transaction" >&2
        exit 1
fi

if ! run_root "$systemctl_bin" is-active --quiet "$unit.timer"; then
        printf "Rollback job was submitted but its timer is not confirmed active. Transaction retained: %s\n" \
                "$transaction" >&2
        exit 1
fi

printf 'Rollback timer active: %s.timer\n' "$unit"
printf 'Rollback delay: %s seconds\n' "$delay"
printf 'Rollback transaction: %s\n' "$transaction"
