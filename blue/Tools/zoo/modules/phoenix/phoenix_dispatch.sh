#!/bin/sh
# Phoenix remote operation dispatcher. Mutating operations are intentionally
# disabled until their rollback and independent verification flows are ready.
umask 077

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd) || exit 1
STATE_DIR="${HOME:-.}/phoenix_state_host"

usage() {
        printf 'Usage: %s {preflight|plan <tcp-port>...|schedule-rollback <seconds>|apply-allowlist <seconds> --confirm <tcp-port>...|cancel-rollback <unit>|rollback|port-fix|outbound-block|outbound-unlock}\n' "$0" >&2
}

valid_port() {
        case "$1" in
                ''|*[!0-9]*|??????*) return 1 ;;
        esac
        [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

load_latest_state() {
        if [ ! -d "$STATE_DIR" ]; then
                printf "No Phoenix preflight state directory: %s\n" "$STATE_DIR" >&2
                return 1
        fi

        if [ "$#" -gt 0 ]; then
                state_file=$1
                case "$state_file" in
                        "$STATE_DIR"/*.env) ;;
                        *)
                                printf "Phoenix state file is outside the state directory.\n" >&2
                                return 1
                                ;;
                esac
        else
                state_file=$(ls -1t "$STATE_DIR"/*.env 2>/dev/null | sed -n '1p')
        fi
        if [ -z "$state_file" ] || [ ! -f "$state_file" ] || [ -L "$state_file" ]; then
                printf "No regular Phoenix preflight state file found in %s\n" \
                        "$STATE_DIR" >&2
                return 1
        fi

        expected_uid=$(id -u) || return 1
        dir_uid=$(stat -c '%u' "$STATE_DIR" 2>/dev/null) || return 1
        dir_mode=$(stat -c '%a' "$STATE_DIR" 2>/dev/null) || return 1
        file_uid=$(stat -c '%u' "$state_file" 2>/dev/null) || return 1
        file_mode=$(stat -c '%a' "$state_file" 2>/dev/null) || return 1
        if [ "$dir_uid" != "$expected_uid" ] || [ "$dir_mode" != 700 ] ||
                [ "$file_uid" != "$expected_uid" ] || [ "$file_mode" != 600 ]; then
                printf "Phoenix state directory/file owner or permissions are unsafe.\n" >&2
                return 1
        fi

        # State is generated atomically by fw_audit.sh in a private directory.
        # shellcheck disable=SC1090
        . "$state_file"
        case "$live_ssh_port" in
                '') ;;
                *) if ! valid_port "$live_ssh_port"; then
                                printf "Invalid live_ssh_port in state file.\n" >&2
                                return 1
                   fi ;;
        esac
        case "$backend_ok" in yes|no) ;; *)
                printf "Invalid backend_ok in state file.\n" >&2
                return 1 ;;
        esac
        if [ -n "$nft_snapshot_path" ]; then
                case "$nft_snapshot_path" in
                        "${HOME:-.}"/phoenix_nftables_*.ruleset) ;;
                        *)
                                printf "nftables snapshot path is outside the Phoenix home directory.\n" >&2
                                return 1
                                ;;
                esac
                state_host=$(basename "$state_file" |
                                sed -E 's/_[0-9]{8}_[0-9]{6}_[0-9]+\.env$//')
                snapshot_host=$(basename "$nft_snapshot_path" |
                                sed -E 's/^phoenix_nftables_//; s/_[0-9]{8}_[0-9]{6}_[0-9]+\.ruleset$//')
                if [ -z "$state_host" ] || [ "$snapshot_host" != "$state_host" ]; then
                                printf "nftables snapshot host does not match the preflight state host.\n" >&2
                                return 1
                fi
                if [ ! -f "$nft_snapshot_path" ] || [ -L "$nft_snapshot_path" ]; then
                        printf "nftables snapshot is missing or unsafe: %s\n" \
                                "$nft_snapshot_path" >&2
                        return 1
                fi
                snapshot_uid=$(stat -c '%u' "$nft_snapshot_path" 2>/dev/null) || return 1
                snapshot_mode=$(stat -c '%a' "$nft_snapshot_path" 2>/dev/null) || return 1
                if [ "$snapshot_uid" != "$expected_uid" ] || [ "$snapshot_mode" != 600 ]; then
                        printf "nftables snapshot owner or permissions are unsafe.\n" >&2
                        return 1
                fi
        fi
}

plan_allowlist() {
        if [ "$backend_ok" != yes ]; then
                printf "Cannot plan an allow-list: preflight did not approve nftables.\n" >&2
                return 1
        fi
        if [ -z "$live_ssh_port" ] || ! valid_port "$live_ssh_port"; then
                printf "Cannot plan an allow-list: live SSH port is unknown.\n" >&2
                return 1
        fi
        if [ -z "$nft_snapshot_path" ] || [ ! -f "$nft_snapshot_path" ]; then
                printf "Cannot plan an allow-list: full nftables snapshot is unavailable.\n" >&2
                return 1
        fi
        if [ "$#" -eq 0 ]; then
                printf "Specify one or more additional TCP service ports to review.\n" >&2
                return 2
        fi

        service_ports=
        while [ "$#" -gt 0 ]; do
                if ! valid_port "$1"; then
                        printf "Invalid TCP port: %s\n" "$1" >&2
                        return 2
                fi
                case " $service_ports " in
                        *" $1 "*) ;;
                        *) service_ports="${service_ports}${service_ports:+ }$1" ;;
                esac
                shift
        done

        plan_file="$STATE_DIR/allowlist_$(date +%Y%m%d_%H%M%S)_$$.plan"
        plan_tmp="${plan_file}.tmp"
        if {
                printf 'Phoenix inbound allow-list proposal (NOT APPLIED)\n'
                printf 'Preflight state: %s\n' "$state_file"
                printf 'Live SSH TCP port (always included): %s\n' "$live_ssh_port"
                printf 'Operator-requested TCP ports: %s\n' "$service_ports"
                printf 'Backend preflight: %s\n' "$backend_ok"
                printf 'Rollback snapshot: %s\n' "$nft_snapshot_path"
                printf '\nReview constraints:\n'
                printf '%s\n' \
                        '- This file is a proposal only; it is not executable nft syntax.' \
                        '- Existing established-session replies and loopback must remain allowed.' \
                        '- Schedule and verify independent rollback before any future apply.' \
                        '- Verify a new SSH connection before canceling rollback.'
        } >"$plan_tmp" && mv -f "$plan_tmp" "$plan_file"; then
                printf "Allow-list proposal saved: %s\n" "$plan_file"
                cat "$plan_file"
        else
                rm -f "$plan_tmp"
                printf "Could not write allow-list proposal.\n" >&2
                return 1
        fi
}

run_root() {
        if [ "$(id -u)" -eq 0 ]; then
                "$@"
        elif command -v sudo >/dev/null 2>&1; then
                sudo -n "$@"
        else
                printf "Root access is required for firewall changes.\n" >&2
                return 1
        fi
}

require_root() {
        root_uid=$(run_root id -u) || {
                printf "Root privileges are required to apply firewall changes; non-interactive sudo failed.\n" >&2
                return 1
        }
        if [ "$root_uid" != 0 ]; then
                printf "Firewall changes require root privileges.\n" >&2
                return 1
        fi
}

apply_allowlist() {
        delay=$1
        shift
        if [ "$#" -ne 2 ] || [ "$1" != --confirm ]; then
                printf "Usage: apply-allowlist <seconds> --confirm <reviewed-plan-file>\n" >&2
                return 2
        fi
        proposal_file=$2

        case "$delay" in
                ''|*[!0-9]*|??????*)
                        printf "Rollback delay must be an integer from 30 to 3600 seconds.\n" >&2
                        return 2
                        ;;
        esac
        if [ "$delay" -lt 30 ] || [ "$delay" -gt 3600 ]; then
                printf "Rollback delay must be an integer from 30 to 3600 seconds.\n" >&2
                return 2
        fi

        case "$proposal_file" in
                "$STATE_DIR"/allowlist_*.plan) ;;
                *)
                        printf "Confirmation must reference a Phoenix allow-list plan in %s.\n" \
                                "$STATE_DIR" >&2
                        return 1
                        ;;
        esac
        if [ ! -f "$proposal_file" ] || [ -L "$proposal_file" ] ||
                [ "$(stat -c '%u' "$proposal_file" 2>/dev/null)" != "$(id -u)" ] ||
                [ "$(stat -c '%a' "$proposal_file" 2>/dev/null)" != 600 ]; then
                printf "Reviewed plan is missing or has unsafe ownership/permissions.\n" >&2
                return 1
        fi

        fresh_preflight_output=$(sh "$HERE/fw_audit.sh") || {
                printf "Fresh preflight failed; allow-list was not applied.\n" >&2
                return 1
        }
        fresh_state_file=$(printf '%s\n' "$fresh_preflight_output" |
                sed -n 's/^Sourceable preflight state: //p')
        if [ -z "$fresh_state_file" ]; then
                printf "Fresh preflight did not report its state file; allow-list was not applied.\n" >&2
                return 1
        fi
        load_latest_state "$fresh_state_file" || return 1
        if [ "$backend_ok" != yes ] || [ -z "$live_ssh_port" ] ||
                ! valid_port "$live_ssh_port" || [ -z "$nft_snapshot_path" ]; then
                printf "Fresh preflight does not approve backend and live SSH port; refusing apply.\n" >&2
                return 1
        fi
        proposal_state=$(sed -n 's/^Preflight state: //p' "$proposal_file")
        proposal_ssh_port=$(sed -n 's/^Live SSH TCP port (always included): //p' "$proposal_file")
        proposal_backend=$(sed -n 's/^Backend preflight: //p' "$proposal_file")
        proposal_ports=$(sed -n 's/^Operator-requested TCP ports: //p' "$proposal_file")
        proposal_snapshot=$(sed -n 's/^Rollback snapshot: //p' "$proposal_file")
        case "$proposal_state" in
                "$STATE_DIR"/*.env) ;;
                *)
                        printf "Reviewed plan contains an invalid preflight state path.\n" >&2
                        return 1
                        ;;
        esac
        if [ ! -f "$proposal_state" ] || [ -L "$proposal_state" ]; then
                printf "Reviewed plan preflight state is missing or unsafe.\n" >&2
                return 1
        fi
        proposal_host=$(basename "$proposal_state" |
                sed -E 's/_[0-9]{8}_[0-9]{6}_[0-9]+\.env$//')
        current_host=$(basename "$state_file" |
                sed -E 's/_[0-9]{8}_[0-9]{6}_[0-9]+\.env$//')
        proposal_snapshot_host=$(basename "$proposal_snapshot" |
                sed -E 's/^phoenix_nftables_//; s/_[0-9]{8}_[0-9]{6}_[0-9]+\.ruleset$//')
        if [ -z "$proposal_state" ] || [ "$proposal_host" != "$current_host" ] ||
                [ "$proposal_snapshot_host" != "$current_host" ] ||
                [ "$proposal_ssh_port" != "$live_ssh_port" ] ||
                [ "$proposal_backend" != yes ] || [ -z "$proposal_snapshot" ] ||
                [ -z "$proposal_ports" ]; then
                printf "Reviewed plan does not match the fresh host, SSH port, or approved backend.\n" >&2
                return 1
        fi
        case "$proposal_snapshot" in
                "${HOME:-.}"/phoenix_nftables_*.ruleset) ;;
                *)
                        printf "Reviewed plan contains an invalid snapshot path.\n" >&2
                        return 1
                        ;;
        esac
        if [ ! -f "$proposal_snapshot" ] || [ -L "$proposal_snapshot" ]; then
                printf "Reviewed plan snapshot is missing or unsafe.\n" >&2
                return 1
        fi
        service_ports=
        for port in $proposal_ports; do
                if ! valid_port "$port"; then
                        printf "Reviewed plan contains invalid TCP port: %s\n" "$port" >&2
                        return 1
                fi
                case " $service_ports " in
                        *" $port "*) ;;
                        *) service_ports="${service_ports}${service_ports:+ }$port" ;;
                esac
        done
        if [ -n "${SSH_CONNECTION:-}" ]; then
                current_ssh_port=$(printf '%s\n' "$SSH_CONNECTION" |
                        awk '{ if (NF == 4) print $4 }')
                if [ "$current_ssh_port" != "$live_ssh_port" ]; then
                        printf "Current SSH connection does not match the preflight port.\n" >&2
                        return 1
                fi
        else
                printf "Current SSH connection is unavailable; refusing apply.\n" >&2
                return 1
        fi
        require_root || return 1
        if ! command -v nft >/dev/null 2>&1; then
                printf "nft is unavailable; allow-list was not applied.\n" >&2
                return 1
        fi
        if run_root nft list table inet phoenix >/dev/null 2>&1; then
                printf "The inet phoenix table already exists; refusing to overwrite it.\n" >&2
                return 1
        fi

        apply_file=$(mktemp "$STATE_DIR/allowlist_$(date +%Y%m%d_%H%M%S)_$$.nft.XXXXXX") || {
                printf "Could not create private nftables transaction.\n" >&2
                return 1
        }
        if ! {
                printf 'add table inet phoenix\n'
                printf 'add chain inet phoenix input { type filter hook input priority 10; policy drop; }\n'
                printf 'add rule inet phoenix input iifname "lo" accept\n'
                printf 'add rule inet phoenix input ct state established,related accept\n'
                printf 'add rule inet phoenix input ip protocol icmp accept\n'
                printf 'add rule inet phoenix input meta l4proto ipv6-icmp accept\n'
                printf 'add rule inet phoenix input tcp dport %s accept\n' "$live_ssh_port"
                for port in $service_ports; do
                        [ "$port" = "$live_ssh_port" ] && continue
                        printf 'add rule inet phoenix input tcp dport %s accept\n' "$port"
                done
        } >"$apply_file"; then
                rm -f "$apply_file"
                printf "Could not generate nftables transaction.\n" >&2
                return 1
        fi
        chmod 600 "$apply_file" || {
                rm -f "$apply_file"
                printf "Could not restrict nftables transaction permissions.\n" >&2
                return 1
        }
        if ! run_root nft -c -f "$apply_file"; then
                rm -f "$apply_file"
                printf "nft rejected the allow-list transaction during validation.\n" >&2
                return 1
        fi

        if ! schedule_output=$(sh "$HERE/phoenix_schedule_rollback.sh" \
                "$nft_snapshot_path" "$delay"); then
                rm -f "$apply_file"
                printf "Rollback scheduling failed; allow-list was not applied.\n" >&2
                return 1
        fi
        rollback_unit=$(printf '%s\n' "$schedule_output" |
                sed -n 's/^Rollback timer active: \(.*\)\.timer$/\1/p')
        if [ -z "$rollback_unit" ]; then
                printf "Rollback schedule was not verifiable; allow-list was not applied.\n" >&2
                return 1
        fi
        if ! run_root nft -f "$apply_file"; then
                rm -f "$apply_file"
                printf "nft failed to apply the policy. Rollback remains armed: %s.timer\n" \
                        "$rollback_unit" >&2
                return 1
        fi
        rm -f "$apply_file"
        displayed_ports=$live_ssh_port
        for port in $service_ports; do
                case " $displayed_ports " in
                        *" $port "*) ;;
                        *) displayed_ports="$displayed_ports $port" ;;
                esac
        done
        printf "Inbound allow-list applied; outbound policy is unchanged.\n"
        printf "Allowed TCP ports: %s\n" "$displayed_ports"
        printf "Rollback remains armed: %s.timer\n" "$rollback_unit"
        printf "Open a new SSH connection to verify access, then cancel rollback with: cancel-rollback %s\n" \
                "$rollback_unit"
}

operation=${1:-}
case "$operation" in
        preflight)
                exec sh "$HERE/fw_audit.sh"
                ;;
        plan)
                load_latest_state || exit 1
                shift
                plan_allowlist "$@"
                ;;
        rollback)
                load_latest_state || exit 1
                if [ "$backend_ok" != yes ] || [ -z "$nft_snapshot_path" ]; then
                        printf "Rollback requires an approved backend and a saved nftables snapshot.\n" >&2
                        exit 1
                fi
                exec sh "$HERE/phoenix_restore.sh" "$nft_snapshot_path"
                ;;
        schedule-rollback)
                load_latest_state || exit 1
                if [ "$backend_ok" != yes ] || [ -z "$live_ssh_port" ] ||
                        [ -z "$nft_snapshot_path" ]; then
                        printf "Scheduling requires approved backend, verified live SSH port, and saved snapshot.\n" >&2
                        exit 1
                fi
                [ "$#" -eq 2 ] || { usage; exit 2; }
                exec sh "$HERE/phoenix_schedule_rollback.sh" \
                        "$nft_snapshot_path" "$2"
                ;;
        apply-allowlist)
                shift
                [ "$#" -ge 1 ] || { usage; exit 2; }
                apply_allowlist "$@"
                ;;
        cancel-rollback)
                [ "$#" -eq 2 ] || { usage; exit 2; }
                exec sh "$HERE/phoenix_cancel_rollback.sh" "$2"
                ;;
        port-fix|outbound-block|outbound-unlock)
                printf "Operation '%s' is not implemented; no changes were made.\n" \
                        "$operation" >&2
                exit 3
                ;;
        *)
                usage
                exit 2
                ;;
esac
