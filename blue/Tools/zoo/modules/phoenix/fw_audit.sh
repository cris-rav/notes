#!/bin/sh
# Phoenix audit payload. This script is intentionally read-only.
umask 077

state_host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'unknown')
state_host=$(printf '%s' "$state_host" | tr -c 'A-Za-z0-9._-' '_')
[ -n "$state_host" ] || state_host=unknown
state_stamp=$(date +%Y%m%d_%H%M%S)
state_dir="${HOME:-.}/phoenix_state_host"
state_file="$state_dir/${state_host}_${state_stamp}_$$.env"
nft_snapshot_path=

valid_port() {
        case "$1" in
                ''|*[!0-9]*|??????*) return 1 ;;
        esac
        [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

ruleset_state() {
        rules_command=$1
        save_command=$2
        if command -v "$save_command" >/dev/null 2>&1; then
                if saved_rules=$("$save_command" 2>/dev/null); then
                        rules_state=empty
                        if printf '%s\n' "$saved_rules" | awk '
                                /^[[:space:]]*-A[[:space:]]/ { active = 1 }
                                /^[[:space:]]*-P[[:space:]]+[^[:space:]]+[[:space:]]+(DROP|REJECT)([[:space:]]|$)/ { active = 1 }
                                /^:[^[:space:]]+[[:space:]]+(DROP|REJECT)([[:space:]]|$)/ { active = 1 }
                                END { exit !active }'; then
                                rules_state=active
                        fi
                else
                        rules_state=unreadable
                fi
        elif command -v "$rules_command" >/dev/null 2>&1; then
                rules_state=unreadable
        else
                rules_state=absent
        fi
        printf '%s\n' "$rules_state"
}

shell_quote() {
        printf "'"
        printf '%s' "$1" | sed "s/'/'\\\\''/g"
        printf "'"
}

printf "===== LIVE SSH CONNECTION =====\n"
live_ssh_port=
if [ -n "${SSH_CONNECTION:-}" ]; then
        # SSH_CONNECTION is: client-ip client-port server-ip server-port.
        IFS=' ' read -r client_ip client_port server_ip live_ssh_port extra <<EOF
$SSH_CONNECTION
EOF
        if [ -n "$client_ip" ] && [ -n "$client_port" ] &&
                [ -n "$server_ip" ] && [ -z "$extra" ] &&
                valid_port "$client_port" && valid_port "$live_ssh_port"; then
                printf "Client: %s:%s\nServer: %s:%s\n" \
                        "$client_ip" "$client_port" "$server_ip" "$live_ssh_port"
        else
                printf "SSH_CONNECTION is malformed; live SSH port is unknown.\n"
                live_ssh_port=
        fi
else
        printf "SSH_CONNECTION is unavailable; live SSH port is unknown.\n"
fi

printf "\n===== SSHD EFFECTIVE PORTS =====\n"
sshd_ports=
if command -v sshd >/dev/null 2>&1; then
        sshd_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -un)
        if [ -n "$sshd_ports" ]; then
                printf "%s\n" "$sshd_ports"
        else
                printf "(could not read effective sshd ports)\n"
        fi
else
        printf "(sshd unavailable)\n"
fi

printf "\n===== LISTENING TCP PORTS =====\n"
if command -v ss >/dev/null 2>&1; then
        ss -H -lntp 2>/dev/null | awk '
                {
                        address = $4
                        sub(/^.*:/, "", address)
                        if (address ~ /^[0-9]+$/) print address, $0
                }'
else
        printf "(ss unavailable)\n"
fi

printf "\n===== SSH PORT CROSS-CHECK =====\n"
ssh_port_consistent=no
if [ -n "$live_ssh_port" ]; then
        printf "Live SSH session uses port %s.\n" "$live_ssh_port"
        listener_match=no
        if command -v ss >/dev/null 2>&1 &&
                ss -H -lntp 2>/dev/null | awk -v port="$live_ssh_port" '
                        {
                                address = $4
                                sub(/^.*:/, "", address)
                                if (address == port) found = 1
                        }
                        END { exit !found }'; then
                listener_match=yes
                printf "A TCP listener exists on the live SSH port.\n"
        else
                printf "WARNING: no TCP listener was confirmed on the live SSH port.\n"
        fi
        sshd_match=no
        if [ -n "$sshd_ports" ]; then
                if printf "%s\n" "$sshd_ports" | grep -Fxq "$live_ssh_port"; then
                        sshd_match=yes
                        printf "The live SSH port appears in sshd's effective port list.\n"
                else
                        printf "WARNING: the live SSH port is not in sshd's effective port list.\n"
                fi
        else
                printf "Cannot cross-check: effective sshd ports are unknown.\n"
        fi
        if [ "$listener_match" = yes ] && [ "$sshd_match" = yes ]; then
                ssh_port_consistent=yes
        fi
else
        printf "Cannot cross-check: live SSH port is unknown.\n"
fi

printf "\n===== IPTABLES (filter) =====\n"
iptables_state=$(ruleset_state iptables iptables-save)
if command -v iptables >/dev/null 2>&1; then
        iptables -S 2>/dev/null || printf "(iptables unreadable)\n"
else
        printf "(iptables absent)\n"
fi
ip6tables_state=$(ruleset_state ip6tables ip6tables-save)
if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -S 2>/dev/null || printf "(ip6tables unreadable)\n"
else
        printf "(ip6tables absent)\n"
fi

printf "\n===== NFTABLES =====\n"
nft_state=absent
if command -v nft >/dev/null 2>&1; then
        nft_snapshot_path="${HOME:-.}/phoenix_nftables_${state_host}_${state_stamp}_$$.ruleset"
        if nft list ruleset >"$nft_snapshot_path" 2>/dev/null; then
                printf "Full nft ruleset snapshot (rollback source): %s\n" "$nft_snapshot_path"
                head -40 "$nft_snapshot_path"
                nft_state=empty
                if awk '
                        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
                        /^[[:space:]]*table[[:space:]]/ { next }
                        /^[[:space:]]*chain[[:space:]]/ { next }
                        /^[[:space:]]*}[[:space:]]*$/ { next }
                        { active = 1 }
                        END { exit !active }' "$nft_snapshot_path"; then
                        nft_state=active
                fi
        else
                rm -f "$nft_snapshot_path"
                nft_snapshot_path=
                printf "(nft ruleset unreadable; no snapshot saved)\n"
                nft_state=unreadable
        fi
else
        printf "(nft absent)\n"
fi

printf "\n===== UFW STATUS =====\n"
ufw_state=absent
if command -v ufw >/dev/null 2>&1; then
        if ufw_status=$(ufw status verbose 2>/dev/null); then
                printf "%s\n" "$ufw_status"
                if printf '%s\n' "$ufw_status" | grep -Fxq 'Status: active'; then
                        ufw_state=active
                elif printf '%s\n' "$ufw_status" | grep -Fxq 'Status: inactive'; then
                        ufw_state=inactive
                else
                        ufw_state=unreadable
                fi
        else
                printf "(ufw status unreadable)\n"
                ufw_state=unreadable
        fi
else
        printf "(ufw absent)\n"
fi

printf "\n===== FIREWALL BACKEND PREFLIGHT =====\n"
printf "nftables: %s\niptables: %s\nip6tables: %s\nufw: %s\n" \
        "$nft_state" "$iptables_state" "$ip6tables_state" "$ufw_state"
BACKEND_OK=no
if [ "$nft_state" = active ] &&
        { [ "$iptables_state" = absent ] || [ "$iptables_state" = empty ]; } &&
        { [ "$ip6tables_state" = absent ] || [ "$ip6tables_state" = empty ]; } &&
        { [ "$ufw_state" = absent ] || [ "$ufw_state" = inactive ]; }; then
        BACKEND_OK=yes
fi
printf "BACKEND_OK=%s\n" "$BACKEND_OK"

printf "\n===== PREFLIGHT STATE FILE =====\n"
if mkdir -p "$state_dir" && chmod 700 "$state_dir"; then
        state_tmp="${state_file}.tmp"
        state_live_ssh_port=
        if [ "$ssh_port_consistent" = yes ]; then
                state_live_ssh_port=$live_ssh_port
        fi
        if {
                printf 'live_ssh_port='
                shell_quote "$state_live_ssh_port"
                printf '\nbackend_ok='
                shell_quote "$BACKEND_OK"
                printf '\nnft_snapshot_path='
                shell_quote "$nft_snapshot_path"
                printf '\n'
        } >"$state_tmp" && mv -f "$state_tmp" "$state_file"; then
                printf "Sourceable preflight state: %s\n" "$state_file"
        else
                rm -f "$state_tmp"
                printf "ERROR: could not write preflight state file.\n" >&2
                exit 1
        fi
else
        printf "ERROR: could not create private preflight state directory: %s\n" \
                "$state_dir" >&2
        exit 1
fi

printf "\n===== LISTENING PORTS (candidate allow-list; operator review required) =====\n"
if command -v ss >/dev/null 2>&1; then
        ss -lntu 2>/dev/null | awk 'NR>1 {print $1, $5}'
else
        printf "(ss unavailable)\n"
fi

printf "\n===== ESTABLISHED CONNECTIONS =====\n"
if command -v ss >/dev/null 2>&1; then
        ss -ntu state established 2>/dev/null |
                awk 'NR>1 {print $5}' | sort -u | head -20
else
        printf "(ss unavailable)\n"
fi

printf "\nAudit only: Phoenix did not change firewall or SSH configuration.\n"
