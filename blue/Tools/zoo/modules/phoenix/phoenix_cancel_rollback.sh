#!/bin/sh
# Cancel an armed rollback only after an operator verifies a fresh SSH session.

if [ "$#" -ne 1 ]; then
        printf 'Usage: %s <phoenix rollback unit>\n' "$0" >&2
        exit 2
fi

unit=$1
case "$unit" in
        phoenix-rollback-[A-Za-z0-9._-]*) ;;
        *)
                printf 'Refusing invalid Phoenix rollback unit name.\n' >&2
                exit 2
                ;;
esac
case "$unit" in
        *[!A-Za-z0-9._-]*)
                printf 'Refusing invalid Phoenix rollback unit name.\n' >&2
                exit 2
                ;;
esac

systemctl_bin=$(command -v systemctl 2>/dev/null) || {
        printf 'systemctl is unavailable; rollback timer was not canceled.\n' >&2
        exit 1
}
run_root() {
        if [ "$(id -u)" -eq 0 ]; then
                "$@"
        elif command -v sudo >/dev/null 2>&1; then
                sudo -n "$@"
        else
                printf 'Root access is required to cancel the rollback timer.\n' >&2
                return 1
        fi
}

if ! run_root "$systemctl_bin" is-active --quiet "$unit.timer"; then
        printf "Rollback timer is not active; it may already have fired: %s.timer\n" \
                "$unit" >&2
        exit 1
fi
if ! run_root "$systemctl_bin" is-active --quiet "$unit.service"; then
        service_active=no
else
        service_active=yes
fi
if [ "$service_active" = yes ]; then
        printf "Rollback service is already running; refusing to cancel it.\n" >&2
        exit 1
fi
if ! run_root "$systemctl_bin" stop "$unit.timer"; then
        printf "Could not stop rollback timer: %s.timer\n" "$unit" >&2
        exit 1
fi
if run_root "$systemctl_bin" is-active --quiet "$unit.timer"; then
        printf "Rollback timer remains active: %s.timer\n" "$unit" >&2
        exit 1
fi
printf "Rollback timer canceled: %s.timer\n" "$unit"
