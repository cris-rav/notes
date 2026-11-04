#!/bin/sh
# Restore an nftables snapshot as one atomic batch.
umask 077

snapshot=${1:-}
if [ "$#" -ne 1 ] || [ -z "$snapshot" ]; then
        printf 'Usage: %s <phoenix nftables snapshot>\n' "$0" >&2
        exit 2
fi

case "$snapshot" in
        "${HOME:-.}"/phoenix_nftables_*.ruleset) ;;
        *)
                printf 'Refusing snapshot outside the Phoenix home-directory namespace.\n' >&2
                exit 1
                ;;
esac
if [ ! -f "$snapshot" ] || [ -L "$snapshot" ]; then
        printf 'Snapshot is missing or is not a regular file: %s\n' "$snapshot" >&2
        exit 1
fi
if [ ! -s "$snapshot" ]; then
        printf 'Refusing to restore an empty nftables snapshot.\n' >&2
        exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
        printf 'nft is unavailable; rollback was not attempted.\n' >&2
        exit 1
fi

transaction="${HOME:-.}/.phoenix-rollback-$$.nft"
trap 'rm -f "$transaction"' EXIT HUP INT TERM
if ! {
        printf 'flush ruleset\n'
        cat "$snapshot"
} >"$transaction"; then
        printf 'Could not prepare nftables rollback transaction.\n' >&2
        exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
        nft -f "$transaction"
        restore_status=$?
elif command -v sudo >/dev/null 2>&1; then
        sudo -n nft -f "$transaction"
        restore_status=$?
else
        printf 'Root access is required for nftables rollback.\n' >&2
        exit 1
fi

if [ "$restore_status" -eq 0 ]; then
        printf 'Restored nftables from full Phoenix snapshot: %s\n' "$snapshot"
else
        printf 'nftables rejected rollback transaction (status %s).\n' "$restore_status" >&2
        exit "$restore_status"
fi
