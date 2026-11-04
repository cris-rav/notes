#!/bin/bash
# Phoenix: deploy the audit and dispatcher, then run a read-only preflight.
# No firewall rules are changed.
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../meow/meow.sh"
log="$HERE/phoenix_log/phoenix_$(date +%H-%M-%S).out"
printf "[phoenix] read-only firewall audit; no rules will be changed.\n"
meow_deploy "$HERE/fw_audit.sh" ':' || exit 1
meow_deploy "$HERE/phoenix_dispatch.sh" ':' || exit 1
meow_deploy "$HERE/phoenix_restore.sh" ':' || exit 1
meow_deploy "$HERE/phoenix_cancel_rollback.sh" ':' || exit 1
meow_deploy "$HERE/phoenix_schedule_rollback.sh" \
        'sh ~/phoenix_dispatch.sh preflight' "$log"
printf "\nSaved: %s\n" "$log"
