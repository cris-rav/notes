# Phoenix
Phoenix is currently a Linux firewall audit deployed through Meow, with explicit
rollback, rollback-scheduling, and inbound allow-list operations. The audit
reports iptables, nftables, UFW, listening sockets, established connections,
and SSH-port evidence. Listening ports are candidates for an operator-reviewed
policy, not an automatically accepted allow-list.
The human-readable nftables section is limited to 40 lines; when
`nft list ruleset` succeeds, Phoenix separately saves its complete output as a
mode-600 file in the remote user's home directory and prints the path. Rollback
must read this full file, not reconstruct state from the truncated display. An
unreadable ruleset does not produce a snapshot.
Each audit also writes a sourceable, mode-600 state file under the remote
user's `phoenix_state_host/` directory, named with a sanitized host label and
timestamp. It contains only `live_ssh_port`, `backend_ok`, and
`nft_snapshot_path`; paths are shell-quoted so later dispatchers can source the
file safely. The containing directory is mode 700. Listener output remains in
the human-readable audit only and is not copied into this state file.

## Safety gates and remaining work

1. Retain the audit as a preflight. Read the remote `SSH_CONNECTION` server port
   and compare it with effective sshd ports and TCP listeners. Unknown or
   conflicting evidence must block any operation that could interrupt access.
2. The inbound allow-list apply path is implemented with reviewed-plan
   confirmation, live SSH-port inclusion, established-session/loopback/ICMP
   allowances, a default-drop input chain, and an independent rollback timer.
   The timer can only be canceled after the operator verifies a new SSH
   connection. Validation so far uses mocked tests, not a live firewall.
3. Implement outbound blocking and temporary unlock as distinct, bounded
   operations. Schedule restoration before blocking, restore even when the
   requested command fails or the Meow session disconnects, and document any
   allowed exceptions.
4. Keep recovery from a host whose SSH port was already changed Phoenix-local
   for now: try only a documented small set of candidate ports, not a scan.
   General custom-port support belongs in a coordinated Meow/Elephant inventory
   change.
5. Keep every mutation gated on `BACKEND_OK=yes`, which requires nftables to
   have substantive rules loaded and IPv4/IPv6 iptables to be absent or empty
   and UFW absent or inactive. Missing nftables, unreadable backend state,
   active iptables, active UFW, or ambiguous ownership means `BACKEND_OK=no`
   and no mutation.
   SSH recovery targets port 22. Missing privileges, scheduler failure, or
   failed verification must also fail closed and report the reason.

Outbound blocking/unlock and the bounded SSH-port recovery operation remain
unimplemented. Do not treat a successful audit or Meow command exit as proof
that a firewall change was safely applied.

## Dispatcher operations

`phoenix_dispatch.sh` accepts `preflight`, `plan`, `apply-allowlist`,
`schedule-rollback`, `cancel-rollback`, `rollback`, `port-fix`, `outbound-block`, and
`outbound-unlock`.
`preflight` runs the audit. `plan <tcp-port>...` validates
the latest private state, requires `BACKEND_OK=yes` and a known live SSH port,
then writes a private, review-only proposal that always includes the current SSH
port. It is not executable nft syntax and changes no rules.
`apply-allowlist <seconds> --confirm <reviewed-plan-file>` requires the
operator-reviewed plan produced by `plan`. It reruns preflight, checks the plan
matches this host and the current live SSH port, validates the nft transaction,
arms and verifies the full-state rollback timer, then atomically adds an
`inet phoenix` input chain. The chain allows loopback, established/related
traffic, ICMP/ICMPv6, the live SSH port, and requested TCP service ports; its
default policy drops other inbound traffic. Outbound policy is unchanged.
Rollback remains armed after apply. From a separate, newly established SSH
connection, verify access and only then run
`cancel-rollback <unit>` using the unit printed by apply. If the connection
cannot be independently verified, leave rollback armed. Cancellation refuses
when the timer is inactive or its service is already running.

`schedule-rollback <seconds>` accepts 30–3600 seconds,
uses non-interactive root access to create a **system-level** transient
systemd timer, and verifies that the timer is active before reporting success.
The timer runs `nft -f` on a private transaction containing `flush ruleset`
and the complete saved snapshot. It does not use a user manager or a background
shell, so it is independent of the Meow SSH session. Scheduling is available
as a safety primitive and is wired into allow-list application. Do not cancel
the timer until a separate SSH connection has been verified.
`rollback` submits the same form of nftables transaction immediately and must
be used only for the matching preflight.
The Phoenix launcher entry deploys the audit, dispatcher, rollback, timer, and
cancellation helpers to Linux hosts, then runs the dispatcher preflight;
Windows hosts are skipped because no PowerShell implementation is provided.
For example, the launcher's ad-hoc command option can run
`sh ~/phoenix_dispatch.sh plan 80 443` on hosts after preflight. Review the
proposal, then explicitly run
`sh ~/phoenix_dispatch.sh apply-allowlist 120 --confirm <plan-file>`.

From `blue/Tools/zoo/`, run the local audit and dispatcher checks with:

```sh
bash modules/phoenix/test_fw_audit.sh
bash modules/phoenix/test_dispatch.sh
```