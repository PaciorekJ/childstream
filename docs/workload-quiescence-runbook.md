# Proposed operator-controlled WSL and Docker pause for Stage A

**Preparation only.** No command in this document has been approved or executed on the physical host. The read-only network diagnostic cannot stop workloads. The version 5 plan/journal is implemented and offline-tested, but the connected-host evidence remains No-Go. A complete offline, quiescent snapshot and separate operator approval are still required. Keep the record below private and available offline.

## Record the original state while connected

Use the same Windows account at the physical console. Save the output in a private directory with access limited to that account, SYSTEM and Administrators. Record the source SHA, time, original child-feature value, RDP policy, `TermService`, listeners, firewall/profile fingerprint, network diagnostic, and all active adapters and routes. Record the physical cable/radio/tether state separately. Do not place raw output in Git or a CI artifact.

Before any workload pause, list `wsl --list --verbose`, `docker ps --format '{{json .}}'`, `docker compose ls --all`, `Get-VM`, `Get-VMNetworkAdapter -VMName '*'`, and the read-only HNS endpoint inventory. Identify every running container's owning Compose project or operator, stateful volumes, pending writes, and restart policy. Record whether Docker Desktop starts at sign-in and whether any scheduled task or service restarts the workloads. The current host evidence has active Ubuntu and `docker-desktop` distributions and one HNS endpoint; their exact state must be rechecked immediately before a separately approved pause.

## Pause only after exact approval

1. Save editor, shell, database and container work. Have each workload owner approve a graceful stop. If a stateful service cannot be stopped cleanly, stop the Stage A attempt.
2. Stop each reviewed Compose project with `docker compose stop` from its recorded project directory, or use `docker stop <EXACT_CONTAINER_ID>` for a reviewed standalone container. Do not use `docker compose down --volumes`, `docker rm`, `wsl --unregister`, or delete any switch, endpoint, image or volume. Verify that `docker ps` is empty and record any failed stop.
3. Quit Docker Desktop through its UI. Verify `com.docker.backend`, Docker Desktop processes, published bindings and HNS endpoints have gone away. If the application does not quit cleanly, retain No-Go; do not kill processes blindly.
4. After saving Ubuntu work, use `wsl --terminate Ubuntu`. Recheck `wsl --list --verbose`. If `docker-desktop` remains Running after Docker Desktop has quit, review its owner/state before a separately approved `wsl --terminate docker-desktop`. Do not run `wsl --shutdown` unless all distributions and their work are included in the approval.
5. Ensure the recorded Docker Desktop sign-in option and any workload restart path will not relaunch a guest at the fresh parent logon. If preventing auto-start would require changing a setting, capture its exact old value and obtain separate approval for that reversible change. A pause that cannot survive fresh logon is No-Go. Verify no other VM or guest endpoint is active.

The operator then performs the separately authorized physical disconnection, with a second local observer checking Ethernet, Wi-Fi, Bluetooth PAN, cellular/USB tether, VPN underlays and any other uplink. The read-only diagnostic must show complete sources and independent `External`, `GuestPath` and `RdpExposure` acceptance. A connected-network firewall failure remains a connected-network blocker; do not edit its rules. The v5 `plan-boundary` command binds the complete private snapshot to an exact approval hash and journal, then rechecks it before the feature write, after the API call, after the fresh console logon, throughout recovery and before reconnect assessment. See [external-boundary-stage-a.md](external-boundary-stage-a.md).

## Stop, recovery and resumption

If Docker/WSL restarts, an endpoint reappears, a physical link comes up, any bridge query is unknown, or an RDP listener or `TermService` changes unexpectedly, do not advance Stage A. Keep the machine physically offline and preserve the private journal and all before/after inventories. The approved recovery path must verify child absence, restore the exact original child-feature value and separately assess changed RDP/service/listener state before network reconnection. An ambiguous feature write or incomplete restoration is a stop; do not retry it by guesswork.

After a passing reconnect assessment and a separate operator decision, restore cables/radios and any approved sign-in setting to their recorded original values. Relaunch only the previously running WSL distributions and Docker Desktop through their normal owning workflows. Restart the exact reviewed containers/Compose projects, verify volumes and service health, and compare network, WSL, Docker, HNS, RDP, firewall, Sunshine and VDD observations with the private original-state record. Do not assume an originally stopped container should be started.

If the workstation cannot hold guests quiescent across fresh logon without interrupting important state, use a separately approved disposable Windows VM with its guest NIC disconnected from all switches instead of the physical host.
