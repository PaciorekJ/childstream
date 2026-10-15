# ChildStream completion mission ledger

This file records reviewable engineering state without private host addresses, account IDs, container details, plan hashes or journal contents. Raw host observations stay in a restricted local location and must be interpreted against the exact source SHA that collected them.

## Current milestone and review boundary

The immediate milestone is **Stage A: physical-host child-session feature feasibility**. The published implementation SHA is `ffe674bfbe4842493cc8b56ef1a3d54725613f78` on `codex/child-session-feasibility` in Draft [PR #3](https://github.com/PaciorekJ/childstream/pull/3), based on the PR #2 branch. Windows offline CI [run 38657570412](https://github.com/PaciorekJ/childstream/actions/runs/38657570412) succeeded for that exact SHA. The preceding read-only collector SHA `d6ed0a3f74a8f43477fff3b2f93554836ed9e2cd` also passed Windows CI [run 38656185244](https://github.com/PaciorekJ/childstream/actions/runs/38656185244). PR #3 remains Draft and unmerged. No Stage A, Stage B or physical-host configuration change has been performed under this mission.

The local `pwsh -NoProfile -File .\tests\offline.ps1` suite at `ffe674b` passed 104 launcher cases, 186 installer assertions, 208 feasibility assertions, network-boundary regressions, native-shim compilation, and source syntax/mutation-command checks. These are offline results, not host API acceptance.

## Elevated physical-console evidence

- The operator ran the reviewed `d6ed0a3` read-only source-shape command from an already elevated, same-account physical console. It reported `HostMutation=False`, `PhysicalConsole=True`, and `StageAPlanAuthorized=False`.
- Hyper-V switch/VM/host-port sources, HNS networks/endpoints, NetNat, PortProxy, IP forwarding, WSL, Docker and Docker-process sources were accessible. Two Internal switches, two management-OS ports, zero registered VM ports, two HNS networks and one endpoint were observed. Host-port and HNS endpoint graphs passed their current identity checks.
- The per-relevant-adapter bridge query completed for **12 adapters with zero failures** and produced a complete source fingerprint. The prior wildcard query had produced `CimJobException`; the exact provider cause was not captured. Successful per-adapter enumeration shows that a currently relevant individual adapter is not blocking the narrowed read.
- The ordinary RDP baseline predicate passed. The host was **connected** when measured: physical uplink and route corroboration failed, active guests/HNS endpoint and Docker host forwarding failed, and guest-to-host RDP exposure was not excluded. Virtual-path attribution remained `Unknown`, plausibly involving an addressed tunnel but not attributable from the redacted report alone. Physical severance and fresh-logon continuity were correctly `Unknown` before approval.
- Existing **20 potentially RDP-permissive and six unknown firewall rules** remain connected-network blockers. No rule has been changed or reclassified to make Stage A pass. A complete fingerprint while connected is evidence of source coverage, not evidence of network isolation.

## Implemented Stage A boundary

- Version 5 `ExternalNetworkIsolated` is separate from the existing strict v4 `NetworkIsolated` and v3 connected RDP posture. The connected-network firewall gate is unchanged.
- A single read-only private boundary capture contains the Windows feasibility inventory and the topology diagnostic. The probe verifies schema, collection and predicate coverage, exact relevant bridge-query set, independent adapter snapshots, RDP observation consistency, external and guest-path passes, RDP exposure pass, operator confirmation and a complete fingerprint. The plan hash and ACL-restricted journal bind the original feature state and full private network observation.
- `plan-boundary` is read-only. `begin-boundary`, `prepare-boundary`, `verify-boundary`, `restore-boundary`, reviewed recovery, and reconnect assessment require renewed physical-isolation confirmation. The probe rechecks topology before the feature write, after the non-atomic API call, after a fresh parent logon, during restoration and before reconnect. Drift or capture failure is durably recorded; it blocks progression and any new child creation. Stage B commands refuse this posture.
- Restoration requires an accepted external/guest boundary, independent child absence, and an exact original child-feature value. Unexpected `TermService` or RDP listener changes leave a conflict even if the feature is restored. Reconnect readiness is separate and requires restored feature, closed RDP posture, original infrastructure and a resolved journal. Error 1168 remains unknown.
- [external-boundary-stage-a.md](external-boundary-stage-a.md) gives the offline physical-console commands, stop conditions and reviewed recovery. [workload-quiescence-runbook.md](workload-quiescence-runbook.md) records the proposed reversible Docker/WSL pause. Neither document authorizes a host action.

## Remaining uncertainties and blockers

1. **Current host state is No-Go.** The latest measurement is connected with live internal guests, one HNS endpoint, Docker forwarding and unresolved virtual-path attribution. Stage A cannot be authorized from it.
2. A separately approved, operator-controlled workload pause must preserve stateful container and WSL work and remain effective after fresh logon. If it cannot, use a separately approved disposable switch-disconnected Windows 11 VM rather than forcing the physical host gate.
3. A separately approved physical disconnection and a second local observer must establish and maintain external severance. The read-only v5 `plan-boundary` must then return an exact hash only when `External`, `GuestPath` and `RdpExposure` all pass. An addressed Tailscale or other unmatched path remains `Unknown` until proven absent or independently attributed. Do not whitelist it by name.
4. Exact plan-hash approval, child-feature mutation, fresh console sign-out/logon and any reviewed recovery remain separate operator gates. The original host configuration, Sunshine and VDD must stay untouched. `TermService`, RDP listeners, feature state and journal must be checked before reconnection.
5. The first live Stage A result must establish WTS behavior after fresh logon. It does not itself establish a second interactive desktop. Stage B viewer lifetime, child connection, independent-desktop interaction, Sunshine, controllers/audio, games, installer live rollback and real-device acceptance remain unrun and unauthorized.

## Next action

Request a **specific** approval for the reversible Docker/WSL pause and physical network disconnection described in the runbooks, after reviewing container ownership and unsaved work. During that separately authorized offline window, the operator first runs the read-only diagnostic and `plan-boundary`; any failed or unknown predicate ends the attempt before `begin-boundary`. If a complete v5 plan is produced, review its private baseline and approve its exact hash and one Stage A feature-enable/fresh-logon/restore cycle separately. Do not run Stage B or reconnect before `reconnect-boundary-check` reports ready and the operator confirms the original host state.
