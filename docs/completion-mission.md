# ChildStream completion mission ledger

This file tracks durable engineering state. It contains no private host addresses, account identifiers, container details, pairing data, or journal contents. Live observations must be kept in a restricted local location and reviewed against the exact source SHA used to collect them.

## Current milestone

**A — physical-host child-session feasibility.** The already elevated same-account console report validated most collector sources. The current increment narrows the bridge read and reports source uncertainty by adapter. It remains read-only. A new Stage A plan/journal version is still gated on a complete, reviewable offline topology snapshot. No physical Stage A operation is approved. Do not advance to Stage B, Sunshine integration, or the gaming installer until Stage A produces meaningful Windows API evidence.

## Source and review lineage

| Review boundary | Branch | Last verified published SHA | State |
| --- | --- | --- | --- |
| Foundation, PR #1 | `codex/hardened-foundation` | `732315800e468774d91a714fd2fb171a3ad1a851` | Draft, unmerged per mission input; refresh remotely before relying on current status |
| Transaction foundation, PR #2 | `codex/transactional-installer` | `fedd27deabdefc48bf51994223f18f1d88b60d39` | Draft, unmerged per mission input; refresh remotely before relying on current status |
| Feasibility, PR #3 | `codex/child-session-feasibility` | `fc5972b0c1a9dd0513a8dbfc288502afa54d268a` | Draft, unmerged; Windows offline CI run 38550773385 passed at this SHA. This document is updated in the next focused increment. |

## Completed evidence

- The reviewed baseline includes a read-only physical-host feasibility inventory, a staged child-session probe, exact-state journal/recovery foundation, and a read-only predicate-level network diagnostic.
- Earlier offline evidence at the PR #3 baseline: 104 launcher cases, 186 installer assertions, 171 feasibility assertions, network diagnostic scenarios, and source/syntax checks. Windows CI passed for that published baseline. These tests are not physical-host acceptance.
- Earlier private host evidence established that connected-network firewall classification and active internal workloads block the Stage A posture. The actual topology, counts, identities and security settings remain in the private report. Those observations predate this mission and may have changed.
- The current zero-non-loopback isolated gate cannot accept the observed workstation topology. The read-only network diagnostic cannot authorize Stage A. No isolated-state host inventory has been collected under this mission.
- This mission added a read-only Hyper-V host/VM port, HNS endpoint, bridge binding, IP forwarding, Docker-process and portproxy registry inventory to the network diagnostic. It now attributes a management-OS vEthernet only through a unique MAC, PnP and Hyper-V host-port/switch relationship; an addressed tunnel stays Unknown. Its fingerprint binds all collected source sections, RDP/firewall evidence and operator confirmation; missing sources yield no fingerprint. It remains diagnostic-only and does not alter the existing v4 probe or connected-network gate.
- A redacted `network-source-shape.ps1` operator command reports property coverage, counts and predicate verdicts without raw host identities or fingerprint values. An inbox Windows PowerShell 5.1 bridge reads HNS because the module is not callable directly from this machine's `pwsh` process. Execution policy is process scoped and access failures remain Unknown.
- The published `fc5972b` offline suite passed locally: 104 launcher cases, 186 installer assertions, 171 feasibility assertions, network boundary scenarios including graph ambiguity and fingerprint drift, native shim compilation, syntax and mutation-command audit. Windows CI run 38550773385 succeeded for that exact SHA.
- The operator's later already elevated same-account physical-console report confirmed read-only access to Hyper-V switch, VM and host-port sources; HNS network and endpoint sources; WSL, Docker, NetNat, PortProxy and IP-forwarding sources. Two internal Hyper-V switches, two management-OS ports, zero registered VM ports, two HNS networks and one endpoint were observed. The ordinary RDP baseline predicate passed. This was a **connected** host measurement: external isolation, internal guest quiescence and guest-to-host RDP exposure all failed. The bridge-binding wildcard query returned `CimJobException`, so the full fingerprint was absent. The redacted property shape showed complete switch/host-port identities and HNS endpoint IDs, but aggregate `NetAdapter` coverage gaps do not establish that management-OS adapters lack identity. The exact bridge failure cause cannot be inferred from the exception class alone.
- The next collector increment queries every relevant adapter's full binding set individually and keeps any failed or empty query Unknown. It compares host-port MAC plus switch ID/name and adapter type/description; PnP and physical-adapter-only properties are not demanded of unrelated miniports. It cross-checks HNS endpoint network IDs and separates current connected/workload blockers from evidence gaps and future operator checks. These changes do not authorize Stage A or change the existing connected-network firewall gate.

## Outstanding acceptance and risks

- Validate the **new per-adapter** bridge query and role-scoped management-OS adapter coverage using an already elevated same-account physical-console read-only report. The prior `CimJobException` cannot identify whether wildcard hidden enumeration, an individual unsupported adapter, or the CIM provider failed. Unreadable or contradictory sources remain Unknown. Names alone are insufficient.
- Confirm physical severance and absence of external underlays without inferring isolation from a missing default route.
- Prove no active internal guest can reach a newly created host RDP listener, or arrange a separately approved, reversible workload pause that remains effective across fresh logon. Existing potentially permissive/unknown firewall rules are connected-network blockers.
- Once the narrowed source checks and an offline quiescent snapshot establish complete evidence, bind the approved topology and guest state to a **new versioned** Stage A plan/journal and recheck it before feature enablement, after the API call, after fresh logon, during recovery, and before reconnecting. Preserve old v4 journal compatibility. The current diagnostic fingerprint is not a probe plan hash.
- Validate actual no-child API result after a fresh parent-console logon; error 1168 remains Unknown. Restore the exact original feature state and verify RDP/TermService/listener posture before external reconnection.
- Later milestones B–F, physical desktop independence, GPU capture/NVENC, Fire TV/Moonlight, controllers/audio, Steam/gameplay, installer usability and rollback, and real-device acceptance are unrun.

## Host change and restoration record

No physical-host modification has been approved or performed under this mission. There is no new original-state snapshot or restoration evidence. No guest or network workload has been stopped. Keep any future live baseline and journal private.

## Next executable action and operator gate

After the focused collector change passes CI and is published, the exact next operator operation is a **targeted read-only** rerun of `pwsh -NoProfile -File .\scripts\network-source-shape.ps1` from an already elevated, same-account physical console, with networking and workloads in their current state. Share only its redacted JSON. The per-adapter bridge failure classes, role-scoped Hyper-V host-adapter coverage and HNS graph predicate determine whether the collector can prove a complete topology. Do not run `plan`, `begin`, `prepare`, `verify`, `restore`, workload stop, network-disconnect or logon during this gate. A separate approval is required for each later physical network disconnection, workload pause, feature enablement and fresh logon. The proposed workload pause and exact restoration record are in [workload-quiescence-runbook.md](workload-quiescence-runbook.md). If any relevant bridge binding remains uninspected, retain No-Go and prefer the separately approved disposable, switch-disconnected VM alternative.
