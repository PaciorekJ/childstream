# Network-isolated Stage A: dedicated-target console runbook

**Preparation only for a separate Windows target.** The protected workstation is blocked by the permanent [scope boundary](scope-boundary.md); do not disconnect it, pause shared services, or sign it out for ChildStream. This document does not authorize a test-target change. Obtain separate approval of the exact source SHA, isolation method, plan hash, Stage A feature write and operator recovery arrangement. This version 4 strict-isolation plan remains Stage A only; its Stage B continuation needs a focused source increment. The separate version 5 external/guest boundary has an [isolated Stage B path](isolated-stage-b.md) only when all v5 sources and predicates pass on an independent target. Keep this document and the repository on the target before disconnecting it; do not depend on internet access during the experiment.

**Current status:** The strict gate below remains unchanged. The predicate-level read-only diagnostic and the proposed external/internal boundary are in [stage-a-network-boundary-design.md](stage-a-network-boundary-design.md). Retained internal adapters cannot be accepted until their switch/underlay paths and active peers are independently verified. Do not try to use this runbook to bypass the strict gate.

## What the offline gate proves and does not prove

`plan-isolated` requires a literal operator confirmation **and** a fresh read-only Windows inventory. The inventory includes visible and hidden adapters, IPv4/IPv6 IP interfaces, addresses, and ActiveStore routes in all network compartments. It accepts only a known disconnected/disabled non-loopback adapter state, disconnected non-loopback IP interfaces, and no non-loopback address or route. It therefore rejects an active Ethernet, Wi-Fi, VPN, Bluetooth PAN, mobile, USB, virtual, or bridged interface even when there is no default gateway. An unknown state, unreadable source, or contradictory loopback reading rejects the plan. Adapter category labels help review; the gate applies to every adapter regardless of label. [Get-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter), [Get-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface), [Get-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute), [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress).

This is an observed Windows network-stack boundary at each check, not continuous monitoring or proof about every external device. An unrepresented path or an interface that reconnects between checks remains a risk. Keep physical cables removed and radios off for the entire experiment, and have a second local observer verify them. If the target cannot satisfy the strict gate, **stop** and design a separately reviewed external isolation mechanism; do not weaken the 20 potentially permissive firewall-rule findings or change those rules.

The 2026-10-14 **connected**, read-only console inventory successfully read all four network sources: 21 adapters, 16 IP interfaces, 22 addresses and 63 routes. Nine adapters were active, eight non-loopback IP interfaces were connected, and non-loopback addresses and routes were present. The gate correctly rejected this connected state. No physical disconnection, isolated plan or plan hash has been tested on the host.

## Before physical isolation

1. At the physical console, confirm the reviewed clean checkout with `git rev-parse HEAD` and `git status --porcelain`. Confirm the operator has the same-account, already elevated Administrator console available for the later feature write and restoration. The probe never elevates itself.
2. Save all work. Arrange a second local operator who can inspect cables, radio state, the physical console, and the private journal without an online reference. Have local power and keyboard access. Do not use RDP or a remote shell.
3. Run `pwsh -NoProfile -File .\tests\offline.ps1` while connected to build the local probe. Keep the executable and this runbook locally. Verify the evidence directory ACL permits only the current user, SYSTEM and Administrators; otherwise prepare a restricted local directory under separate approval. Do not upload raw inventory.
4. Save a **private pre-isolation inventory** using `pwsh -NoProfile -File .\scripts\feasibility-inventory.ps1 > .\tests\.artifacts\pre-isolation.json`. Record cable, Wi-Fi, Bluetooth, cellular, USB tether, VPN, virtual-switch/bridge and VM state separately. This pre-isolation record is for manually restoring the network after the experiment; the probe never changes networking.

## Establish isolation under separate authorization

The operator physically unplugs all Ethernet and USB networking/tethering paths, turns off Wi-Fi, Bluetooth PAN and cellular radios, and disconnects VPNs. Review virtual switches, bridges, host-only networks and VMs. If a virtual adapter or route remains active, `plan-isolated` must reject; manually changing adapter or VM configuration requires separate approval and a recorded original state. Do not modify firewall rules, ordinary RDP, Sunshine, or VDD. Keep the PC disconnected through restoration and the final reconnect check.

Run the read-only inventory again into a separate private file and inspect **all four** `Network` sections. A route to a local subnet or a link-local address is a blocker even if the default route is absent. Verify the process session is the active physical console and the current protocol is 0. A failed query is a stop, not permission to infer disconnection.

Only after both operators confirm the actual physical isolation, run from the repository root:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe plan-isolated I-CONFIRM-PHYSICAL-ISOLATION
```

Keep the printed hash privately. The v4 plan binds the `NetworkIsolated` posture, operator confirmation, network fingerprint, RDP-denied policy, stopped `TermService`, absent inspected RDP endpoints, firewall/profile inventory, console/session identity and other original-state fingerprints. The connected-network `plan` still rejects the 20 potentially permissive and six unknown firewall rules.

## Stage A, only after exact-hash approval

First, create the private journal from a **fresh matching inventory**:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe begin-isolated <APPROVED_PLAN_HASH> I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

In an already elevated PowerShell under the **same Windows account** at the physical console, recheck the cables and radios, then run exactly once:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe prepare-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

The probe records `PreparedEnable` before the non-atomic `WTSEnableChildSessions(true)` call. It rechecks isolation and all bound state before and after. A failure or unknown result is **not** permission to repeat the call. If the call starts `TermService`, creates a listener, or changes another bound resource, progression stops and the journal stays available for recovery.

If and only if the stage reached `AwaitFreshParent`, the operator saves remaining work and signs out and back in manually at the physical console. The network stays physically isolated. Reconfirm cables and radios and run:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe verify-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

Only a successful no-child API response plus independent session enumeration validates Stage A. Error 1168 remains `StageAQueryUnknown` and requires restoration; it never authorizes Stage B. No command in this runbook creates or signs out a child session.

## Restore before considering reconnection

From an already elevated same-account physical console, after confirming continued isolation and no unexpected child/session, use the ordinary route:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

If `PreparedEnable` leaves the feature write ambiguous, or the journal records a network deviation, **stop and review** the private journal, before/after inventory, feature state, session enumeration, physical network state, and original plan with the second operator. Re-establish verified isolation first. Only after separate recovery approval use:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore-isolated-reviewed I-CONFIRM-PHYSICAL-ISOLATION
```

This route does not override child absence, console/account, RDP policy, or a lost/unknown isolation reading. It can restore the original child-feature value only when the probe proves it owns that change. A network fingerprint that still differs from the approved offline baseline leaves `Conflict` even if feature restoration succeeds. Failed or ambiguous restoration keeps the journal; never delete it or repeat an uncertain feature write.

Run the explicit assessment while still isolated:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe reconnect-check I-CONFIRM-PHYSICAL-ISOLATION
```

**Do not reconnect unless it returns `ReconnectReady=True` and exit code 0.** This requires the original child-feature value, child absence, exact offline network fingerprint, ordinary RDP-denied policy, stopped `TermService`, no inspected RDP listener, unchanged firewall/display/native-resource fingerprints, and a restored journal. An unexpected service or listener change is an unresolved security exposure even if the feature was restored; the probe never stops services or edits firewall rules. Such a change requires a separate local recovery decision before reconnection.

After a passing reconnect check and a separate operator decision, manually restore the network from the private pre-isolation record. Immediately take a new read-only inventory and compare the feature, RDP policy, services/listeners, firewall, Sunshine, VDD and network state to the recorded originals. Preserve both inventories and the journal privately.

## Stop and independent recovery

If isolation is lost, a Wi-Fi/virtual interface reappears, a query is unreadable, a new session appears, or any fingerprint drifts: keep the PC physically offline, do not run `verify-isolated` again, and do not run any Stage B command. The probe records a detected network deviation in its private journal and blocks further progression. It has no background monitor; a local observer must watch the physical links between checks.

If the probe cannot run, the second operator can inspect the host **read-only** from local PowerShell with `Get-NetAdapter -Name '*' -IncludeHidden`, `Get-NetIPInterface -PolicyStore ActiveStore -IncludeAllCompartments`, `Get-NetIPAddress -PolicyStore ActiveStore -IncludeAllCompartments`, `Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments`, `Get-Service TermService`, and the saved inventory/journal. Leave the machine disconnected and preserve evidence. Do not guess at a child ID, use generic session logoff, enable ordinary RDP, stop `TermService`, change firewall rules, delete a journal, or reconnect to seek help. If the harness cannot prove safe restoration, escalate to a separately reviewed local recovery procedure while physical isolation remains in force.
