# External-boundary Stage A: physical-console operator procedure

**Historical v5 procedure; not authorized for the protected workstation.** Its workload/network interruption premise conflicts with the permanent [scope boundary](scope-boundary.md). Do not execute this sequence on that workstation or use it to request shutdown of unrelated work. The active test target is a [separate Windows environment](stage-ab-physical-window.md). The transaction and recovery details below remain reference material for an independently isolated target whose full v5 gate actually passes; they do not authorize a host change. Do not use a remote shell or RDP session.

## Approval and original-state record

For a separate dedicated target only, approval must identify the exact published source SHA, operator account, console, test machine, isolation method, one child-feature enable/restore cycle and one fresh parent sign-out/logon. Those actions need separate authorization from code publication. A second local observer must verify the target's isolation before each confirmation and watch for reconnection throughout the test. Software snapshots alone cannot prove continuous severance.

From the exact checkout on the dedicated target, run `pwsh -NoProfile -File .\tests\offline.ps1`. This creates `tests\.artifacts\ChildStreamFeasibilityProbe.exe` from the checkout and runs the offline suite; it performs no Windows feature mutation. Verify `git rev-parse HEAD`, `git status --short`, the console/protocol-0 finding in `pwsh -NoProfile -File .\scripts\feasibility-inventory.ps1`, and an already elevated **same-account** process. The probe does not elevate itself. Capture the target's original child feature, RDP policy, `TermService`, TCP/UDP listeners, firewall/profile evidence, Sunshine/VDD observations and active adapters/routes in a restricted local location; never upload raw inventory, plan hash or journal to GitHub. The probe writes its private journal beneath `%LOCALAPPDATA%\ChildStream-Feasibility` and checks its ACL.

Do not stop or inspect unrelated workloads to satisfy `GuestPath`. Choose a dedicated target with no protected guests or shared-service dependencies; if its gate fails, stop rather than altering unrelated resources. Isolate only that target under separate authorization. Do not edit ordinary RDP policy, firewall rules, Sunshine, VDD or display settings to force a pass. The protected workstation's 20 potentially permissive and six unknown firewall findings remain connected-network blockers.

Before authorizing a later fresh sign-out, the operator must independently verify an offline Windows sign-in method for this account and an available physical-console recovery administrator. A read-only account or policy check cannot prove that a password, PIN or cached identity will unlock the desktop offline. The current plan-only rehearsal does not sign out; if offline sign-in is unverified, finish that rehearsal and defer Stage A mutation. Record the recovery method privately without storing credentials in the project or journal.

## Offline plan and feature test

All commands below are from the repository root in the same already elevated physical-console account. The literal confirmation means the operator and observer have **just** checked physical severance. Do not supply it based on an old reading.

```powershell
pwsh -NoProfile -File .\scripts\network-boundary-diagnostic.ps1 -OperatorConfirmedPhysicalSeverance
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe plan-boundary I-CONFIRM-PHYSICAL-ISOLATION
```

The diagnostic is read-only. Inspect each predicate and its local evidence. `External`, `GuestPath` and `RdpExposure` must all be `Pass`; `Continuity` is `Unknown` before a journal exists. `virtual-paths-attributed` must be `Pass`: an addressed tunnel or other unmatched virtual path remains `Unknown` even when Wi-Fi is down. Do not assume a missing default route or an Internal switch is safe. If a source or relationship is unknown, or a guest/endpoint/forwarding path remains active, **No-Go**. Do not change shared adapters or workloads to force a pass. Keep the complete report private.

`plan-boundary` is read-only and prints an exact v5 plan hash. Review the local baseline and obtain explicit approval for that exact hash. If any topology, session, RDP or firewall observation changes, discard the hash and plan again; the probe will also reject a stale hash. Only after approval:

### Abort before `begin-boundary`

If the diagnostic or `plan-boundary` fails or returns an unknown predicate, **do not run `begin-boundary`**. There is no new probe journal and no feature write. Preserve the private diagnostic and error. Verify locally that `%LOCALAPPDATA%\ChildStream-Feasibility\probe.journal` was absent before and after the attempt; if a journal exists, this is not the pre-transaction path and its own recovery procedure applies. Rerun the read-only feasibility inventory and compare the child-feature value, RDP policy, `TermService`, listener observations, firewall and physical console with the private original record. If any reading is inaccessible or changed unexpectedly, remain offline for review.

With the original feature and RDP baseline confirmed on the dedicated target, the operator may restore only that target's approved isolation controls. Do **not** use `reconnect-boundary-check`: it requires a journal and is not a pre-transaction recovery mechanism. An unresolved addressed virtual path is a failed plan, not permission to whitelist an adapter or alter shared networking. A later attempt needs a new read-only plan and approval.

### Approved transaction only

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe begin-boundary <APPROVED_PLAN_HASH> I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe prepare-boundary I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

`begin-boundary` records the exact original feature and full private network/topology fingerprint in an ACL-restricted version 5 journal. `prepare-boundary` rereads the boundary, records enable intent before the non-atomic API, enables the child feature only if the exact baseline still matches, and checks the result. It must finish at `AwaitFreshParent`. A write failure, listener/service change, unexpected session, missing source, active uplink/guest or fingerprint drift is a stop. Do not create a child session, run `approve-b` or `connect-once`, or reconnect the isolated test target.

After a separate approval for fresh sign-out/logon, sign out **only the parent console session** using the normal Windows UI and log back into the same account at the target console. The local observer keeps external links severed and confirms no guest peer appeared. From an already elevated same-account console:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe verify-boundary I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

`StageAValidated` requires a fresh console parent and a positive no-child WTS API result plus independent session enumeration. `StageAQueryUnknown` preserves error 1168 or another ambiguous result as **unknown**, not success. Stage A approval alone never authorizes Stage B. The normal path restores the feature. If Stage A is validated and a **new, exact-plan Stage B approval** is separately granted while the same v5 boundary remains intact, continue directly with [one isolated local Stage B test](isolated-stage-b.md) before restoration. A deviation or query failure prohibits that progression.

## Restoration and reconnect decision

While still physically offline, review `status` and the private diagnostic. If no deviation or ambiguous feature write occurred, run:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore-boundary I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe reconnect-boundary-check I-CONFIRM-PHYSICAL-ISOLATION
```

If the journal records a network deviation, ambiguous enable intent, interruption or a failure, stop and review the exact original/current states with the local operator. Re-establish independently verified severance and guest quiescence first. `restore-boundary-reviewed I-CONFIRM-PHYSICAL-ISOLATION` is the explicit reviewed recovery command; it acknowledges both network deviation and an ambiguous feature write, so it must be used only after that review. A retained `probe.journal.new`/prior replacement conflict requires inspection and the separate `repair-journal` action before recovery. Never delete or reset the journal to make a command run. Do not repeat an ambiguous feature write or sign out a session by guessing its ID.

### Unexpected `TermService` or RDP listener after feature enablement

This branch needs a **separate physical-console recovery review and approval**. Keep every external link severed, keep guests quiescent, and make no child-session connection. Record `status` and a new private read-only feasibility inventory. Compare the original and current feature value, exact parent and enumerated sessions, `TermService` state/start mode/image, RDP TCP/UDP endpoints and owning PIDs, configured RDP port, deny policy and firewall fingerprint. An unknown listener owner, changed policy/firewall, unexpected session, inaccessible source or lost physical boundary is a stop for local expert recovery; do not stop an unidentified process or reconnect.

If the external and guest boundary is independently re-established, the reviewer may authorize `restore-boundary-reviewed I-CONFIRM-PHYSICAL-ISOLATION` to restore **only** the child feature from its journaled original value. The probe checks child absence and verifies the result. It can leave `Conflict` when `TermService` or a listener differs; this is intentional and does not permit reconnection. If the original service was Stopped, no child or remote session exists, the service identity is unchanged, and the changed listener is positively attributed to `TermService`, a separate reviewer may authorize an exact `Stop-Service -Name TermService -ErrorAction Stop` from the elevated physical console. Do not use `-Force` or change its start mode. Reinspect service state and all relevant TCP/UDP listeners. If the service cannot stop cleanly, restarts, or a listener remains, stay offline and escalate to local Windows recovery. If a listener is not attributable to `TermService`, investigate its owning PID/service separately; no generic kill is authorized.

After the original service/listener state is independently verified again, rerun the reviewed restoration command to resolve a `Conflict` journal, then run `reconnect-boundary-check I-CONFIRM-PHYSICAL-ISOLATION`. Only `ReconnectReady=True` plus operator review permits the dedicated target's network restoration. This sequence has not been exercised on a live test target.

The restoration path permits exact child-feature restoration only while the external and guest boundary is accepted. It verifies the original feature value and independently excludes a child session. An unexpected `TermService` or RDP listener change can leave `Conflict` even after the feature is restored. `reconnect-boundary-check` must print `ReconnectReady=True` with feature restored, child excluded, boundary intact, RDP policy denied, `TermService` stopped, listeners absent, and original infrastructure verified. If it returns false or errors, keep the PC offline, preserve the journal and arrange a separately reviewed recovery. Do not silently stop a changed service or edit RDP/firewall settings.

Only after a passing reconnect assessment and a separate operator decision may the operator restore the dedicated target's approved network state. Compare post-restoration RDP, firewall, Sunshine and VDD observations with its private baseline. A Stage A result is evidence about the Windows API on that target; it is not permission to install ChildStream or attempt Stage B.
