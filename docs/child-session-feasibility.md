# Child-session feasibility boundary

## Question and evidence level

The single experiment asks whether a Windows 11 Pro console can open one local, password-free child session while ordinary network Remote Desktop remains disabled. The code in this branch is **offline-only**: `FeasibilityProbe` has a fake-host interface and no implementation that enables the feature, connects an RDP control, or logs off a Windows session. `scripts/feasibility-inventory.ps1` is a read-only candidate adapter; it has been syntax checked and its embedded native shim compiled, but it has not been run on the target computer. Synthetic success is not platform evidence.

Microsoft describes the child session as a loopback session tied to the parent, created through the Remote Desktop ActiveX control after setting `ConnectToChildSession`; automatic logon has exceptions for smart-card logon and a parent signed in before child sessions were enabled. It does **not** state that general network RDP must be enabled. Therefore the experiment must never set `fDenyTSConnections`, start an RDP listener, or add a firewall rule. A network RDP opening is a failed precondition, not a fallback. Sources: [Child Sessions](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions), [ConnectToChildSession property](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings-property), [WTSEnableChildSessions](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenablechildsessions).

## Read-only inventory and original snapshot

The inventory reports typed `Accessible`, `Absent`, `Inaccessible`, or `Unknown` states instead of treating failed reads as absence. It captures the exact child-feature Boolean; active console, current process, associated child ID and WTS session logon generation; Windows build; exact local and policy `fDenyTSConnections` values with registry types; configured RDP TCP port; listener addresses; effective RDP firewall rule identity, action, profile and remote scope; display bounds; and Sunshine service/process and VDD device identity. Account SID and Sunshine paths appear only as SHA-256 hashes. Usernames, passwords, pairing material, and Sunshine configuration contents are never collected.

`WTSLogonTime` is documented as unsupported. The inventory uses read-only `WTSSessionInfoEx` for logon generation instead. Its native structure layout and readings still need validation on the target Windows build. The screen list is current-session topology, **not proof of physical display identity**. The adapter labels network closure unverified; an operator must review all listening ports, policy and effective firewall state before a plan may be approved. Sources: [WTS_INFO_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class), [WTSINFOEX_LEVEL1](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w).

The approved `ProbePlan` hashes the canonical original state: feature value, parent session ID and logon generation, console ID, account binding, OS edition/build, verified closed network RDP, and fingerprints of RDP registry, listener, firewall, display and native resources. Child absence must be positively established. The journal stores the snapshot before any intended mutation. Any inaccessible, unknown, or conflicting field blocks the live plan.

## Transaction sequence and stop rules

1. Read inventory under the exclusive cross-process lock. Verify Windows 11 Pro, same parent and console session, no associated child, closed network RDP, known feature state and stable resource fingerprints. Review and approve the exact plan hash and the single proposed feature change separately from this PR.
2. Under the lock, reload the journal and inventory. Persist `Captured`, then `PreparedEnable` **before** calling `WTSEnableChildSessions(TRUE)` if the original value was false. Require an already elevated Administrator token for that call; never elevate automatically. Verify the feature by rereading `WTSIsChildSessionsEnabled`. If it was already true, make no feature write.
3. Persist `AwaitFreshParent`. The operator signs out and signs back in; the probe resumes only for the same account binding with a different parent logon generation, same closed-RDP and resource fingerprints, and no child. This boundary is required even if the feature was already enabled, so the automatic-authentication prerequisite is explicit.
4. Persist `Connecting` and make **one** local ActiveX child-session connection attempt with `ConnectToChildSession=true`. Record HRESULT/Win32 error, whether credentials were requested, and the parent-associated child session ID plus its logon generation. Never supply, save, or prompt for credentials. Only an automatic-authentication result with a matching parent-associated identity may enter `Connected`. A failure or uncertain return enters `OutcomeUnknown`; no automatic retry occurs.
5. A human verifies the physical console still works independently and records this checkpoint. Before teardown, reread the associated child and compare **both** ID and logon generation. Persist `TeardownPrepared`, then log off that exact child only with explicit teardown consent. An exception or uncertain result leaves the durable intent and forbids another automatic logoff.
6. Verify no associated child. Restore only the child-feature Boolean that this transaction changed: if originally false, compare/exchange true to false with Administrator rights, then reread and verify false. If originally true, leave it true. Mark `Restored` only after verification. No RDP, firewall, display, Sunshine or VDD value is in the write interface.

An interruption before the feature write can resume at `PreparedEnable` and verify the original false value. If `PreparedEnable` survives and the value is true, the intent alone cannot prove whether this probe or an external actor made the change. Restoration then requires explicit reviewed acknowledgement; an unplanned change from `Captured` is blocked even with that acknowledgement. A partial journal replacement blocks action until explicit journal repair under the same lock. An interruption around connection or teardown leaves `Connecting` or `TeardownPrepared`; it requires a new read-only assessment and a human decision. A failed restore stays `Restoring` with the snapshot and can be retried only after state and privilege checks. A child with unknown identity, a different ID/generation, a changed parent or account, any RDP drift, or uncertain child query blocks destructive action. The operator must preserve the journal and diagnostics when rollback cannot be verified. These are state-machine guarantees under a truthful host adapter; they do not make the Windows API calls atomic.

## Privilege and command boundary

The first **currently executable** live-host command, after separate authorization, is read-only and should run from the interactive parent console:

```powershell
pwsh -NoProfile -File .\scripts\feasibility-inventory.ps1
```

Do not pipe its output to a public log. The inventory has no write method. A signed, reviewable Windows mutation adapter and CLI still must be implemented and independently reviewed before any Apply command exists. The planned CLI contract for that future boundary is:

```powershell
# Proposed only; these commands are not available in this branch.
.\ChildStreamProbe.exe plan --inventory .\private\inventory.json --journal .\private\probe.journal
.\ChildStreamProbe.exe begin --approved-sha256 <exact-plan-hash> --consent-enable-child-feature
.\ChildStreamProbe.exe prepare-feature
# Sign out and sign back in to a new parent console logon.
.\ChildStreamProbe.exe resume --journal .\private\probe.journal
.\ChildStreamProbe.exe connect-once --journal .\private\probe.journal
.\ChildStreamProbe.exe confirm-console --journal .\private\probe.journal
.\ChildStreamProbe.exe end-positive-child --consent-logoff-exact-child
.\ChildStreamProbe.exe restore-original --journal .\private\probe.journal
```

`prepare-feature` and `restore-original` require an already elevated Administrator token **only when changing the feature**. Connection must run in the correct interactive parent session. Teardown authority must be established for the exact child; the API permissions and safe host implementation still need Windows review. This plan never needs Administrator rights to change ordinary RDP or firewall because neither is changed.

## Gates before the first mutating test

- Separately authorize the specific host, time window, feature enablement (if needed), one connection, exact-child teardown, and restoration. Keep a second operator at the physical console and a recovery route if the display becomes unusable.
- Verify the read-only adapter's WTS structure layout, session generations, registry values, listener/firewall coverage, display interpretation and native resource identity on the target build. Resolve every `Unknown` or `Inaccessible` result. Confirm smart-card logon is not involved.
- Implement and offline-test the narrow Windows host adapter with the documented ActiveX control, `WTSEnableChildSessions`, `WTSIsChildSessionsEnabled`, `WTSGetChildSessionId`, session-generation query, and exact-child logoff. Bind it to the locked journal and explicit approvals; do not add global RDP or firewall setters.
- Review ACLs and placement for the journal and lock, ensure no untrusted process can replace them, and verify the operator has an independent host recovery method. This branch's fake host and generic file journal do not prove these Windows deployment properties.
- Demonstrate an offline rehearsal of interrupted states and a manual recovery sheet for unresolved child identity or failed feature restoration. Recheck network RDP remains closed before and after the experiment.
