# One-session Windows feasibility experiment

This branch provides an operator-controlled experiment harness, not approval to run it. No Stage A or B command has been executed on the physical host. Synthetic tests establish code behavior, not Windows build 26200 behavior.

Microsoft documents child sessions as local loopback sessions connected through `ConnectToChildSession`, with an automatic-logon exception when the parent signed in before the feature was enabled. General network Remote Desktop enablement is not a documented prerequisite. If it proves necessary here, **stop**. This harness has no RDP registry, firewall, service, display, Sunshine, VDD, audio, or Steam writer. [Child Sessions](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions), [WTSEnableChildSessions](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenablechildsessions).

## Measured host evidence and corrections

The 2026-10-13 physical-console inventory observed Windows 11 Pro build 26200, process/console session 1 and protocol 0, disabled child feature, and repeated `WTSGetChildSessionId` failure 1168. The latter is **Unknown**, not absence: Microsoft's successful no-child result is `UINT_MAX`. Parent `WTSINFOEX` logon generation appeared plausible. Independent WTS enumeration showed no unexpected interactive session; this is the narrow pre-feature safety gate for Stage A, not a successful child API response. [WTSGetChildSessionId](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsgetchildsessionid), [WTSINFOEX_LEVEL1](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w).

Local `fDenyTSConnections=1`, absent policy override, stopped Manual `TermService`, and no inspected TCP/UDP RDP listener were observed. The updated inventory also reads related services, configured RDP port, TCP/UDP endpoints, firewall profiles, RDP rules, port ranges, and broad inbound allow rules with program/service scope. `LocalRdpPostureAccepted` is a conservative **local observation gate**, not a proof that every network route is closed. It fails on enabled RDP-relevant allow rules, unscoped broad allows, an observed listener, an unreadable firewall view, or a disabled firewall profile. This updated inventory has not yet been run on the host.

The native service is `SunshineService`. Inventory now discovers services by name, display name and executable identity. It reports hashed service commands and process paths. VDD selection requires exact Display/Monitor class, PnP root and name, and joins signed-driver metadata; `Xvdd SCSI Miniport` is excluded. The measured primary 3440×1440 screen is topology evidence, not proven physical hardware identity. The inventory does not read Sunshine pairing/configuration contents, usernames or passwords.

## Transaction and recovery

`plan` reads inventory without creating a lock or journal. It requires process session ID to match the active console and `WTSClientProtocolType=0`; a remote RDP session (protocol 2), inaccessible protocol query, or remote shell cannot pass. `begin HASH` is explicit Stage A approval: it repeats inventory and writes the original-state snapshot only when the hash matches. `prepare-a` is a separate command. Only it can call `WTSEnableChildSessions(true)`, once, when the original feature was false. It requires an **already elevated Administrator token** for the same Windows identity; there is no automatic elevation. Changed session, account, feature state, local RDP posture, or infrastructure fingerprint blocks the call. [WTSQuerySessionInformation](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw).

Journal and lock live at `%LOCALAPPDATA%\ChildStream-Feasibility`. Creation uses a protected DACL limited to the current SID, SYSTEM and Administrators. Existing state must have an approved owner and no other allow principals. Reparse paths, alternate data streams, unexpected state files/directories and ambiguous `.new` replacements are rejected. The lock is an exclusive OS file handle, and the checksum-protected journal is atomically replaced. Keep this directory private and never copy it into the repository or CI.

After Stage A enabling, the operator saves ordinary work and signs out/in at the physical console. `verify-a` requires the same SID and a different parent logon generation. A positive `WTSGetChildSessionId` no-child response (`UINT_MAX`) plus independent enumeration yields `StageAValidated`. Error 1168 or another ambiguous query yields `StageAQueryUnknown`; Stage B is blocked and restoration is the normal next action. Stage A never creates a child.

Stage B has a **separate** `approve-b HASH` command available only after validation. `connect-once` durably records `Connecting` before one local ActiveX call. Prompt suppression properties are mandatory; no username or password is supplied or saved. If a required property is missing, the control fails before `Connect`. `Connect` is asynchronous: only an observed connected control plus a parent-associated child ID and `WTSINFOEX` generation can yield `Connected`. Any failed or ambiguous attempt becomes `OutcomeUnknown`, without retry. Actual COM property availability, automatic authentication, and viewer lifetime remain live-validation questions. Do not authorize Stage B solely from offline tests. [IMsTscAx::Connect](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscax-connect), [AllowPromptingForCredentials](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclientnonscriptable5-allowpromptingforcredentials).

The operator confirms the physical console works, then separately approves `end-child ID:LOGON` using the ID and generation printed by `status`. The adapter rereads the **parent-associated** child and generation immediately before `WTSLogoffSession` for that exact ID. Any mismatch blocks it. `TeardownPrepared` is durable before the call; uncertain outcome never retries automatically. `restore` checks session absence and restores only the original child-feature value when the journal proves this probe changed it. Error 1168 is accepted only for Stage A recovery with independent no-unexpected-session evidence. After a Stage B attempt, restoration requires positive no-child API evidence. Failed restoration preserves the journal. [WTSLogoffSession](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtslogoffsession).

## Exact commands for a separately authorized run

Run from the repository root in the **physical Windows console**, never through RDP, CI, a container or remote shell. The commands below exist in this branch but were **not executed** in Stages A or B during this task. Keep the checkout at the reviewed, tested SHA and obtain separate authorization for each stage.

```powershell
# Read-only baseline. Review JSON locally; do not publish it.
pwsh -NoProfile -File .\scripts\feasibility-inventory.ps1

# Offline build/tests; creates only ignored repository artifacts.
pwsh -NoProfile -File .\tests\offline.ps1

# Read-only plan; record and review the printed hash and inventory.
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe plan

# Stage A, only after separate approval of the exact plan/hash.
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe begin <PLAN_HASH>
# In already elevated PowerShell of the SAME account at the console:
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe prepare-a
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status

# Save all work; the operator signs out and signs back in manually.
# No harness command signs out Windows.
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe verify-a
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status

# Stage B is a separate later decision, only if Stage A validated.
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe approve-b <PLAN_HASH>
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe connect-once
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
# Only after personally confirming the physical console is usable:
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe confirm-console
# Only after separate approval of the exact identified test child:
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe end-child <SESSION_ID>:<LOGON_TIME>

# In an already elevated same-account console if original feature was false:
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
pwsh -NoProfile -File .\scripts\feasibility-inventory.ps1
```

`status` reads the private journal. If `prepare-a` stopped at `PreparedEnable`, inspect inventory and journal at the physical console. If the feature is still false, `restore` can close the journal without a write. If true and change ownership is ambiguous, only after separate manual review use elevated `restore-reviewed`; it does not override session gates. Inspect both files before `repair-journal` when a `.new` replacement exists. Never delete journal files or repeat `prepare-a`, `connect-once`, or `end-child` after uncertain outcomes.

If the parent closes unexpectedly, log back in physically under the same account, run read-only inventory and `status`, and use `restore` only if child/session gates allow it. If a child is visible but its parent binding or generation is unknown, stop and preserve the journal; never use generic session logoff. If the feature is restored but RDP/firewall/display/native observations drift, the journal records `Conflict` for investigation. No harness command changes those resources.

## Stop points before a live experiment

- Re-run the **updated** read-only inventory and inspect broad allowances, firewall profiles, service state, VDD identity, and WTS sessions. The prior host report predates these corrections.
- Review the exact checkout and CI result. Confirm an already elevated same-account token can be used without switching SIDs, and a physical-console recovery route exists. Save all work before the required sign-out.
- Authorize Stage A as its own host change. Stop after `verify-a` if child APIs remain Unknown, an unexpected session appears, RDP posture drifts, or restoration cannot be verified.
- Stage B requires another decision after actual Stage A evidence. ActiveX no-prompt COM behavior, authentication, viewer close behavior and exact logoff permissions remain unverified on this host.
