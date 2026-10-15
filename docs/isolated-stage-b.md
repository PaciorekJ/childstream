# One isolated local Stage B interaction test

**Prepared in source; no live Stage B test is authorized or reported as passed.** The protected workstation is [outside this execution path](scope-boundary.md); do not pause Docker/WSL/Tailscale, disconnect its network or sign it out for ChildStream. On a separate dedicated target whose complete version 5 `ExternalNetworkIsolated` gate actually passes, this path continues the *same* journal after a positive `StageAValidated` result. Keep that target isolated and the second local observer present. Do not restore its child feature or reconnect it between Stage A and this separately approved test. The version 4 strict-isolation plan remains Stage A only. The connected-network RDP gate is unchanged.

## Separate approval and preflight

The operator's separate Stage B approval must identify the exact tested source SHA and v5 plan hash, one local loopback ActiveX connection, the exact-child teardown procedure, and the physical-console recovery reviewer. Approving Stage A never approves Stage B. After `verify-boundary` prints `StageAValidated`, run read-only `status`, `feasibility-inventory.ps1`, and `network-boundary-diagnostic.ps1 -OperatorConfirmedPhysicalSeverance -IncludeInventory` from an already elevated same-account physical console. Keep raw reports private. Require the same parent console logon, a positive no-child API result, independent session enumeration, complete External/GuestPath/RdpExposure acceptance, unchanged network fingerprint, ordinary RDP denied, stopped `TermService`, and no RDP listener. `StageAQueryUnknown`, error 1168, a source failure, a journal replacement conflict, or a topology change is a stop followed by Stage A restoration.

Only after the new approval, from the same checkout and while isolation is freshly verified:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe approve-b-boundary <APPROVED_STAGE_A_PLAN_HASH> I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe connect-once-boundary I-CONFIRM-PHYSICAL-ISOLATION
```

`approve-b-boundary` rechecks the exact plan, parent, child absence, RDP and network boundary before recording `ReadyConnect`. `connect-once-boundary` is the **single child-creating action** and needs its own explicit operator authorization. It records `Connecting` before ActiveX. The control is pointed at `localhost` with `ConnectToChildSession`; no password is supplied or stored. The viewer remains open until the operator closes it. Read-only boundary captures run immediately before ActiveX, when the exact child identity is observed, and periodically in the background while the viewer is open. A capture failure, network fingerprint drift, guest-path change, new listener/`TermService` state, RDP policy change, different account, or unexpected session stops the viewer and records an unresolved outcome. Captures are periodic and Windows APIs are not atomic; the local observer must watch the physical links continuously. The command may block while a capture completes. Do not infer that a briefly unseen exposure was impossible.

## Independent interaction evidence

While the viewer is open, use a second same-account physical-console window to capture private `status` and read-only feasibility inventory. Record exact parent and child session IDs and WTS logon generation; a journal in `Connecting` may already contain the positive child identity. Verify the child desktop is *visible and interactive*, then actively type or click in harmless unsaved windows on both desktops in alternation. Move focus to the physical desktop, minimize and restore the viewer, and verify child input and parent input continue independently. Record the physical primary display and any observed credential prompt, lock screen, unexpected listener, or loss of interaction. Keep screenshots and raw inventory local; do not publish private host data. This check does not assert controller, audio, GPU, Sunshine or game behavior.

Close only the **viewer window** when observations are complete; closing it is not child sign-out. The command then rechecks the exact associated child and journal. If `status` reports `Connected` with the expected ID and generation and the operator actually observed independent interaction, run:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe confirm-interaction-boundary <CHILD_ID>:<LOGON_TIME> I-CONFIRM-PHYSICAL-ISOLATION I-OBSERVED-INDEPENDENT-DESKTOP
```

The confirmation is a human acceptance record; source checks cannot substitute for the two visible desktops. A child ID alone is insufficient. If the desktop was not independently interactive, do not issue that confirmation and classify Stage B as failed or unknown with the observed cause.

## Exact teardown and restoration

After **separate approval to terminate the exact test child**, and only while the boundary still passes:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe end-child-boundary <CHILD_ID>:<LOGON_TIME> I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore-boundary I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe reconnect-boundary-check I-CONFIRM-PHYSICAL-ISOLATION
```

The probe rereads the parent-associated child ID and WTS generation immediately before `WTSLogoffSession`, writes `TeardownPrepared` first, and does not retry an ambiguous logoff. It verifies positive child absence and unrelated-session exclusion afterward. Restoration changes only the journal-owned child-feature value; `ReconnectReady=True` requires the original feature, RDP policy, service/listeners, firewall, display/native-resource fingerprint and isolated boundary to be independently verified. Only after local review of that result may the operator restore the dedicated target's approved network state. No command here changes ordinary RDP, firewall, Sunshine, VDD or display configuration.

## Interrupted viewer or changed boundary

If the viewer closes on its own, errors, or the process dies, **remain physically offline and do not reconnect or repeat `connect-once-boundary`**. Capture `status` and a private read-only inventory. A `Connecting` journal with a durably recorded positive child may be changed to `OutcomeUnknown` using `reconcile-connection-boundary I-CONFIRM-PHYSICAL-ISOLATION` only if the original isolated boundary and exact child identity still match. This does not create another child or claim interaction success. If the child identity was never durably recorded, or an unrelated session appears, do not guess an ID or use generic logoff; obtain local expert review.

For an identified child after a monitor failure or unexpected `TermService`/listener change, a **separate physical-console recovery approval** may use `end-child-boundary-reviewed <CHILD_ID>:<LOGON_TIME> I-CONFIRM-PHYSICAL-ISOLATION`. It requires independently accepted External and GuestPath predicates, the same parent/account, ordinary RDP policy denied, complete firewall observation, and the exact parent-associated child plus no unrelated session. It can terminate that exact child even when the RDP listener baseline drifted; it does not mark the interaction test passed or allow network reconnection. If External/GuestPath is lost or unknown, stop with no destructive action until that boundary is safely re-established and reviewed. A listener of unknown owner is a separate stop.

After reviewed child absence, use `restore-boundary-reviewed I-CONFIRM-PHYSICAL-ISOLATION` only with the separately reviewed feature/network-deviation acknowledgement. It may leave `Conflict` if `TermService`, a listener or another infrastructure observation differs. Follow the [Stage A physical-console recovery procedure](external-boundary-stage-a.md#unexpected-termservice-or-rdp-listener-after-feature-enablement) to resolve that exact difference; never silently stop an unidentified process or enable ordinary RDP. Run `reconnect-boundary-check` again only when feature restoration, child absence, listener/service restoration and complete original-state comparison all pass. Preserve the journal through any unresolved outcome.
