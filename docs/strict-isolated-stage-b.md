# One strict-isolation Stage B test on an independent Windows target

**Source prepared; no live Stage A or B has run.** This procedure applies only to a separately approved Windows 11 Pro physical PC or no-NIC VM on an independent host. It is prohibited on the protected development workstation. A new `plan-isolated` creates a v6 plan; old v4 journals remain Stage A only. Review the [minimum environment](independent-test-environment.md) and [scope boundary](scope-boundary.md) first.

After an independently accepted read-only `plan-isolated`, a separate approval of its exact private hash permits `begin-isolated`, `prepare-isolated`, a controlled fresh parent-console logon and `verify-isolated`. The expected Stage A result is `StageAValidated` with positive WTS no-child evidence. `StageAQueryUnknown`, including persistent error 1168, cannot advance. Keep the target isolated, do not restore the feature between stages, and preserve the same private journal. All mutating commands require their own explicit authorization; this document grants none.

## Separate Stage B decision

From the same tested source and already elevated same-account physical or VMConnect Basic guest console, recheck `status`, the read-only feasibility inventory, console protocol 0, child absence, original network fingerprint, RDP denied policy, stopped `TermService` and absent RDP listeners. A second local observer must be available to watch the actual parent and child desktops. Stage B approval must name the exact plan hash and authorize **one** local loopback ActiveX connection; Stage A approval is insufficient.

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe approve-b-isolated <APPROVED_STAGE_A_PLAN_HASH> I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe connect-once-isolated I-CONFIRM-PHYSICAL-ISOLATION
```

`approve-b-isolated` rereads the exact no-child, parent, feature, RDP and strict network state before recording `ReadyConnect`. `connect-once-isolated` durably records `Connecting` before ActiveX, uses `localhost` and `ConnectToChildSession`, supplies no password, and never retries an uncertain connection. The viewer remains open for interaction. Periodic read-only strict-isolation, listener, service, parent and exact-child checks abort it on drift; these checks are not atomic, so the observer must watch the physical link as well.

While the viewer is open, record the parent ID and exact associated child ID plus WTS logon generation privately. Type or click in harmless unsaved windows on each desktop in alternation; return to the parent, minimize and restore the viewer, and verify both desktops remain independently interactive. Do not mark acceptance from an ID alone. Close only the viewer window. If `status` then shows `Connected` with the same child and interaction was observed, record that human observation:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe confirm-interaction-isolated <CHILD_ID>:<LOGON_TIME> I-CONFIRM-PHYSICAL-ISOLATION I-OBSERVED-INDEPENDENT-DESKTOP
```

After separate exact-child teardown approval, while isolation and identity still match:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe end-child-isolated <CHILD_ID>:<LOGON_TIME> I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe reconnect-check I-CONFIRM-PHYSICAL-ISOLATION
```

Only `ReconnectReady=True`, positive child absence, restored original feature, denied RDP policy, stopped `TermService`, absent listeners and unchanged infrastructure support restoring that **test target's** original network connection after independent review. A checkpoint adds a VM rollback option but does not prove application restoration. Do not publish raw inventory or the plan hash.

## Failure and reviewed recovery

If the viewer closes unexpectedly, the process fails, network isolation changes, or a listener appears, keep the target offline; do not call `connect-once-isolated` again. Read `status` and take a private inventory. A `Connecting` journal with a durably recorded exact child can be moved to `OutcomeUnknown` only after the same isolation and identity are reverified:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe reconcile-connection-isolated I-CONFIRM-PHYSICAL-ISOLATION
```

With a separately reviewed recovery decision, `end-child-isolated-reviewed <CHILD_ID>:<LOGON_TIME> I-CONFIRM-PHYSICAL-ISOLATION` may end **only** the independently reidentified child while strict isolation and its original network fingerprint, account, parent, denied RDP policy and complete firewall observation still pass. It can handle a changed listener but cannot declare the interaction successful or clear that exposure. If isolation or child identity is unknown, perform no destructive child action. Never substitute a guessed ID or generic logoff.

After positive child absence, `restore-isolated-reviewed I-CONFIRM-PHYSICAL-ISOLATION` requires separate acknowledgement for ambiguous feature or network deviation. A feature restored with unexpected `TermService` or listener state remains `Conflict`; `reconnect-check` must stay false. Use a separately reviewed physical-console diagnosis and exact restoration of the unexpected service/listener difference, then rerun original-state assessment. Do not stop an unidentified service or process, alter firewall rules, reconnect a network, delete the journal or repeat a feature write to force success.
