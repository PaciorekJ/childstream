# Proposed first physical qualification — unexecuted

**REVIEW-ONLY QUALIFICATION KIT — LIVE EXECUTION NOT AUTHORIZED.**

This sequence requires a later identified Windows parent/child context,
separately approved feature/session and controller effects, and a review of the
installed ViGEmBus graph and version. It does not authorize execution itself.
Preserve protected workloads and native Sunshine/VDD. Do not restart a shared
driver or use another application as an observer.

1. Establish an exact child session using the separately qualified Stage A/B
   process. Record parent and child session IDs and WTS logon times. Confirm
   installed ViGEmBus version and that the pinned client can create one X360
   target. If the PnP graph or child relationship is ambiguous, stop.
2. Start the feeder within the exact child session. It creates one neutral
   target, records a private run ID and pinned XInput user index, and holds
   explicit reports. Creation may already expose neutral state. Identify all
   present target nodes under the unique ViGEmBus interface. A reused serial
   or identity is a stop.
3. Start `--observe parent-pre RUN_ID 600` in the exact parent session **before
   assignment**; it waits for the one-shot helper pipe and sends READY only
   after its first sample. Keep it polling across assignment. Run `--focus` for a kit-owned parent
   window for translated keyboard/navigation observations. Actions outside that
   window remain outside the kit's coverage.
4. Under a **separate** one-shot elevation approval, run assignment by exact
   run ID from the parent session. It reads original `DEVPKEY_Device_SessionId`
   type and value, persists them, assigns the exact target nodes to the child
   session and reads each back. A failed, partial, or conflicted assignment
   leaves the report gate closed and requires exact-owned recovery review.
5. Start `--observe parent-fresh RUN_ID 600` in the parent and `--observe child
   RUN_ID 600` in the child. Each sends READY after the first sample. If any
   observer is missing, late, exits, or has an identity mismatch, stop; a
   pre-arm abort removes the exact target and attempts to restore its original
   non-present properties. After a **separate explicit arm**, submit
   A/B/A/neutral once at 400 ms per state and retain neutral for its full
   observation window before removal. Save monotonic phase start/end ticks and
   observer summaries. Compare positive attributable child reception
   with the continuously polling parent and fresh parent. Vary only kit-owned
   window focus for translation checks. A preopened raw HID handle case is not
   implemented because a supported target interface path and safe exact
   handle-to-node attribution are not yet established; review this before any
   comprehensive isolation claim.
6. Parent report or translated action is FAIL for the tested route. Missing
   child reception, ambiguous target/slot, observer failure, absent translated
   coverage, or changed session/device identity is INCONCLUSIVE. Property
   readback alone proves only configuration. No XInput-only result proves all
   Windows input paths.
7. Stop feeder submissions, remove only its target, verify absence, then use
   recorded exact-node state to reconcile any non-present property residue.
   If a node stays present, feeder identity is uncertain, removal fails,
   readback disagrees, or the helper was interrupted before its in-memory
   original state could be used, retain the restriction and stop for separately
   reviewed recovery. The same-user run file alone cannot authorize a write.

Same-target reconnect currently has a synthetic method only and **is not an
executable physical test in this kit**. A new target, new
child logon generation, or second controller requires a separate qualification
case; admission does not carry across those boundaries. The kit never changes
global input settings, patches processes, installs drivers, or enables
production controller injection.
