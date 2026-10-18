# ChildStream X360 device-session qualification kit

**REVIEW-ONLY QUALIFICATION KIT — LIVE EXECUTION NOT AUTHORIZED.**

This is a separate experimental package. It is not loaded by the ChildStream
application. Production controller injection remains disabled. This kit has
not established that `DEVPKEY_Device_SessionId` prevents parent consumption.

Run `ChildStreamX360Kit.exe` or `ChildStreamX360Kit.exe --help` to read the safe
mode list. Run `ChildStreamX360Kit.exe --self-test` to exercise substituted
Windows/ViGEm effects. These invocations do not enumerate devices or sessions,
connect to the driver, or write a property. The live modes shown by help are
future experiment entry points and require a separately reviewed context and
explicit approval. Do not invoke them on a development workstation.

## Build and identity

From the repository root on Windows, `pwsh -NoProfile -File
scripts/build-x360-qualification-kit.ps1` compiles the managed x64 tool and
runs its synthetic test. On a Windows MSVC x64 builder, add `-BuildNative` to
build the pinned ViGEmClient source and create the ZIP. The ZIP manifest records
the exact Git source SHA, whether the tree was dirty, pinned dependency
revisions, and SHA-256 for each included file. The native client is MIT licensed;
the package includes its license and ChildStream's license. It does not include
or install ViGEmBus, Sunshine, libvirtualhid, or a new privileged service.

The source is reviewed for a single pinned X360 target only. `--feeder` creates
one neutral target and holds **explicit feeder reports** until assignment and
separate arm. The driver can expose neutral state at creation. `--assign` is a
one-shot, separately elevated helper: it verifies the live feeder PID, start
time, image hash, parent/child logon generations, parent-child WTS relationship,
and new target PnP graph; persists prior typed property values before each
SetupAPI write; reads back each exact node. It never writes the bus root.
The expected executable hash is calculated from the helper's **own image**,
not accepted from the same-user run file. Peer process and token session,
account SID, role elevation, creation identity, and both WTS generations are
checked before assignment. Inaccessible identity fails closed. The run file
correlates the one-shot exchange but is not peer authority.
Normal one-shot cleanup restores non-present properties from the helper's
in-memory originals after exact target removal. Interrupted recovery is **not
automated**: the same-user run file is diagnostic evidence, not authorization
to write an arbitrary device property. A protected original-state record and
independent non-present PnP ancestry check are required before a standalone
recovery operation can be qualified. Unresolved residue is a stop condition.

`--observe` polls only the pinned client's reported X360 user index for at most
600 seconds and labels each record `NATIVE-ORIGIN-UNQUALIFIED`. Three separate
observer processes announce readiness over exact-run named pipes after their
first sample. The helper requires parent-pre before assignment and parent-fresh
plus child after assignment, then checks that all three remain present before
the operator's explicit arm. The feeder emits A/B/A/neutral once, dwelling
400 ms on each state (eight nominal 50 ms polls), including neutral before
target removal. Phase boundaries use monotonic ticks and are saved to the run
record. Missing, late, or gapped sampling is inconclusive, never success.
`--focus` opens
a bounded kit-owned parent window and records only navigation key codes delivered
to that window. It does not use a global hook. XInput exposes no held device handle through
`XInputGetState`; a continuously polling parent observer is the preinitialized
consumer. The current observer does not prove a slot-to-PnP relationship or
cover raw HID, GameInput, translated keys outside the kit-owned window, or every broker path. Those are
explicit experiment coverage gaps. A negative XInput result alone is never a
PASS; a positive attributable child result is also required. No automatic
physical-verdict evaluator is included.

The run record lives under the operator's LocalAppData with an owner-only ACL.
It distinguishes native-origin, still-unqualified data from synthetic tests.
It is a recovery record, not a bearer authorization to write arbitrary PnP
properties. The feeder and helper use a same-account named pipe and exact
process challenge, with a ten-minute watchdog. Failure can leave a recorded
property residue; do not guess at ownership or clear a property on a present
device.

The same-target reconnect method is exercised only by synthetic state tests;
the executable kit has **no reconnect command or physical reconnect coverage**.
No XInput-only result qualifies raw HID, GameInput, preopened handles, or
translation paths beyond the kit-owned focus window. Installed-device graph
and late-assignment behavior require later physical qualification.

See `FUTURE-EXPERIMENT.md` for the bounded, unexecuted qualification sequence.
