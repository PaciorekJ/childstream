# Independent Windows acceptance kit

**Target only:** a borrowed/dedicated Windows 11 Pro PC or a no-NIC Generation 2 Windows 11 Pro VM on a separate Hyper-V host. Neither exists yet. The protected development workstation, its virtualization, networking and unrelated workloads are excluded. A VM can prove WTS/session interaction only; physical GPU and Fire TV acceptance require a real gaming PC. This kit does not authorize any mutation. Review the detailed [strict Stage B recovery procedure](strict-isolated-stage-b.md) before asking for an exact-plan approval.

## Read-only qualification

Prepare the target's local console or VMConnect Basic Session Mode, offline-capable sign-in and recovery administrator, original-state snapshot or VM checkpoint, second observer, and a physically no-NIC boundary. Use a licensed Windows 11 Pro installation; prefer build 26200 and at least four vCPUs/cores, 8 GB RAM and 64 GB available disk for the API test. The target must have no protected workloads. Keep the source and report local, not in public CI artifacts.

From the source root in an already elevated **same-account console process**, these commands are read-only except test fixture files under `tests/.artifacts`:

```powershell
git rev-parse HEAD
git status --short
pwsh -NoProfile -File .\tests\offline.ps1
pwsh -NoProfile -File .\scripts\feasibility-inventory.ps1
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe plan-isolated I-CONFIRM-PHYSICAL-ISOLATION
```

The final command must print `Posture=NetworkIsolated NetworkIsolationAccepted=True RdpPolicyDenied=True` with a `Plan=` hash. Independently inspect the private inventory for physical console protocol 0, original child feature and RDP/`TermService`/listener/firewall/display state, positive no-child status and complete isolation. A rejected or unknown plan has no journal or feature write: stop, compare the original state and restore only the independent target's operator-controlled isolation state after confirming there was no mutation. Do not use `reconnect-check` before a journal exists.

## Separately approved Stage A

Only after a human approval names the exact private hash, target and one feature/fresh-logon cycle, paste that hash when prompted. The prompt does not itself grant approval. Maintain the physical no-NIC boundary throughout.

```powershell
$approvedHash = Read-Host 'Paste the separately approved exact Stage A plan hash'
if ($approvedHash -notmatch '^[0-9a-f]{64}$') { throw 'Invalid approved hash' }
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe begin-isolated $approvedHash I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe prepare-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

Require `AwaitFreshParent` and no RDP/service/listener/network deviation. After a **separate fresh-logon authorization**, sign out only the test parent through Windows UI, sign in offline to the same account at the actual console, and use an already elevated same-account process:

```powershell
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe verify-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

Require `StageAValidated` and a positive WTS no-child result. Error 1168, unknown feature, listener drift or session ambiguity is a stop; keep the target offline and its private journal. Do not rerun `prepare-isolated` to force a result.

## Separately approved Stage B and exact teardown

Only after reviewing the positive Stage A journal and obtaining separate approval for **one** loopback interaction, use the same exact private hash:

```powershell
$approvedHash = Read-Host 'Paste the separately approved Stage B plan hash'
if ($approvedHash -notmatch '^[0-9a-f]{64}$') { throw 'Invalid approved hash' }
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe approve-b-isolated $approvedHash I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe connect-once-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe status
```

Keep the viewer open. Physically interact with parent and child desktops in alternation and while parent has focus; record exact child ID and WTS logon generation. After closing only the viewer, and only if interaction was truly observed:

```powershell
$exactChild = Read-Host 'Paste the independently verified child ID:logon generation'
if ($exactChild -notmatch '^\d+:\d+$') { throw 'Invalid child identity' }
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe confirm-interaction-isolated $exactChild I-CONFIRM-PHYSICAL-ISOLATION I-OBSERVED-INDEPENDENT-DESKTOP
```

The following phase requires **separate exact-child teardown approval**. After approval, re-enter the independently checked identity, then restore and assess before reconnecting the independent target:

```powershell
$exactChild = Read-Host 'Paste the separately approved exact child ID:logon generation'
if ($exactChild -notmatch '^\d+:\d+$') { throw 'Invalid child identity' }
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe end-child-isolated $exactChild I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe restore-isolated I-CONFIRM-PHYSICAL-ISOLATION
.\tests\.artifacts\ChildStreamFeasibilityProbe.exe reconnect-check I-CONFIRM-PHYSICAL-ISOLATION
```

Reconnect only if `ReconnectReady=True` and each original-state field passes independent review. On a changed listener, `TermService`, feature, network, child identity or journal, leave the target offline and follow the reviewed recovery path in [strict Stage B](strict-isolated-stage-b.md); no generic logoff, service stop or firewall edit is authorized. Keep raw evidence and hashes private.

## Later physical streaming acceptance

After Stage B, use a separately authorized physical gaming PC and reviewed LAN posture to test child display and GPU access before enabling a Sunshine stream. The source pins the Sunshine lite release and builds a loopback-only child config; LAN access and firewall scope are **not** approved by Stage A/B. Record exact child and process IDs, selected Sunshine display GUID, NVENC log, Moonlight 1920×1080/60 measurements, dropped frames, Fire TV connection, two controllers with parent foreground focus, separate PC/TV audio, Steam Big Picture and Minecraft Dungeons app `1672970`, disconnect/reconnect and exact restoration. A VM-only result cannot satisfy these rows. See [product integration](product-integration.md) and [acceptance matrix](acceptance-matrix.md).
