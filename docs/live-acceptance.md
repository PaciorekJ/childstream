# First live-system acceptance plan (not yet executed)

Product target attributes: Windows 11 Pro build 26200, Ryzen 7 5800X, RTX 3060, 32 GB RAM, Acer 3440x1440 primary, Fire TV Moonlight, Xbox Series Bluetooth controller, Xbox One USB controller. Preserve the current native Sunshine/VDD setup and its working fallback. **This is an acceptance specification, not an executable plan for the protected workstation.** The permanent [scope boundary](scope-boundary.md) blocks a test there that inspects or interrupts unrelated work or shared services. First prove child-session behavior in a [separate Windows environment](stage-ab-physical-window.md); later target-host acceptance requires a coexistence and RDP-containment design plus separate authorization.

## Before any mutation

1. Record OS build, GPU driver, physical display topology/primary/refresh, active Windows sessions, native Sunshine/VDD version/config/process/ports, RDP listener and firewall state, child-session state, target registry values with types/presence, existing portable Sunshine config and hash, Startup hook, desktop shortcut, and all matching firewall rule identifiers. Export a redacted inventory without credentials or pairing secrets. Capture an appropriate system restore or equivalent recovery option.
2. Run `powershell -NoProfile -File .\scripts\setup.ps1 -Mode Validate` only after reviewing the diagnostic fields. It is read-only. `Apply`, `Recover`, and `Uninstall` are currently blocked.
3. Choose an isolated, approved test window and define abort criteria: physical console disruption, native Sunshine/VDD failure, unexpected RDP exposure, wrong-session process launch, or any untracked host mutation.
4. Confirm the PR's offline Windows CI passed at the exact candidate SHA. Treat this as compile and fake-API evidence only. Inspect any legacy `cred.bin` by path and ownership; `-resetpass` is a separate, explicit deletion action and ordinary startup does not remove it.

## Architecture gate

1. With ordinary remote RDP denied and its inbound firewall closed, use a separately reviewed, reversible manual procedure to enable only the documented child-session feature. Sign out/in the parent if required by Microsoft's authentication exception. Attempt `ConnectToChildSession` without a supplied password. Record success/failure, child ID, console ID, listener state, and error codes. Revert the child feature if the test cannot proceed.
2. If loopback fails, investigate exact dependency and Microsoft policy. If opening ordinary RDP is required, document the exposure and test a narrow local-only listener/firewall approach before any production recommendation. Do not silently set `fDenyTSConnections=0`.
3. Verify the physical Acer stays primary at 3440x1440 and remains independently interactive while the child viewer has focus and while it is minimized.

## Functional evidence

| Claim | Required evidence |
| --- | --- |
| Independent child desktop | Parent and child session IDs, simultaneous keyboard/mouse activity and focus observations, no physical display primary change |
| Sunshine child capture | Exact Sunshine process/session ID and config path, stream target showing child not console, connection/disconnection recovery |
| NVENC and 1080p/60+ | Sunshine encoder log/telemetry naming NVENC, Moonlight resolution/FPS and sustained game run, dropped-frame measurements |
| Minecraft Dungeons | Launch and play in child while local mouse/keyboard continues on parent; record Steam/account/DRM behavior |
| Controllers | Map Bluetooth Xbox Series and USB Xbox One independently in intended client/host roles; verify inputs do not leak between desktops |
| Audio separation | Play distinct audio on both desktops, inspect captured endpoints, verify PC and TV do not hear the other's stream unexpectedly |
| Lifecycle | Viewer transient disconnect and manual/automatic reconnect of the same child; sign-out success, failure, and unknown outcome tested separately from Moonlight disconnect, Sunshine stop, graceful game exit, and parent termination |
| Precise sign-out | Record parent ID, associated child ID and WTS logon time before the action; recheck immediately before logoff; verify unrelated console and any other RDP session survive; retain the query/logoff race as an explicit residual risk |
| Rollback | Failure injection and uninstall restore every recorded registry value/type/absence, firewall identity, startup/shortcut ownership, and native Sunshine/VDD functionality |

Keep a result ledger with source SHA, installer/package hashes, command, privilege context, timestamps, expected/actual states, logs with secrets removed, and pass/fail/blocked for each row. A compile or synthetic test result does not satisfy the live claims.

## Current installation and rollback procedure

There is **no authorized safe apply procedure yet**. The prior setup had no original-state journal; `scripts/setup.ps1` now defaults to validation and rejects `Apply`, `Recover`, and `Uninstall` before changes. Do not execute the old script from Git history. Use the mutation inventory in `audit.md` to inspect legacy state and recover only resources whose prior state and ownership can be proven. If those facts are unavailable, leave the resource in place and record the unresolved recovery action; guessing a Windows default is not rollback.
