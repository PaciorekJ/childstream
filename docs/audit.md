# ChildStream architecture and security audit

Audited 2026-10-13 from `d41693eb27691516e96df42a05396f1dfe3bd17c` (`PaciorekJ/childstream`, `master`). The checkout was clean; its local `origin/master` and GitHub's `PaciorekJ/childstream` and parent `mattxslv/childstream` `master` all pointed to that SHA. Local Git could not resolve github.com, so remote identity and head were checked through the GitHub connection. Work is on `codex/hardened-foundation`.

## Architecture and evidence boundary

The design uses a Windows child session attached to an existing parent session through the RDP ActiveX control. Microsoft documents one active connected child session at a time, automatic logon in the usual case, no child lock screen, and termination when the parent session terminates. The API is supported starting with Windows 8, but that is not proof of operation on Windows 11 Pro build 26200 with this GPU, display driver, games, audio, or controllers. [Microsoft child sessions](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions).

`ConnectToChildSession` redirects the control to a local child session. It does **not** prove that the systemwide `fDenyTSConnections=0` change is necessary. That value enables ordinary Remote Desktop connections, and the legacy installer made that change without testing a narrower configuration. The RDP listener requirement is a live-system question; do not reopen external RDP as a convenience. [Microsoft ActiveX property](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings-property), [Microsoft RDP setting](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections).

The child is an **interactive desktop boundary**, not a security boundary. It uses the same Windows user account as the parent and can access that account's files and resources. Its separate input focus does not imply privilege or file isolation. Microsoft documents automatic child logon except for smart-card logon or a parent logon preceding child-session enablement. The previous mandatory password prompt and DPAPI persistence were therefore based on an incorrect general assumption. DPAPI CurrentUser also permits any process running as that user to decrypt the value. [Microsoft child sessions](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions), [DPAPI scope](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dpapidataprotector.scope?view=netframework-4.8.1).

The old flow was: compile `ChildStream.exe`; enable child sessions; enable general RDP; change `DWMFRAMEINTERVAL` and `RemoteDesktop_SuppressWhenMinimized`; download the latest portable Sunshine with no hash; overwrite portable Sunshine config; add program-wide inbound firewall allow on every profile; add an all-users Startup hook; create a desktop shortcut. At child logon the hook classified every non-console session as a child and elevated Sunshine with `RunAs`. The launcher stored the Windows password in `cred.bin`, passed it to RDP ActiveX, retried viewer connection, and used username matching in `qwinsta` output to call `logoff`. Closing the viewer left the Windows session alive but removed its display. There is no game, audio, controller, NVENC, or uninstall implementation in the repository.

The feature branch removes credential persistence from the launcher. Legacy `cred.bin` cleanup is an explicit `-resetpass` action with path display, confirmation, and post-delete verification; ordinary startup leaves it alone. The launcher binds the parent-associated child ID and its WTS session logon time while connected, then rechecks both immediately before `WTSLogoffSession`. Manual and automatic reconnect use the same terminal-state guard. Session query and logoff are separate API calls, so an identifier-reuse race cannot be eliminated or claimed mathematically impossible. The `-enable` command and legacy autostart script fail closed. It does **not** launch Sunshine, install the system, or prove live behavior. [Microsoft child ID](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsgetchildsessionid), [Microsoft session information](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w), [Microsoft logoff](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtslogoffsession).

## Security risks

Severity describes consequence; likelihood and exploitability are estimates from source, not a penetration test. Operational impact identifies what can fail even without an attacker.

| Risk | Severity | Likelihood / exploitability | Operational impact | Disposition |
| --- | --- | --- | --- | --- |
| General RDP enabled by `fDenyTSConnections=0` | High | Medium / network dependent | Enlarged remote logon surface; can conflict with existing policy | New setup does not change it; verify requirement on an isolated test host |
| Broad Sunshine inbound allow on all profiles and ports, with admin UI potentially LAN accessible | High | Medium / any reachable peer | Host control and pairing exposure | New setup creates no rule; future rules need exact ports, remote addresses, profile, and admin UI localhost restriction |
| Persisted Windows account password in DPAPI CurrentUser file | High | Medium / same-user code or file access | Credential theft or password rotation failure | New launcher neither reads nor writes it; explicit local cleanup reports absent/present/inaccessible/failure |
| Username substring session selection for `logoff` | Critical | High / local interaction or matching session name | Unrelated session and unsaved work lost | Replaced with parent-associated ID plus logon-time check; query/logoff race remains |
| All-users Startup hook uses `non-console == child` | High | Medium / other RDP user logon | Runs portable Sunshine in unrelated sessions | No longer installed; legacy hook still needs manual review/removal |
| Elevated Sunshine via `Start-Process -Verb RunAs` | High | Medium / remote stream client once paired | Paired client can interact with elevated desktop; UAC prompt may stall startup | Not adopted as a safe default; privilege need and threat boundary require live review |
| Unpinned latest ZIP and unchecked extraction | High | Medium / compromised or changed distribution | Arbitrary executable runs | Download removed from setup path; future release needs fixed version and independently checked digest/signature |
| Overwritten `sunshine.conf` | Medium | High / repeated setup | Existing pairing and settings can be lost | New setup does not write it; future migration must preserve bytes or use an explicit separate config |
| Same-account child access to physical-session resources | High | High / inherent after game or client compromise | No file or account isolation | Explicit accepted architecture limit; use a separate Windows account if security isolation is required |
| No exact rollback journal | High | High / partial install | RDP, registry, rule, hook, or shortcut may persist | New setup blocks apply; inventory and manual recovery below |
| Viewer disconnect/reconnect coupled to display lifetime | Medium | High / normal client interruption | Black or absent stream while games remain | Launcher retains child on transient disconnect; display continuity needs live validation |

Sunshine's current documentation lists a LAN-allowed web UI by default, optional bind address, configurable port family, and optional automatic Steam audio driver installation. Those defaults must be evaluated for the **pinned version actually used**. [Sunshine configuration](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html). Elevated process input behavior is governed by Windows integrity levels/UIPI; elevating Sunshine trades an input-compatibility problem for a larger privilege boundary. [Microsoft integrity model](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).

## Functional gap matrix

| Operation | Current implementation | Gap / likely failure | Owner |
| --- | --- | --- | --- |
| Create child session | ActiveX `ConnectToChildSession`, automatic parent authentication | Build 26200 and RDP prerequisite unverified; smart-card/old parent logon exception | Launcher + acceptance |
| Reconnect existing child | Offline-tested state machine; timer and manual action share identity guard | Viewer display and real ActiveX timing need live evidence | Launcher |
| Detect session health | ActiveX `Connected`, parent-associated child ID, and WTS logon time | No Sunshine/game health; WTS query availability unverified on target | Launcher + diagnostics |
| Start Sunshine | Not implemented; legacy autostart entry point throws | Exact child startup and least privilege need design and live evidence | Session agent, future |
| Stop Sunshine | None | Must not equate stream stop with game sign-out | Session agent, future |
| Configure resolution/refresh | `display.cfg` width/height/scale; `DWMFRAMEINTERVAL` tweak in legacy setup | Refresh and actual streamed geometry unmeasured; tweak rollback absent | Launcher + acceptance |
| Validate NVENC | None | GPU presence does not prove encoder selection or FPS | Diagnostics + acceptance |
| Controller forwarding | Sunshine default behavior only | Driver, Moonlight mapping, two-controller focus unproven | Sunshine integration + acceptance |
| Separate game audio | No routing configuration | Shared default endpoint or Steam driver side effects | Audio integration + acceptance |
| Steam Big Picture launch | None | Manual only | App catalog, future |
| Steam game launch | None | Manual only; account/DRM conflicts possible | App catalog, future |
| Graceful game closure | None | Session sign-out kills apps | Lifecycle, future |
| Session sign-out | Explicit confirmation, parent-associated ID plus logon time, terminal state on unknown outcome; offline-tested | WTS query/logoff is not atomic; live race/error behavior untested | Launcher |
| Credential removal | Explicit `-resetpass`, exact local path, consent, and verified removal; fake-file tested | Copies outside the executable directory need manual ownership review | Launcher + operator |
| Complete rollback | None for prior setup; new setup blocked | Original values were not recorded; cannot infer them | Installer, future |
| Diagnostics and recovery | Read-only `diagnose.ps1` inventory | NVENC, audio stream, and child feature API require live probes | Diagnostics, future |

## Persistent mutations in the legacy installer and recovery

The old installer recorded **none** of the original values. Never assume the former value was the Windows default. Before removing anything, record the current state and determine whether ChildStream actually owns it. The native Sunshine/VDD installation is outside this cleanup.

| Old mutation | Exact safe recovery condition |
| --- | --- |
| `WTSEnableChildSessions(true)` | Disable only if a pre-install record proves it was previously disabled and no other application now relies on it. The current branch has no transaction journal. |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections=0` | Restore original DWORD or absence only from a known pre-install backup; inspect policy, listener, firewall, and other RDP users first. |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\DWMFRAMEINTERVAL=8` | Restore original DWORD/type or remove only if known absent. |
| `HKCU:\Software\Microsoft\Terminal Server Client\RemoteDesktop_SuppressWhenMinimized=2` | Restore original value/type or absence for the installing user; remove newly created key only if empty and known installer-created. |
| Portable `Sunshine/` and `sunshine.conf` | Preserve all existing files. Remove only verified installer-created files after exporting pairing/config state; the old script may have overwritten original config irreversibly. |
| Firewall rule display name `ChildStream Sunshine` | Remove only after confirming exact rule identity, program path, and absence of unrelated owner. Display name alone is insufficient. |
| All-users `childstream-sunshine.cmd` | Inspect file content and metadata; remove only if it is the ChildStream-created hook and no other process owns it. |
| Desktop `Child Session.lnk` | Inspect target and user changes; remove only when it still targets this checkout. |
| `cred.bin` | `ChildStream.exe -resetpass` inspects only its local legacy path and requires confirmation before deletion. Check any copies/backups separately and do not remove unowned files. |

## Dependency-ordered plan

### PR #1 lifecycle correction evidence (offline only)

The launcher starts in `NoChild`, moves through `Connecting` to `Connected`, and moves to `ViewerDisconnected` only when the same parent-associated child ID and WTS logon time still exist. Both manual and timer reconnect enter `Reconnecting` through one guard. An absent child becomes `Terminated`; changed/invalid identity or a failed identity query becomes `Error`. A confirmed user sign-out passes through `SignOutRequested` and `SignOutOutcomeUnknown` before `Terminated` on a successful synchronous logoff. A false return or exception leaves `SignOutOutcomeUnknown`; neither it nor `Terminated` or `Error` permits reconnect. The fake API suite covers these transitions and destructive-operation guards, but cannot prove native API availability, ActiveX timing, or the absence of a query-to-logoff race on Windows 11 Pro 26200.

The `WTSINFOEX_LEVEL1_W.LogonTime` generation check is a documented session field, not a username or non-console heuristic. If the query is unavailable or malformed, the launcher fails closed. It reduces ID-reuse exposure but cannot make `WTSLogoffSession` atomic with validation. [Microsoft session information](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w).

The new Windows PR workflow compiles the launcher and executes only offline tests with read-only repository permission. It does not call setup Apply or any host mutation. A green CI run is source evidence, not live child-session, Sunshine, VDD, media, or rollback evidence. The installer remains unimplemented.

1. **Architecture gate:** on a controlled Windows 11 Pro 26200 system, test child connection with Remote Desktop normally denied and no external RDP firewall allowance. Re-logon the parent after enabling the child feature. Record whether the loopback child works. Keep native Sunshine/VDD operational.
2. **Transactional installer:** define exact owned resources and immutable pre-state snapshots, journal each intended operation before applying it, and restore in reverse order after failure. Refuse apply when an existing resource cannot be distinguished from a user-owned one. Test against mocked registry, file, firewall, and child-feature adapters, including repeated apply and interrupted journal recovery.
3. **Pinned portable Sunshine:** choose a version, verify archive provenance and digest, extract to a dedicated directory, preserve any existing portable config byte-for-byte, select a dedicated config path, and verify port conflicts with native Sunshine. Do not install drivers silently.
4. **Session-specific startup and lifecycle:** start Sunshine only after positively identifying the child; keep viewer disconnect, Moonlight disconnect, Sunshine stop, game closure, sign-out, and uninstall as separate operations. Avoid automatic elevation unless an acceptance case proves it is necessary and its trust boundary is accepted.
5. **Network and media:** restrict stream ports to approved TV addresses and network profile; keep admin UI local or explicitly routed for pairing; validate NVENC, audio endpoints, controller devices, resolution, and FPS with actual stream telemetry.
6. **Recovery and release gate:** test install/reinstall/failure/rollback/uninstall on disposable state, then run the live acceptance plan. No deployment or merge until evidence is reviewed.

The first gate is unresolved. The implementation intentionally stops at a fail-closed setup, read-only diagnostics, and launcher safety changes rather than guessing how to enable RDP or creating a persistent Sunshine startup resource.
