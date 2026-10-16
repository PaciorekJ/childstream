# ChildStream

ChildStream is a Windows child-session and portable Sunshine proof of concept for streaming a second interactive desktop to Moonlight. It is **not ready for live installation**. The original setup changed global RDP and firewall state, downloaded an unpinned executable, and had no rollback journal. This branch disables that installer path until its architecture and recovery behavior can be validated.

**Execution target:** The shared development workstation is blocked for Stage A/B under the permanent [scope boundary](docs/scope-boundary.md). ChildStream must not inspect or interrupt unrelated work, Docker Desktop, WSL2, Tailscale or shared networking to make a feasibility plan pass. No independent Windows target is currently available; its [minimum requirements and no-purchase options](docs/independent-test-environment.md) are documented. The next live test belongs on a [separate Windows environment](docs/stage-ab-physical-window.md); no host mutation is authorized by this repository.

Read the [architecture and security audit](docs/audit.md) and [live acceptance plan](docs/live-acceptance.md) before testing on a Windows host. The intended outcome is independent physical and remote interaction with separate capture, input, and audio; none of those hardware claims has been established by this branch.
The [runtime map](docs/product-runtime-map.md) identifies which product classes are actually invoked and which still require connection and live Windows proof.

## Offline work

From PowerShell in the repository root:

```powershell
.\tests\offline.ps1
```

This compiles the standard-user launcher, scoped setup helper, standalone install bootstrap, product runtime and feasibility harness. The suite exercises deterministic logic, temporary owned files, real harmless named pipes and an optional loopback TLS fixture without changing Windows settings. It does not create or connect a child session. Windows CI retains an unsigned candidate ZIP and rendered simulated UI screenshots. Building the feasibility harness or bootstrap authorizes no protected-host execution. The [independent-machine kit](docs/independent-acceptance-kit.md) preserves separate Stage A/B approvals. `scripts/setup.ps1` remains a disabled legacy mutation entry; the normal application now exposes a separately approved protected-file bootstrap. See the [installer foundation](docs/installer-foundation.md) and [product integration state](docs/product-integration.md).

The launcher uses Microsoft's documented automatic child-session authentication from the existing parent session. It does not request or persist the Windows password. Ordinary startup does not delete `cred.bin`. `ChildStream.exe -resetpass` inspects only the regular `cred.bin` beside `ChildStream.exe`, shows its exact path, requests confirmation, and verifies removal; inaccessible, unsafe, and failed states are reported separately. Copies outside that path require manual ownership review. Microsoft documents exceptions for smart-card parent logon and a parent session established before child sessions were enabled. The live behavior on Windows 11 Pro build 26200 still needs verification.

An explicit **End session** action checks the parent-associated child ID and its session logon time against the observed child immediately before `WTSLogoffSession`. Manual and automatic reconnect share the same lifecycle guard. An unknown sign-out outcome, changed child identity, or confirmed termination blocks reconnection. These checks reduce the session-ID reuse risk, but the query and logoff are not atomic; the remaining race requires live review. Closing the viewer does not intentionally sign out the child. The Stage B feasibility viewer stays open for an operator interaction check, but it has not been exercised with a real child and remains separately gated. Child bootstrap, protected installation, optional separately approved LAN Sunshine mode, owned pairing and Steam/game commands are connected in source; actual capture, streaming, controller routing, installed-state rollback and hardware behavior remain unverified. Controller injection stays disabled even if ViGEmBus is present. See the [acceptance matrix](docs/acceptance-matrix.md).

## Source

- `src/ChildStream.cs`: WinForms RDP ActiveX viewer and Windows session adapter.
- `src/ChildSessionLifecycle.cs`: offline-tested connection and sign-out state machine.
- `src/SessionSignOutGuard.cs`: durable, credential-free sign-out intent and explicit absence reconciliation.
- `src/LegacyCredentialCleanup.cs`: explicit, path-scoped legacy credential cleanup.
- `src/InstallerFoundation.cs` and `src/InstallerInventory.cs`: offline transaction engine, typed inventory, and portable package admission contracts.
- `src/FirstRun.cs`, `src/InstallDialog.cs`, `src/ProductInstallProgram.cs`, `src/SetupDialog.cs`, `src/SetupBoundary.cs`, and `src/ChildAgentTaskInstaller.cs`: standard-user shell, separate protected-file bootstrap, scoped feature/LAN setup helper and current-user demand-only task adapter. No helper, install or task operation was run on this workstation.
- `src/PortableSunshine.cs`, `src/PortableExtractionTransaction.cs`, `src/ProductIntegration.cs`, `src/WindowsAudioEndpoints.cs`, `src/ChildRuntimeBootstrap.cs`, `src/ChildAgentRuntime.cs`, `src/WindowsChildAgentOperations.cs`, `src/SunshineIdentityStore.cs`, `src/SunshinePairingTransport.cs`, `src/WindowsSteamDiscovery.cs`, `src/ProductAcceptance.cs`, and `src/WindowsOwnedInstallerHost.cs`: pinned Sunshine package, exact-child process/audio guards, typed agent operations, owned pairing identity and TLS API, Steam/game discovery, and recovery candidates. All physical acceptance remains open.
- `scripts/build-candidate.ps1` and `scripts/verify-candidate.ps1`: unsigned, uninstalled candidate package with committed source blobs, file hashes, license and notice; no Sunshine binary or hardware acceptance claim. The legacy Framework compiler is not deterministic, so verify each build by its own ZIP digest.
- `src/FeasibilityProbe.cs`, `src/WindowsFeasibilityHost.cs`, and `src/FeasibilityProbeProgram.cs`: gated one-session experiment, narrow Windows adapter, and console commands; live execution requires separate approval.
- `scripts/feasibility-inventory.ps1`: read-only, typed Windows 11 Pro feasibility inventory.
- `scripts/diagnose.ps1`: read-only inventory; omits credentials and Sunshine config contents.
- `scripts/childsession-autostart.ps1`: inert guard if a legacy all-users hook still invokes it; the original script is available in Git history for audit.
- `docs/audit.md`: source behavior, risk/gap matrix, mutation inventory, recovery conditions, and prioritized plan.
- `docs/live-acceptance.md`: separate live-system test gate and evidence requirements.

MIT licensed; see [LICENSE](LICENSE).
