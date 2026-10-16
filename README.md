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

This compiles the launcher, installer foundation, product integration candidates and one-session feasibility harness, then runs deterministic logic and fault-injection tests. It also tests real create/rollback behavior for **temporary owned fixture files**, without changing Windows settings. The offline suite does not create or connect a child session. The restricted Windows pull-request workflow runs the suite and retains an unsigned candidate ZIP. The feasibility harness is **not authorized to run on the protected host** by building it; the [independent-machine kit](docs/independent-acceptance-kit.md) preserves separate Stage A/B approvals. `scripts/setup.ps1 -Mode Validate` runs read-only host diagnostics only when that read is authorized. `Apply`, `Recover`, and `Uninstall` deliberately fail before modifying the host. See the [installer foundation](docs/installer-foundation.md) and [product integration state](docs/product-integration.md).

The launcher uses Microsoft's documented automatic child-session authentication from the existing parent session. It does not request or persist the Windows password. Ordinary startup does not delete `cred.bin`. `ChildStream.exe -resetpass` inspects only the regular `cred.bin` beside `ChildStream.exe`, shows its exact path, requests confirmation, and verifies removal; inaccessible, unsafe, and failed states are reported separately. Copies outside that path require manual ownership review. Microsoft documents exceptions for smart-card parent logon and a parent session established before child sessions were enabled. The live behavior on Windows 11 Pro build 26200 still needs verification.

An explicit **End session** action checks the parent-associated child ID and its session logon time against the observed child immediately before `WTSLogoffSession`. Manual and automatic reconnect share the same lifecycle guard. An unknown sign-out outcome, changed child identity, or confirmed termination blocks reconnection. These checks reduce the session-ID reuse risk, but the query and logoff are not atomic; the remaining race requires live review. Closing the viewer does not intentionally sign out the child. The Stage B feasibility viewer stays open for an operator interaction check, but it has not been exercised with a real child and remains separately gated. Sunshine package/configuration, distinct LAN port-family planning, process ownership and file recovery candidates are implemented in source. Controller injection stays disabled even if ViGEmBus is present. Child bootstrap, live Sunshine capture, game/audio/controller routing, normal installer orchestration and full hardware rollback remain unfinished or unverified. See the [acceptance matrix](docs/acceptance-matrix.md).

## Source

- `src/ChildStream.cs`: WinForms RDP ActiveX viewer and Windows session adapter.
- `src/ChildSessionLifecycle.cs`: offline-tested connection and sign-out state machine.
- `src/SessionSignOutGuard.cs`: durable, credential-free sign-out intent and explicit absence reconciliation.
- `src/LegacyCredentialCleanup.cs`: explicit, path-scoped legacy credential cleanup.
- `src/InstallerFoundation.cs` and `src/InstallerInventory.cs`: offline transaction engine, typed inventory, and portable package admission contracts.
- `src/PortableSunshine.cs`, `src/PortableExtractionTransaction.cs`, `src/ProductIntegration.cs`, `src/WindowsAudioEndpoints.cs`, `src/ChildRuntimeBootstrap.cs`, `src/ProductAcceptance.cs`, and `src/WindowsOwnedInstallerHost.cs`: pinned Sunshine package, exact-child configuration and agent protocol, process/collision and audio selection guards, archive and owned-file recovery candidates, and physical acceptance gates. Task registration and live agent startup remain disabled.
- `scripts/build-candidate.ps1` and `scripts/verify-candidate.ps1`: repeatable unsigned, uninstalled candidate package with source and file hashes, license and notice; no Sunshine binary or hardware acceptance claim.
- `src/FeasibilityProbe.cs`, `src/WindowsFeasibilityHost.cs`, and `src/FeasibilityProbeProgram.cs`: gated one-session experiment, narrow Windows adapter, and console commands; live execution requires separate approval.
- `scripts/feasibility-inventory.ps1`: read-only, typed Windows 11 Pro feasibility inventory.
- `scripts/diagnose.ps1`: read-only inventory; omits credentials and Sunshine config contents.
- `scripts/childsession-autostart.ps1`: inert guard if a legacy all-users hook still invokes it; the original script is available in Git history for audit.
- `docs/audit.md`: source behavior, risk/gap matrix, mutation inventory, recovery conditions, and prioritized plan.
- `docs/live-acceptance.md`: separate live-system test gate and evidence requirements.

MIT licensed; see [LICENSE](LICENSE).
