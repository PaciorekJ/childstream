# External-path-only rehearsal with Docker and WSL running

**Prepared, not authorized.** This is a separately approved, operator-controlled read-only diagnostic window. It does not run `plan-boundary`, create a journal, stop any workload, enable the child feature, sign out, or establish Stage A acceptance. It answers whether an unmatched addressed virtual path remains after external links are severed. Active Docker and WSL are expected to keep `GuestPath=Fail`; no result here can approve Stage A.

## Before disconnection

Use the same account in an already elevated physical-console PowerShell 7 window. Keep this file and the tested checkout available offline. Record the exact source SHA and require a clean tree. Independently record the currently connected Wi-Fi/Ethernet, radio, Bluetooth PAN, USB/cellular and VPN-underlay state, plus the operator and second observer. Confirm that a short external-network outage will not interrupt an active deployment, transfer, replication or application write that its owner cannot recover; keeping containers running does not make a network outage harmless. The private workload matrix in `%LOCALAPPDATA%\ChildStream-Workload-Preflight` is for later owner review; do **not** stop its projects for this rehearsal.

Use the already restricted local preflight directory. Its ACL must grant access only to this account, SYSTEM and Administrators. If the directory or ACL check fails, stop and prepare a restricted local evidence location before disconnecting; never save the raw capture in Git, CI or a public folder.

```powershell
git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Checkout identity is unavailable.' }
$dirty = @(& git status --porcelain=v1)
if ($LASTEXITCODE -ne 0 -or $dirty.Count) { throw 'Checkout is not clean.' }
$principal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use an already elevated, same-account physical console.'
}
$private = Join-Path $env:LOCALAPPDATA 'ChildStream-Workload-Preflight'
$allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
$acl = Get-Acl -LiteralPath $private -ErrorAction Stop
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed -or
    @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
      Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $allowed }).Count) {
    throw 'Private evidence directory ACL is not restricted.'
}
function Assert-PrivateFile([string]$path) {
    $fileAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
    if (@($fileAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
      Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $allowed }).Count) {
        [IO.File]::Delete($path)
        throw 'Private capture file ACL is not restricted.'
    }
}
function Assert-NoProbeJournal {
    foreach ($name in @('probe.journal','probe.journal.new','probe.lock')) {
        if (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA "ChildStream-Feasibility\$name")) {
            throw 'Existing probe journal or lock requires separate transaction review.'
        }
    }
}
$tag = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N')
$beforePath = Join-Path $private "external-connected-$tag.json"
$beforeRaw = & pwsh -NoProfile -File .\scripts\network-boundary-diagnostic.ps1 -IncludeInventory
if ($LASTEXITCODE -ne 0) { throw 'Connected read-only capture failed.' }
$before = ($beforeRaw -join "`n") | ConvertFrom-Json -ErrorAction Stop
if ($before.HostMutation -ne $false -or $before.Boundary.DiagnosticOnly -ne $true -or
    $before.Boundary.StageAPlanAuthorized -ne $false -or
    $before.Inventory.Sessions.ProcessSessionId -ne $before.Inventory.Sessions.ActiveConsoleSessionId -or
    $before.Inventory.Sessions.CurrentProtocol.State -ne 'Accessible' -or
    $before.Inventory.Sessions.CurrentProtocol.Value -ne 0 -or
    $before.Inventory.ChildFeature.State -ne 'Accessible' -or
    @($before.Boundary.Predicates | Where-Object Id -eq 'rdp-baseline-closed')[0].Verdict -ne 'Pass') {
    throw 'Unsafe, incomplete, or non-console baseline.'
}
Assert-NoProbeJournal
[IO.File]::WriteAllText($beforePath, ($beforeRaw -join "`n"), [Text.UTF8Encoding]::new($false))
Assert-PrivateFile $beforePath
```

The connected capture records the original child-feature, RDP policy, `TermService`, listeners, firewall and topology observations. Check the saved file ACL before proceeding. A failed or incomplete baseline is No-Go.

## Operator-controlled offline observation

Only after a **separate approval for this rehearsal**, the operator and second local observer disconnect all external paths: unplug Ethernet, turn the Wi-Fi radio off rather than only leaving one SSID, and verify Bluetooth PAN, cellular/USB tether and other physical uplinks are inactive. Inspect any VPN underlay. Do not stop Docker/WSL/Tailscale, disable a virtual adapter, edit a switch/bridge, or change firewall or RDP settings. If a radio or alternative uplink cannot be verified severed, do not assert `-OperatorConfirmedPhysicalSeverance`; record the reason and end the attempt.

While still at the same console with Docker and WSL running:

```powershell
$offlinePath = Join-Path $private "external-offline-$tag.json"
$offlineRaw = & pwsh -NoProfile -File .\scripts\network-boundary-diagnostic.ps1 `
    -OperatorConfirmedPhysicalSeverance -IncludeInventory
if ($LASTEXITCODE -ne 0) { throw 'Offline read-only capture failed.' }
$offline = ($offlineRaw -join "`n") | ConvertFrom-Json -ErrorAction Stop
if ($offline.HostMutation -ne $false -or $offline.Boundary.DiagnosticOnly -ne $true -or
    $offline.Boundary.StageAPlanAuthorized -ne $false -or
    $offline.Inventory.Sessions.ProcessSessionId -ne $offline.Inventory.Sessions.ActiveConsoleSessionId -or
    $offline.Inventory.Sessions.CurrentProtocol.Value -ne 0) { throw 'Unexpected diagnostic or console state.' }
[IO.File]::WriteAllText($offlinePath, ($offlineRaw -join "`n"), [Text.UTF8Encoding]::new($false))
Assert-PrivateFile $offlinePath
$offline.Boundary.Predicates |
    Where-Object { $_.Condition -in @('External','GuestPath','RdpExposure') } |
    Select-Object Condition,Id,Verdict,Evidence | Format-Table -Wrap
$offline.Boundary.Conditions | Format-List
```

Inspect `network-inventory-complete`, `physical-uplinks-down`, `physical-route-link-corroboration`, `switches-have-no-external-bridge`, `hyperv-host-port-graph`, **`virtual-paths-attributed`**, and `nat-bridge-forwarding-mapped` individually. An `External=Fail/Unknown` caused by a different predicate must not obscure the virtual-path verdict. Map any reported ifIndex to the private `Observation.Adapters.Items` and its addresses/routes; a name such as Tailscale is evidence to investigate, not an allow rule. `virtual-paths-attributed=Unknown` means that path would still block a later v5 plan. `Pass` means only that this predicate found no unmatched active path at this instant. Active guests, HNS endpoints or Docker forwarding should keep `GuestPath` blocked. They may also make `guest-to-host-rdp-exposure-excluded` and overall `RdpExposure` fail even when the independent `rdp-baseline-closed` predicate passes. **Do not run `plan-boundary`** regardless of `External` or virtual-path results. Preserve the existing connected-network firewall findings.

## No-journal abort and network restoration

Keep the second observer at the console. Before reconnecting, take one more offline capture with the same command and a new private filename; check that physical links stayed down and compare its virtual-path and RDP predicates. Verify the probe journal was absent before and after the rehearsal. Compare the new child-feature and full RDP observations to the connected baseline. If any source is inaccessible, a feature/RDP value changed, a journal appeared, or an unexpected `TermService`/listener is observed, **remain disconnected** for local review. There is no transaction journal to use with `reconnect-boundary-check`.

```powershell
$returnPath = Join-Path $private "external-before-reconnect-$tag.json"
$returnRaw = & pwsh -NoProfile -File .\scripts\network-boundary-diagnostic.ps1 `
    -OperatorConfirmedPhysicalSeverance -IncludeInventory
if ($LASTEXITCODE -ne 0) { throw 'Before-reconnect capture failed.' }
$return = ($returnRaw -join "`n") | ConvertFrom-Json -ErrorAction Stop
[IO.File]::WriteAllText($returnPath, ($returnRaw -join "`n"), [Text.UTF8Encoding]::new($false))
Assert-PrivateFile $returnPath
Assert-NoProbeJournal
if (($before.Inventory.ChildFeature | ConvertTo-Json -Depth 12 -Compress) -cne
    ($return.Inventory.ChildFeature | ConvertTo-Json -Depth 12 -Compress) -or
    ($before.Inventory.Rdp | ConvertTo-Json -Depth 32 -Compress) -cne
    ($return.Inventory.Rdp | ConvertTo-Json -Depth 32 -Compress) -or
    @($return.Boundary.Predicates | Where-Object Id -eq 'rdp-baseline-closed')[0].Verdict -ne 'Pass') {
    throw 'Feature or RDP baseline differs: remain offline for review.'
}
```

After local review of the three private captures and physical uplink state, the operator may restore **only** the links and radios intentionally changed for this rehearsal to their recorded original values. No workload resumption is needed because none was paused. Re-run the diagnostic without the physical-severance flag and compare connected adapters, routes, virtual paths, guest observations and RDP posture to the original capture:

```powershell
$afterPath = Join-Path $private "external-restored-$tag.json"
$afterRaw = & pwsh -NoProfile -File .\scripts\network-boundary-diagnostic.ps1 -IncludeInventory
if ($LASTEXITCODE -ne 0) { throw 'Restored-network capture failed.' }
$after = ($afterRaw -join "`n") | ConvertFrom-Json -ErrorAction Stop
[IO.File]::WriteAllText($afterPath, ($afterRaw -join "`n"), [Text.UTF8Encoding]::new($false))
Assert-PrivateFile $afterPath
$after.Boundary.Predicates |
    Where-Object { $_.Condition -in @('External','GuestPath','RdpExposure') } |
    Select-Object Condition,Id,Verdict,Evidence | Format-Table -Wrap
```

Preserve all reports locally; report only predicate verdicts and unresolved ifIndex relationships in PR discussion, without host addresses, identities or fingerprints. A passing virtual-path result here is a reason to consider a separately approved full workload pause and `plan-boundary` rehearsal, not permission to enable the child feature.
