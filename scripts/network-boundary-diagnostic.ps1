<#
.SYNOPSIS
  Read-only, predicate-level diagnosis of a proposed Stage A network boundary.
.DESCRIPTION
  Reports observations; it cannot approve a plan or change networking, guests,
  firewall, services, or child-session state. Keep output private: host topology
  and the fingerprint are local security inventory.
#>
[CmdletBinding()]
param(
    [switch]$OperatorConfirmedPhysicalSeverance,
    [string]$ExpectedNetworkFingerprint
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\NetworkBoundaryDiagnostic.psm1') -Force

function Observed([scriptblock]$Read) {
    try { & $Read }
    catch { [pscustomobject]@{ State = 'Inaccessible'; Items = @(); ErrorType = $_.Exception.GetType().Name } }
}

$inventory = Observed {
    $json = & pwsh -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'feasibility-inventory.ps1')
    if ($LASTEXITCODE -ne 0 -or -not $json) { throw 'Read-only feasibility inventory failed.' }
    ($json -join "`n") | ConvertFrom-Json -ErrorAction Stop
}
$network = $inventory.Network

$adapters = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-NetAdapter -Name '*' -IncludeHidden -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                InterfaceIndex = [int]$_.ifIndex
                Status = [string]$_.Status
                MediaConnectionState = [string]$_.MediaConnectionState
                HardwareInterface = [bool]$_.HardwareInterface
                Virtual = [bool]$_.Virtual
                # Names are emitted only as local diagnostic labels, never as allow rules.
                Label = [string]$_.Name
                VerifiedRole = ''
                RoleEvidence = ''
            }
        }) }
}
$switches = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-VMSwitch -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; SwitchType = [string]$_.SwitchType }
        }) }
}
$adapterCollectionConsistent = $false
if ($adapters.State -eq 'Accessible' -and $network.Adapters.State -eq 'Accessible') {
    $earlier = @($network.Adapters.Items | ForEach-Object {
        "$($_.InterfaceIndex):$($_.Status):$($_.MediaConnectionState)"
    } | Sort-Object -CaseSensitive)
    $later = @($adapters.Items | ForEach-Object {
        "$($_.InterfaceIndex):$($_.Status):$($_.MediaConnectionState)"
    } | Sort-Object -CaseSensitive)
    $adapterCollectionConsistent = ($earlier.Count -eq $later.Count -and
        ($earlier -join "`n") -ceq ($later -join "`n"))
}
$vms = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-VM -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; State = [string]$_.State }
        }) }
}
$hns = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-HnsNetwork -ErrorAction Stop | Select-Object Name,Type,NetworkAdapterName
    ) }
}
$netNat = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-NetNat -ErrorAction Stop | Select-Object Name,InternalIPInterfaceAddressPrefix,ExternalIPInterfaceAddressPrefix
    ) }
}
$portProxy = Observed {
    $lines = @(netsh interface portproxy show all)
    if ($LASTEXITCODE -ne 0) { throw 'Portproxy inventory failed.' }
    [pscustomobject]@{ State = 'Accessible'; Items = @($lines | Where-Object { $_.Trim() }) }
}
$forwarding = [pscustomobject]@{
    HnsState = $hns.State; NetNatState = $netNat.State; PortProxyState = $portProxy.State
    # A bridge binding is not proof of an active or absent bridge. A future
    # privileged topology graph must map every switch, HNS and forwarding path.
    BridgeGraphReviewed = $false
    UnreviewedForwardingPaths = @($netNat.Items).Count + @($portProxy.Items).Count
}
$wsl = Observed {
    $lines = @(wsl --list --verbose | ForEach-Object { $_ -replace [char]0, '' })
    if ($LASTEXITCODE -ne 0 -or -not ($lines -match '\bNAME\s+STATE\s+VERSION\b')) {
        throw 'WSL distribution listing was not parseable.'
    }
    $running = @()
    foreach ($line in $lines) {
        if ($line -match '^\s*\*?\s*(.*?)\s{2,}(Running|Stopped)\s+([12])\s*$') {
            if ($Matches[2] -eq 'Running') { $running += $Matches[1].Trim() }
        }
        elseif ($line.Trim() -and $line -notmatch '\bNAME\s+STATE\s+VERSION\b') {
            throw 'WSL distribution state was not parseable.'
        }
    }
    [pscustomobject]@{ State = 'Accessible'; RunningDistributions = $running;
        Mode = 'Unknown'; Note = 'No distro is launched to query effective WSL networking mode.' }
}
$docker = Observed {
    $lines = @(docker ps --format '{{json .}}')
    if ($LASTEXITCODE -ne 0) { throw 'Docker container listing failed.' }
    $bindings = @()
    foreach ($line in $lines) {
        if (-not $line) { continue }
        $container = $line | ConvertFrom-Json -ErrorAction Stop
        foreach ($port in ([string]$container.Ports -split ',\s*')) {
            if ($port -match '^(.*?)\s*->') { $bindings += $Matches[1] }
        }
    }
    [pscustomobject]@{ State = 'Accessible'; RunningContainerCount = @($lines | Where-Object { $_ }).Count;
        PublishedBindings = @($bindings) }
}

$rdp = [pscustomobject]@{ State = 'Inaccessible'; PolicyDenied = $null;
    TermServiceStopped = $null; TcpListenerCount = $null; UdpEndpointCount = $null }
if ($null -ne $inventory.Rdp) {
    $r = $inventory.Rdp
    $localKnown = $r.LocalDenyConnections.State -eq 'Accessible'
    $policyKnown = $r.PolicyDenyConnections.State -in @('Accessible', 'Absent')
    $serviceKnown = $r.Services.State -eq 'Accessible' -and
        @($r.Services.Items | Where-Object Name -eq 'TermService').Count -eq 1
    $listenerKnown = $r.TcpListener.State -eq 'Accessible' -and $r.UdpEndpoint.State -eq 'Accessible'
    $rdp = [pscustomobject]@{
        State = if ($localKnown -and $policyKnown -and $serviceKnown -and $listenerKnown) { 'Accessible' } else { 'Inaccessible' }
        PolicyDenied = if ($localKnown -and $policyKnown) { $r.LocalDenyConnections.Data -eq 1 -and
            ($r.PolicyDenyConnections.State -eq 'Absent' -or $r.PolicyDenyConnections.Data -eq 1) } else { $null }
        TermServiceStopped = if ($serviceKnown) { ($r.Services.Items | Where-Object Name -eq 'TermService' | Select-Object -First 1).State -eq 'Stopped' } else { $null }
        TcpListenerCount = if ($listenerKnown) { @($r.TcpListener.Items).Count } else { $null }
        UdpEndpointCount = if ($listenerKnown) { @($r.UdpEndpoint.Items).Count } else { $null }
    }
}

$fingerprint = $null
if ($null -ne $network -and $network.Adapters.State -eq 'Accessible' -and
    $network.IpInterfaces.State -eq 'Accessible' -and $network.IpAddresses.State -eq 'Accessible' -and
    $network.Routes.State -eq 'Accessible') {
    $canonical = foreach ($section in @('Adapters', 'IpInterfaces', 'IpAddresses', 'Routes')) {
        $items = @($network.$section.Items | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 12 } | Sort-Object -CaseSensitive)
        "$section=$($items -join '|')"
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $fingerprint = [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical -join "`n"))).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

$observation = [pscustomobject]@{
    Adapters = $adapters
    IpInterfaces = $network.IpInterfaces
    IpAddresses = $network.IpAddresses
    Routes = $network.Routes
    Switches = $switches
    VirtualMachines = $vms
    Wsl = $wsl
    Docker = $docker
    Rdp = $rdp
    Forwarding = $forwarding
    AdapterCollectionConsistent = $adapterCollectionConsistent
    OperatorPhysicalSeveranceConfirmed = [bool]$OperatorConfirmedPhysicalSeverance
    CurrentNetworkFingerprint = $fingerprint
    ExpectedNetworkFingerprint = $ExpectedNetworkFingerprint
}
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $observation
$report | Add-Member -NotePropertyName CurrentNetworkFingerprint -NotePropertyValue $fingerprint
$report | Add-Member -NotePropertyName Collection -NotePropertyValue ([pscustomobject]@{
    Inventory = if ($null -ne $inventory.Schema) { 'Accessible' } else { 'Inaccessible' }
    HyperVSwitches = $switches.State; HyperVVirtualMachines = $vms.State
    Wsl = $wsl.State; Docker = $docker.State; Hns = $hns.State
    NetNat = $netNat.State; PortProxy = $portProxy.State
})
$report | ConvertTo-Json -Depth 8
