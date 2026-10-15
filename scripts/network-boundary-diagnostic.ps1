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
    [switch]$IncludeInventory,
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
                MacAddress = [string]$_.MacAddress
                InterfaceDescription = [string]$_.InterfaceDescription
                PnPDeviceID = [string]$_.PnPDeviceID
                InterfaceGuid = [string]$_.InterfaceGuid
                # Names are emitted only as local diagnostic labels, never as allow rules.
                Label = [string]$_.Name
            }
        }) }
}
$switches = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-VMSwitch -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; Id = [string]$_.Id;
                SwitchType = [string]$_.SwitchType;
                NetAdapterInterfaceGuid = [string]$_.NetAdapterInterfaceGuid }
        }) }
}
$hostPorts = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Id = [string]$_.Id; MacAddress = [string]$_.MacAddress;
                SwitchName = [string]$_.SwitchName; SwitchId = [string]$_.SwitchId }
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
$vmPorts = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-VMNetworkAdapter -VMName '*' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Id = [string]$_.Id; VMName = [string]$_.VMName;
                SwitchName = [string]$_.SwitchName; SwitchId = [string]$_.SwitchId }
        }) }
}
$hnsRead = Observed {
    $json = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $PSScriptRoot 'hns-readonly.ps1') 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $json) { throw 'Read-only HNS inventory failed.' }
    $value = ($json -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($value.Schema -ne 'ChildStream.HnsReadOnly.v1' -or $value.HostMutation -ne $false -or
        $null -eq $value.Networks -or $null -eq $value.Endpoints) {
        throw 'Unexpected HNS read-only inventory schema.'
    }
    [pscustomobject]@{ State = 'Accessible'; Value = $value }
}
$hns = if ($hnsRead.State -eq 'Accessible') {
    [pscustomobject]@{ State = 'Accessible'; Items = @($hnsRead.Value.Networks) }
} else { [pscustomobject]@{ State = 'Inaccessible'; Items = @(); ErrorType = $hnsRead.ErrorType } }
$hnsEndpoints = if ($hnsRead.State -eq 'Accessible') {
    [pscustomobject]@{ State = 'Accessible'; Items = @($hnsRead.Value.Endpoints) }
} else { [pscustomobject]@{ State = 'Inaccessible'; Items = @(); ErrorType = $hnsRead.ErrorType } }
$netNat = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-NetNat -ErrorAction Stop | Select-Object Name,InternalIPInterfaceAddressPrefix,ExternalIPInterfaceAddressPrefix
    ) }
}
$portProxy = Observed {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy'
    $items = foreach ($family in @('v4tov4','v4tov6','v6tov4','v6tov6')) {
        $path = Join-Path $root "$family\tcp"
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { continue }
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        foreach ($name in $key.GetValueNames()) {
            [pscustomobject]@{ Family = $family; Listen = $name;
                Connect = [string]$key.GetValue($name) }
        }
    }
    [pscustomobject]@{ State = 'Accessible'; Items = @($items) }
}
$bridgeBindings = Get-ChildStreamBridgeBindingObservation -Adapters $adapters -Addresses $network.IpAddresses -Routes $network.Routes
$ipForwarding = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        Get-NetIPInterface -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop |
            Select-Object InterfaceIndex,CompartmentId,AddressFamily,Forwarding
    ) }
}
$forwarding = [pscustomobject]@{
    HnsState = $hns.State; NetNatState = $netNat.State; PortProxyState = $portProxy.State
    HnsEndpointState = $hnsEndpoints.State; HnsEndpointCount = @($hnsEndpoints.Items).Count
    BridgeBindingState = $bridgeBindings.State
    EnabledBridgeBindingCount = @($bridgeBindings.Items | Where-Object Enabled -eq $true).Count
    IpForwardingState = $ipForwarding.State
    EnabledIpForwardingCount = @($ipForwarding.Items | Where-Object Forwarding -eq 'Enabled').Count
    # A bridge binding is not proof of an active or absent bridge. A future
    # privileged topology graph must map every switch, HNS and forwarding path.
    BridgeGraphReviewed = $switches.State -eq 'Accessible' -and
        $hostPorts.State -eq 'Accessible' -and $vmPorts.State -eq 'Accessible' -and
        $hns.State -eq 'Accessible' -and $hnsEndpoints.State -eq 'Accessible' -and
        $bridgeBindings.State -eq 'Accessible' -and $ipForwarding.State -eq 'Accessible'
    UnreviewedForwardingPaths = @($portProxy.Items).Count +
        @($bridgeBindings.Items | Where-Object Enabled -eq $true).Count +
        @($ipForwarding.Items | Where-Object Forwarding -eq 'Enabled').Count +
        @($hns.Items | Where-Object { [string]$_.Type -notin @('NAT','ICS') }).Count
}
$wsl = Observed {
    $lines = @(wsl --list --verbose 2>$null | ForEach-Object { $_ -replace [char]0, '' })
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
$docker = try {
    $lines = @(docker ps --format '{{json .}}' 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($lines | ForEach-Object { [string]$_ }) -join ' '
        [pscustomobject]@{ State = 'Inaccessible'; ErrorClass = Get-ChildStreamDockerErrorClass $errorText;
            RunningContainerCount = $null; PublishedBindings = @() }
    } else {
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
} catch {
    [pscustomobject]@{ State = 'Inaccessible'; ErrorClass = Get-ChildStreamDockerErrorClass $_.Exception.Message;
        RunningContainerCount = $null; PublishedBindings = @() }
}
$dockerProcesses = Observed {
    [pscustomobject]@{ State = 'Accessible'; Items = @(
        # A filtered CIM query can succeed with zero rows. Get-Process with
        # SilentlyContinue could hide a provider/access error as zero peers.
        Get-CimInstance -ClassName Win32_Process -Filter "Name='Docker Desktop.exe' OR Name='com.docker.backend.exe' OR Name='dockerd.exe' OR Name='com.docker.proxy.exe' OR Name='vpnkit.exe'" -ErrorAction Stop |
            Select-Object @{Name='ProcessName';Expression={$_.Name}},@{Name='Id';Expression={$_.ProcessId}}
    ) }
}
$dockerListeners = Observed {
    if ($dockerProcesses.State -ne 'Accessible') { throw 'Docker process inventory is inaccessible.' }
    $processIds = @($dockerProcesses.Items | ForEach-Object { [int]$_.Id })
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { [int]$_.OwningProcess -in $processIds })
    $udp = @(Get-NetUDPEndpoint -ErrorAction Stop |
        Where-Object { [int]$_.OwningProcess -in $processIds })
    [pscustomobject]@{ State = 'Accessible'; DockerOwnedTcpCount = $tcp.Count;
        DockerOwnedUdpCount = $udp.Count }
}
$docker = Resolve-ChildStreamDockerObservation -Docker $docker -DockerProcesses $dockerProcesses -Wsl $wsl `
    -HnsEndpoints $hnsEndpoints -PortProxy $portProxy -Forwarding $forwarding -DockerListeners $dockerListeners

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

$observation = [pscustomobject]@{
    Adapters = $adapters
    IpInterfaces = $network.IpInterfaces
    IpAddresses = $network.IpAddresses
    Routes = $network.Routes
    Switches = $switches
    HostPorts = $hostPorts
    VirtualMachines = $vms
    VmPorts = $vmPorts
    Hns = $hns
    HnsEndpoints = $hnsEndpoints
    NetNat = $netNat
    PortProxy = $portProxy
    BridgeBindings = $bridgeBindings
    IpForwarding = $ipForwarding
    Wsl = $wsl
    Docker = $docker
    DockerProcesses = $dockerProcesses
    DockerListeners = $dockerListeners
    Rdp = $rdp
    RdpEvidence = $inventory.Rdp
    Forwarding = $forwarding
    AdapterCollectionConsistent = $adapterCollectionConsistent
    OperatorPhysicalSeveranceConfirmed = [bool]$OperatorConfirmedPhysicalSeverance
    CurrentNetworkFingerprint = $null
    ExpectedNetworkFingerprint = $ExpectedNetworkFingerprint
}
$fingerprint = Get-ChildStreamBoundaryFingerprint -Observation $observation
$observation.CurrentNetworkFingerprint = $fingerprint
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $observation
$report | Add-Member -NotePropertyName CurrentNetworkFingerprint -NotePropertyValue $fingerprint
$report | Add-Member -NotePropertyName BridgeBindingDiagnostic -NotePropertyValue ([pscustomobject]@{
    QueryMode = $bridgeBindings.QueryMode
    QueriedCount = @($bridgeBindings.Queried).Count
    FailureCount = @($bridgeBindings.Failures).Count
    Failures = @($bridgeBindings.Failures)
})
$report | Add-Member -NotePropertyName Collection -NotePropertyValue ([pscustomobject]@{
    Inventory = if ($null -ne $inventory.Schema) { 'Accessible' } else { 'Inaccessible' }
    HyperVSwitches = $switches.State; HyperVVirtualMachines = $vms.State
    HyperVHostPorts = $hostPorts.State; HyperVVmPorts = $vmPorts.State
    Wsl = $wsl.State; Docker = $docker.State; Hns = $hns.State
    HnsEndpoints = $hnsEndpoints.State; NetNat = $netNat.State; PortProxy = $portProxy.State
    BridgeBindings = $bridgeBindings.State; IpForwarding = $ipForwarding.State
    DockerProcesses = $dockerProcesses.State; DockerListeners = $dockerListeners.State
})
if ($IncludeInventory) {
    # One read-only capture supplies both the probe baseline and the topology
    # decision. This contains private host inventory and must never be uploaded.
    [pscustomobject]@{ Schema = 'ChildStream.BoundaryCapture.v1'; HostMutation = $false;
        Inventory = $inventory; Boundary = $report; Observation = $observation } |
        ConvertTo-Json -Depth 32 -Compress
} else {
    $report | ConvertTo-Json -Depth 8
}
