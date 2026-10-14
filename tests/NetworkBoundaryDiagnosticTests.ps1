$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\NetworkBoundaryDiagnostic.psm1') -Force

function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Clone($Value) { $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable }
function Predicate($Report, [string]$Id) { @($Report.Predicates | Where-Object Id -eq $Id)[0].Verdict }

$baseline = @{
    Adapters = @{ State = 'Accessible'; Items = @(
        @{ InterfaceIndex = 2; Status = 'Disconnected'; MediaConnectionState = 'Disconnected'; HardwareInterface = $true; Virtual = $false; VerifiedRole = '' },
        @{ InterfaceIndex = 3; Status = 'Disconnected'; MediaConnectionState = 'Disconnected'; HardwareInterface = $true; Virtual = $false; VerifiedRole = '' },
        @{ InterfaceIndex = 40; Status = 'Up'; MediaConnectionState = 'Connected'; HardwareInterface = $false; Virtual = $true;
            MacAddress = '00-15-5D-00-00-40'; InterfaceDescription = 'Hyper-V Virtual Ethernet Adapter';
            PnPDeviceID = 'ROOT\VMS_MP\0001' }
    ) }
    IpInterfaces = @{ State = 'Accessible'; Items = @(@{ InterfaceIndex = 40; ConnectionState = 'Connected' }) }
    IpAddresses = @{ State = 'Accessible'; Items = @(@{ InterfaceIndex = 40; Address = '172.30.0.1' }) }
    Routes = @{ State = 'Accessible'; Items = @(@{ InterfaceIndex = 40; DestinationPrefix = '172.30.0.0/20' }) }
    Switches = @{ State = 'Accessible'; Items = @(@{ Name = 'host-only'; Id = 'switch-1'; SwitchType = 'Internal' }) }
    HostPorts = @{ State = 'Accessible'; Items = @(@{ Id = 'port-1'; SwitchName = 'host-only'; SwitchId = 'switch-1'; MacAddress = '00155D000040' }) }
    VirtualMachines = @{ State = 'Accessible'; Items = @() }
    VmPorts = @{ State = 'Accessible'; Items = @() }
    Hns = @{ State = 'Accessible'; Items = @(@{ ID = 'network-1'; Type = 'NAT' }) }
    HnsEndpoints = @{ State = 'Accessible'; Items = @() }
    NetNat = @{ State = 'Accessible'; Items = @() }
    PortProxy = @{ State = 'Accessible'; Items = @() }
    BridgeBindings = @{ State = 'Accessible'; Items = @() }
    IpForwarding = @{ State = 'Accessible'; Items = @() }
    Wsl = @{ State = 'Accessible'; Mode = 'nat'; RunningDistributions = @() }
    Docker = @{ State = 'Accessible'; RunningContainerCount = 0; PublishedBindings = @() }
    DockerProcesses = @{ State = 'Accessible'; Items = @() }
    Forwarding = @{ HnsState = 'Accessible'; NetNatState = 'Accessible'; PortProxyState = 'Accessible';
        HnsEndpointState = 'Accessible'; BridgeBindingState = 'Accessible';
        IpForwardingState = 'Accessible'; EnabledBridgeBindingCount = 0;
        BridgeGraphReviewed = $true; UnreviewedForwardingPaths = 0 }
    Rdp = @{ State = 'Accessible'; PolicyDenied = $true; TermServiceStopped = $true; TcpListenerCount = 0; UdpEndpointCount = 0 }
    RdpEvidence = @{ Firewall = @{ State = 'Accessible'; Items = @() };
        FirewallProfiles = @{ State = 'Accessible'; Items = @() };
        LocalDenyConnections = @{ State = 'Accessible'; Data = 1 };
        PolicyDenyConnections = @{ State = 'Absent' };
        Services = @{ State = 'Accessible'; Items = @() };
        TcpListener = @{ State = 'Accessible'; Items = @() };
        UdpEndpoint = @{ State = 'Accessible'; Items = @() } }
    OperatorPhysicalSeveranceConfirmed = $true
    AdapterCollectionConsistent = $true
    ExpectedNetworkFingerprint = 'baseline'
    CurrentNetworkFingerprint = 'baseline'
}

$hostOnly = Get-ChildStreamNetworkBoundaryDiagnostic -Observation (Clone $baseline)
Check ($hostOnly.Conditions.External -eq 'Pass' -and $hostOnly.Conditions.GuestPath -eq 'Pass' -and
    $hostOnly.Conditions.RdpExposure -eq 'Pass' -and $hostOnly.Conditions.Continuity -eq 'Pass') 'Known host-only paths without active peers should diagnose separately from external reachability.'
Check (-not $hostOnly.StageAPlanAuthorized -and $hostOnly.DiagnosticOnly) 'Diagnostic cannot authorize Stage A.'
$hostWithoutPnp = Clone $baseline
$hostWithoutPnp.Adapters.Items[2].Remove('PnPDeviceID')
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $hostWithoutPnp) 'virtual-paths-attributed') -eq 'Pass') 'A unique MAC, virtual identity, adapter description and matched Hyper-V port/switch attribute the host port without PnP coverage.'
$firstFingerprint = Get-ChildStreamBoundaryFingerprint -Observation (Clone $baseline)
Check (-not [string]::IsNullOrEmpty($firstFingerprint)) 'Complete source graph has a private fingerprint.'
$reordered = Clone $baseline
$reordered.Adapters.Items = @($reordered.Adapters.Items[2],$reordered.Adapters.Items[1],$reordered.Adapters.Items[0])
Check ((Get-ChildStreamBoundaryFingerprint -Observation $reordered) -ceq $firstFingerprint) 'Item order must not change the approved fingerprint.'
$changed = Clone $baseline
$changed.Hns.Items[0].Type = 'Transparent'
Check ((Get-ChildStreamBoundaryFingerprint -Observation $changed) -cne $firstFingerprint) 'HNS topology drift changes the approved fingerprint.'
$changed = Clone $baseline
$changed.Hns.State = 'Inaccessible'
Check ($null -eq (Get-ChildStreamBoundaryFingerprint -Observation $changed)) 'Incomplete topology cannot produce an approved fingerprint.'
$changed = Clone $baseline
$changed.RdpEvidence.Firewall.Items += @{ Name = 'new-rule' }
Check ((Get-ChildStreamBoundaryFingerprint -Observation $changed) -cne $firstFingerprint) 'Firewall inventory drift changes the approved fingerprint.'

$activeGuests = Clone $baseline
$activeGuests.Wsl.RunningDistributions = @('example-dev', 'example-containers')
$activeGuests.Docker.RunningContainerCount = 2
$activeGuests.Docker.PublishedBindings = @('0.0.0.0:15432', '[::]:15432')
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $activeGuests
Check ($report.Conditions.External -eq 'Pass') 'Physical disconnection with internal guests is not automatically external exposure.'
Check ((Predicate $report 'internal-guests-quiescent') -eq 'Fail' -and
    (Predicate $report 'guest-to-host-rdp-exposure-excluded') -eq 'Fail' -and
    (Predicate $report 'docker-host-forwarding-absent') -eq 'Fail') 'Active WSL2/Docker guests and forwarding block the internal exposure claim.'
Check ('internal-guests-quiescent' -in $report.BlockingFindings.CurrentState -and
    'physical-severance-confirmed' -notin $report.BlockingFindings.EvidenceGaps) 'Current workload blockers and preapproval checks are reported separately.'

$tunnel = Clone $baseline
$tunnel.Adapters.Items += @{ InterfaceIndex = 41; Status = 'Up'; MediaConnectionState = 'Connected'; HardwareInterface = $false; Virtual = $true; PnPDeviceID = 'SWD\EXAMPLE\0001'; Label = 'Example tunnel' }
$tunnel.IpAddresses.Items += @{ InterfaceIndex = 41; Address = '100.64.0.25' }
$tunnel.Routes.Items += @{ InterfaceIndex = 41; DestinationPrefix = '100.64.0.0/24' }
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $tunnel
Check ($report.Conditions.External -eq 'Unknown') 'An addressed tunnel without an independently proven underlay graph remains unknown.'
$tunnel.Adapters.Items[-1].Label = 'Tailscale'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $tunnel) 'virtual-paths-attributed') -eq 'Unknown') 'Tunnel name alone is never a whitelist.'

$miniport = Clone $baseline
$miniport.Adapters.Items += @{ InterfaceIndex = 42; Status = 'Up'; MediaConnectionState = 'Connected'; HardwareInterface = $false; Virtual = $true }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $miniport) 'virtual-paths-attributed') -eq 'Pass') 'Verified unaddressed miniport is not automatically external exposure.'
$miniport.Routes.Items += @{ InterfaceIndex = 42; DestinationPrefix = '10.0.0.0/8' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $miniport) 'virtual-paths-attributed') -eq 'Unknown') 'Miniport with a route needs independent path attribution.'

$listener = Clone $baseline
$listener.Rdp.TcpListenerCount = 1
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $listener) 'rdp-baseline-closed') -eq 'Fail') 'Unexpected RDP listener blocks even with no active guests.'

$lan = Clone $baseline
$lan.Adapters.Items[0].Status = 'Up'
$lan.Adapters.Items[0].MediaConnectionState = 'Connected'
$lan.Routes.Items += @{ InterfaceIndex = 2; DestinationPrefix = '10.20.30.0/24' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $lan) 'physical-uplinks-down') -eq 'Fail') 'Active LAN is exposure even without a default route.'
$stale = Clone $baseline
$stale.Routes.Items += @{ InterfaceIndex = 2; DestinationPrefix = '10.20.30.0/24' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $stale) 'physical-route-link-corroboration') -eq 'Pass') 'A retained route on a verified disconnected physical link is recorded without pretending the link is live.'

$bridge = Clone $baseline
$bridge.Switches.Items += @{ SwitchType = 'External' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $bridge) 'switches-have-no-external-bridge') -eq 'Fail') 'External switch cannot masquerade as a host-only path.'

$drift = Clone $baseline
$drift.Adapters.Items[0].Status = 'Up'
$drift.Adapters.Items[0].MediaConnectionState = 'Connected'
$drift.CurrentNetworkFingerprint = 'after-fresh-logon'
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $drift
Check ((Predicate $report 'physical-uplinks-down') -eq 'Fail' -and
    (Predicate $report 'fresh-logon-network-unchanged') -eq 'Fail') 'Reappearing Wi-Fi and fingerprint drift stop fresh-logon progression.'

$unknown = Clone $baseline
$unknown.VirtualMachines.State = 'Inaccessible'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'internal-guests-quiescent') -eq 'Unknown') 'Inaccessible VM inventory cannot prove guest absence.'
$unknown = Clone $baseline
$unknown.DockerProcesses.State = 'Inaccessible'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'internal-guests-quiescent') -eq 'Unknown') 'A failed process query cannot prove Docker is absent.'
$unknown = Clone $baseline
$unknown.Forwarding.HnsState = 'Inaccessible'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'nat-bridge-forwarding-mapped') -eq 'Unknown') 'HNS denial cannot prove an empty forwarding graph.'
$unknown = Clone $baseline
$unknown.HostPorts.State = 'Inaccessible'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'hyperv-host-port-graph') -eq 'Unknown') 'Inaccessible port mapping cannot prove virtual adapter identity.'
$unknown = Clone $baseline
$unknown.HostPorts.Items[0].SwitchId = 'different-switch'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'hyperv-host-port-graph') -eq 'Unknown') 'Conflicting host-port switch identity cannot pass.'
$unknown = Clone $baseline
$unknown.Forwarding.UnreviewedForwardingPaths = 1
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'nat-bridge-forwarding-mapped') -eq 'Fail') 'Enabled forwarding or bridge path blocks the boundary.'
$unknown = Clone $baseline
$unknown.HnsEndpoints.Items += @{ Id = 'running-endpoint' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'hns-endpoints-quiescent') -eq 'Fail') 'An active HNS endpoint blocks the guest boundary.'
$unknown = Clone $baseline
$unknown.HnsEndpoints.Items += @{ ID = 'endpoint-1'; VirtualNetwork = 'different-network'; State = 'Attached' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'hns-endpoint-network-graph') -eq 'Unknown') 'An endpoint without a matching HNS network cannot be attributed.'
$known = Clone $baseline
$known.HnsEndpoints.Items += @{ ID = 'endpoint-1'; VirtualNetwork = 'network-1'; State = 'Attached' }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $known) 'hns-endpoint-network-graph') -eq 'Pass') 'An HNS endpoint maps to its network by identity.'
$unknown = Clone $baseline
$unknown.HostPorts.Items[0].SwitchName = 'different-switch'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'hyperv-host-port-graph') -eq 'Unknown') 'Host-port ID and name must refer to the same switch.'
$unknown = Clone $baseline
$unknown.DockerProcesses.Items += @{ ProcessName = 'Docker Desktop'; Id = 1 }
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'internal-guests-quiescent') -eq 'Fail') 'Docker daemon must be quiescent even without published containers.'

$bindingReader = {
    param($adapter)
    @([pscustomobject]@{ Name = $adapter.Label; ComponentID = 'ms_tcpip'; Enabled = $true })
}
$bindingSource = Clone $baseline
foreach ($adapter in $bindingSource.Adapters.Items) { $adapter.Label = "adapter-$($adapter.InterfaceIndex)" }
$bridgeRead = Get-ChildStreamBridgeBindingObservation -Adapters $bindingSource.Adapters -Addresses $bindingSource.IpAddresses -Routes $bindingSource.Routes -QueryBinding $bindingReader
Check ($bridgeRead.State -eq 'Accessible' -and $bridgeRead.Queried.Count -eq 3 -and $bridgeRead.Items.Count -eq 0) 'All relevant per-adapter binding queries establish absence of ms_bridge.'
$faultReader = {
    param($adapter)
    if ($adapter.InterfaceIndex -eq 40) { throw [System.InvalidOperationException]::new('Synthetic provider failure.') }
    @([pscustomobject]@{ Name = $adapter.Label; ComponentID = 'ms_tcpip'; Enabled = $true })
}
$bridgeRead = Get-ChildStreamBridgeBindingObservation -Adapters $bindingSource.Adapters -Addresses $bindingSource.IpAddresses -Routes $bindingSource.Routes -QueryBinding $faultReader
Check ($bridgeRead.State -eq 'Inaccessible' -and $bridgeRead.Failures.Count -eq 1 -and
    $bridgeRead.Failures[0].InterfaceIndex -eq 40) 'A single failed relevant binding remains unknown and identifies its adapter.'
$unreadBridge = Clone $baseline
$unreadBridge.BridgeBindings = $bridgeRead
$unreadBridge.Forwarding.BridgeBindingState = $bridgeRead.State
Check ($null -eq (Get-ChildStreamBoundaryFingerprint -Observation $unreadBridge) -and
    (Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unreadBridge) 'nat-bridge-forwarding-mapped') -eq 'Unknown') 'An unread bridge member cannot become absent through the fingerprint or forwarding predicate.'
$emptyReader = { param($adapter) @() }
$bridgeRead = Get-ChildStreamBridgeBindingObservation -Adapters $bindingSource.Adapters -Addresses $bindingSource.IpAddresses -Routes $bindingSource.Routes -QueryBinding $emptyReader
Check ($bridgeRead.State -eq 'Inaccessible') 'An empty unsupported binding query cannot prove absence.'
$bridgeReader = {
    param($adapter)
    @([pscustomobject]@{ Name = $adapter.Label; ComponentID = 'ms_bridge'; Enabled = $true })
}
$bridgeRead = Get-ChildStreamBridgeBindingObservation -Adapters $bindingSource.Adapters -Addresses $bindingSource.IpAddresses -Routes $bindingSource.Routes -QueryBinding $bridgeReader
Check ($bridgeRead.State -eq 'Accessible' -and $bridgeRead.Items.Count -eq 3) 'Enabled bridge bindings are retained as blockers.'

Write-Output 'Network boundary diagnostic regression scenarios passed.'
