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
        @{ InterfaceIndex = 40; Status = 'Up'; MediaConnectionState = 'Connected'; HardwareInterface = $false; Virtual = $true; VerifiedRole = 'InternalSwitchHost'; RoleEvidence = 'HyperVPortGraph' }
    ) }
    IpInterfaces = @{ State = 'Accessible'; Items = @(@{ InterfaceIndex = 40; ConnectionState = 'Connected' }) }
    IpAddresses = @{ State = 'Accessible'; Items = @(@{ InterfaceIndex = 40; Address = '172.30.0.1' }) }
    Routes = @{ State = 'Accessible'; Items = @(@{ InterfaceIndex = 40; DestinationPrefix = '172.30.0.0/20' }) }
    Switches = @{ State = 'Accessible'; Items = @(@{ SwitchType = 'Internal' }) }
    VirtualMachines = @{ State = 'Accessible'; Items = @() }
    Wsl = @{ State = 'Accessible'; Mode = 'nat'; RunningDistributions = @() }
    Docker = @{ State = 'Accessible'; RunningContainerCount = 0; PublishedBindings = @() }
    Forwarding = @{ HnsState = 'Accessible'; NetNatState = 'Accessible'; PortProxyState = 'Accessible';
        BridgeGraphReviewed = $true; UnreviewedForwardingPaths = 0 }
    Rdp = @{ State = 'Accessible'; PolicyDenied = $true; TermServiceStopped = $true; TcpListenerCount = 0; UdpEndpointCount = 0 }
    OperatorPhysicalSeveranceConfirmed = $true
    AdapterCollectionConsistent = $true
    ExpectedNetworkFingerprint = 'baseline'
    CurrentNetworkFingerprint = 'baseline'
}

$hostOnly = Get-ChildStreamNetworkBoundaryDiagnostic -Observation (Clone $baseline)
Check ($hostOnly.Conditions.External -eq 'Pass' -and $hostOnly.Conditions.GuestPath -eq 'Pass' -and
    $hostOnly.Conditions.RdpExposure -eq 'Pass' -and $hostOnly.Conditions.Continuity -eq 'Pass') 'Known host-only paths without active peers should diagnose separately from external reachability.'
Check (-not $hostOnly.StageAPlanAuthorized -and $hostOnly.DiagnosticOnly) 'Diagnostic cannot authorize Stage A.'

$activeGuests = Clone $baseline
$activeGuests.Wsl.RunningDistributions = @('example-dev', 'example-containers')
$activeGuests.Docker.RunningContainerCount = 2
$activeGuests.Docker.PublishedBindings = @('0.0.0.0:15432', '[::]:15432')
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $activeGuests
Check ($report.Conditions.External -eq 'Pass') 'Physical disconnection with internal guests is not automatically external exposure.'
Check ((Predicate $report 'internal-guests-quiescent') -eq 'Fail' -and
    (Predicate $report 'guest-to-host-rdp-exposure-excluded') -eq 'Fail' -and
    (Predicate $report 'docker-host-forwarding-absent') -eq 'Fail') 'Active WSL2/Docker guests and forwarding block the internal exposure claim.'

$tunnel = Clone $baseline
$tunnel.Adapters.Items += @{ InterfaceIndex = 41; Status = 'Up'; MediaConnectionState = 'Connected'; HardwareInterface = $false; Virtual = $true; VerifiedRole = 'TunnelWithoutUnderlay'; RoleEvidence = 'UnderlayGraph'; Label = 'Example tunnel' }
$tunnel.IpAddresses.Items += @{ InterfaceIndex = 41; Address = '100.64.0.25' }
$tunnel.Routes.Items += @{ InterfaceIndex = 41; DestinationPrefix = '100.64.0.0/24' }
$report = Get-ChildStreamNetworkBoundaryDiagnostic -Observation $tunnel
Check ($report.Conditions.External -eq 'Pass') 'An independently attributed tunnel without an underlay is not itself an external path.'
$tunnel.Adapters.Items[-1].VerifiedRole = ''
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $tunnel) 'virtual-paths-attributed') -eq 'Unknown') 'Tunnel name alone is never a whitelist.'

$miniport = Clone $baseline
$miniport.Adapters.Items += @{ InterfaceIndex = 42; Status = 'Up'; MediaConnectionState = 'Connected'; HardwareInterface = $false; Virtual = $true; VerifiedRole = 'UnaddressedMiniport'; RoleEvidence = 'DriverAndPathGraph' }
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
$unknown.Forwarding.HnsState = 'Inaccessible'
Check ((Predicate (Get-ChildStreamNetworkBoundaryDiagnostic -Observation $unknown) 'nat-bridge-forwarding-mapped') -eq 'Unknown') 'HNS denial cannot prove an empty forwarding graph.'

Write-Output 'Network boundary diagnostic regression scenarios passed.'
