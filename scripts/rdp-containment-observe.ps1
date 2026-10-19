# Fixed, read-only, narrowly scoped policy observation for the elevated setup helper.
# It does not change firewall, RDP, services, sessions, or networking.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ChildStreamRdpFeatureRead {
  [DllImport("wtsapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool WTSIsChildSessionsEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);
}
'@
$enabled = $false
$featureKnown = [ChildStreamRdpFeatureRead]::WTSIsChildSessionsEnabled([ref]$enabled)
$local = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$policy = if (Test-Path -LiteralPath $policyPath) {
    (Get-ItemProperty -LiteralPath $policyPath -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
} else { $null }
$denied = if ($null -ne $policy) { [int]$policy -eq 1 } else { [int]$local -eq 1 }
$port = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
$service = Get-Service -Name TermService
$serviceProcess = Get-CimInstance Win32_Service -Filter "Name='TermService'" -ErrorAction Stop
if ($null -eq $serviceProcess -or $serviceProcess.ProcessId -lt 0) { throw 'TermService process identity unavailable' }
$tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
    $_.LocalPort -eq $port -or $_.LocalPort -eq 3389 -or
    ($serviceProcess.ProcessId -gt 0 -and $_.OwningProcess -eq $serviceProcess.ProcessId)
})
$udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
    $_.LocalPort -eq $port -or $_.LocalPort -eq 3389 -or
    ($serviceProcess.ProcessId -gt 0 -and $_.OwningProcess -eq $serviceProcess.ProcessId)
})
$names = @('ChildStream RDP containment TCP v1', 'ChildStream RDP containment UDP v1')
$allActive = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
$ordinaryAllows = @($allActive | Where-Object {
    $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
}).Count
$bypass = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -OverrideBlockRules $true -ErrorAction Stop |
    Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
    }).Count
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
    $bit = switch ($_.Name.ToString()) { Domain { 1 } Private { 2 } Public { 4 } default { throw 'Unknown firewall profile' } }
    $excluded = $fw.ExcludedInterfaces($bit)
    if ($null -eq $excluded) { throw 'Profile exclusions are unavailable' }
    [pscustomobject]@{ Name = $_.Name.ToString(); Enabled = $_.Enabled.ToString();
        DefaultInboundAction = $_.DefaultInboundAction.ToString();
        AllowLocalFirewallRules = $_.AllowLocalFirewallRules.ToString();
        ExcludedInterfaces = @($excluded) }
})
function RuleShape($rule) {
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $security = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
    $type = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    $interface = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
    if (@($portFilter).Count -ne 1 -or @($address).Count -ne 1 -or
        @($serviceFilter).Count -ne 1 -or @($app).Count -ne 1 -or
        @($security).Count -ne 1 -or @($type).Count -ne 1 -or @($interface).Count -ne 1) {
        throw 'Rule filters are incomplete'
    }
    [pscustomobject]@{ Name = $rule.Name; Description = [string]$rule.Description;
        Service = $serviceFilter.Service;
        Application = $app.Program;
        Authentication = $security.Authentication.ToString();
        Encryption = $security.Encryption.ToString();
        LocalUser = [string]$security.LocalUser; RemoteUser = [string]$security.RemoteUser;
        RemoteMachine = [string]$security.RemoteMachine;
        Protocol = $portFilter.Protocol.ToString(); LocalPorts = $portFilter.LocalPort;
        RemotePorts = $portFilter.RemotePort; LocalAddresses = $address.LocalAddress;
        RemoteAddresses = $address.RemoteAddress; InterfaceTypes = $type.InterfaceType.ToString();
        InterfaceAlias = @($interface.InterfaceAlias); Profiles = $rule.Profile.ToString();
        Direction = $rule.Direction.ToString(); Action = $rule.Action.ToString();
        Enabled = $rule.Enabled.ToString(); EdgeTraversal = $rule.EdgeTraversalPolicy.ToString();
        OverrideBlockRules = $security.OverrideBlockRules.ToString();
        SourceType = $rule.PolicyStoreSourceType.ToString();
        PrimaryStatus = $rule.PrimaryStatus.ToString(); EnforcementStatus = @($rule.EnforcementStatus) }
}
$persistent = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
    Where-Object { $names -contains $_.Name } | ForEach-Object { RuleShape $_ })
$active = @($allActive | Where-Object { $names -contains $_.Name } | ForEach-Object { RuleShape $_ })
[pscustomobject]@{ Schema = 'ChildStream.RdpContainmentObservation.v1';
    FeatureKnown = [bool]$featureKnown; FeatureEnabled = [bool]$enabled;
    PolicyDenied = [bool]$denied; TermServiceState = $service.Status.ToString();
    ListenersAbsent = ($tcp.Count -eq 0 -and $udp.Count -eq 0);
    ConfiguredRdpPort = $port; BypassCount = $bypass; OrdinaryAllowCount = $ordinaryAllows;
    Profiles = $profiles; PersistentRules = $persistent; ActiveRules = $active
} | ConvertTo-Json -Depth 8 -Compress
