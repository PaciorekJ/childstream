<#
.SYNOPSIS
  Read-only, typed inventory for the proposed child-session experiment.
.DESCRIPTION
  Emits JSON only. It never calls child-session enable/connect/logoff APIs, writes a
  registry value, changes a firewall rule, or reads Sunshine pairing/config files.
  Host observations are local and sensitive; save the JSON only in a private path.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class ChildStreamReadOnlyWts
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SessionInfo { public int SessionId; public IntPtr Name; public int State; }
    // WTSINFOEXW level 1, through LogonTime. Names are marshalled for layout only
    // and never returned to PowerShell or the report.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Level1 {
        public uint SessionId; public int State; public int Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string Station;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string Domain;
        public long LogonTime;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct InfoEx { public uint Level; public Level1 Data; }

    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSIsChildSessionsEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSGetChildSessionId(out uint sessionId);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    private static extern bool Enumerate(IntPtr server, int reserved, int version, out IntPtr data, out int count);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    private static extern bool Query(IntPtr server, uint sessionId, int infoClass, out IntPtr data, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr data);
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();

    public static object Feature()
    {
        bool enabled;
        if (WTSIsChildSessionsEnabled(out enabled)) return new { State = "Accessible", Enabled = (bool?)enabled, ErrorCode = 0 };
        int error = Marshal.GetLastWin32Error();
        return new { State = error == 5 ? "Inaccessible" : "Unknown", Enabled = (bool?)null, ErrorCode = error };
    }
    public static object AssociatedChild()
    {
        uint id;
        if (WTSGetChildSessionId(out id))
            return new { State = id == uint.MaxValue ? "Absent" : "Accessible", SessionId = id == uint.MaxValue ? (uint?)null : id, ErrorCode = 0 };
        int error = Marshal.GetLastWin32Error();
        return new { State = error == 5 ? "Inaccessible" : "Unknown", SessionId = (uint?)null, ErrorCode = error };
    }
    public static object Session(uint id)
    {
        IntPtr data; int bytes;
        if (!Query(IntPtr.Zero, id, 25, out data, out bytes))
        {
            int error = Marshal.GetLastWin32Error();
            return new { State = error == 5 ? "Inaccessible" : "Unknown", SessionId = id,
                LogonTime = (long?)null, ConnectionState = (int?)null, ErrorCode = error };
        }
        try
        {
            if (bytes < Marshal.SizeOf(typeof(InfoEx)))
                return new { State = "Unknown", SessionId = id, LogonTime = (long?)null,
                    ConnectionState = (int?)null, ErrorCode = 0 };
            InfoEx info = (InfoEx)Marshal.PtrToStructure(data, typeof(InfoEx));
            if (info.Level != 1 || info.Data.SessionId != id || info.Data.LogonTime <= 0)
                return new { State = "Unknown", SessionId = id, LogonTime = (long?)null,
                    ConnectionState = (int?)null, ErrorCode = 0 };
            return new { State = "Accessible", SessionId = id, LogonTime = (long?)info.Data.LogonTime,
                ConnectionState = (int?)info.Data.State, ErrorCode = 0 };
        }
        finally { WTSFreeMemory(data); }
    }
    public static object CurrentProtocol()
    {
        IntPtr data; int bytes;
        if (!Query(IntPtr.Zero, uint.MaxValue, 16, out data, out bytes))
        {
            int error = Marshal.GetLastWin32Error();
            return new { State = error == 5 ? "Inaccessible" : "Unknown", Value = (int?)null, ErrorCode = error };
        }
        try
        {
            if (data == IntPtr.Zero || bytes < 2)
                return new { State = "Unknown", Value = (int?)null, ErrorCode = 0 };
            return new { State = "Accessible", Value = (int?)((ushort)Marshal.ReadInt16(data)), ErrorCode = 0 };
        }
        finally { if (data != IntPtr.Zero) WTSFreeMemory(data); }
    }
    public static object Sessions()
    {
        IntPtr data; int count;
        if (!Enumerate(IntPtr.Zero, 0, 1, out data, out count))
        {
            int error = Marshal.GetLastWin32Error();
            return new { State = error == 5 ? "Inaccessible" : "Unknown", Items = new object[0], ErrorCode = error };
        }
        try
        {
            if (count < 0 || count > 1024)
                return new { State = "Unknown", Items = new object[0], ErrorCode = 0 };
            var items = new List<object>();
            int size = Marshal.SizeOf(typeof(SessionInfo));
            for (int i = 0; i < count; i++)
            {
                SessionInfo item = (SessionInfo)Marshal.PtrToStructure(IntPtr.Add(data, i * size), typeof(SessionInfo));
                items.Add(new { SessionId = item.SessionId, ConnectionState = item.State });
            }
            return new { State = "Accessible", Items = items.ToArray(), ErrorCode = 0 };
        }
        finally { WTSFreeMemory(data); }
    }
}
'@

function Observed([scriptblock] $Read) {
    try { return & $Read }
    catch [System.UnauthorizedAccessException] { return [ordered]@{ State = 'Inaccessible'; ErrorType = 'UnauthorizedAccess' } }
    catch [System.Security.SecurityException] { return [ordered]@{ State = 'Inaccessible'; ErrorType = 'Security' } }
    catch { return [ordered]@{ State = 'Unknown'; ErrorType = $_.Exception.GetType().Name } }
}
function RegistryValue([string] $Path, [string] $Name) {
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($Name -notin $key.GetValueNames()) { return [ordered]@{ State = 'Absent'; Type = $null; Data = $null } }
        return [ordered]@{ State = 'Accessible'; Type = [string]$key.GetValueKind($Name);
            Data = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    } catch [System.Management.Automation.ItemNotFoundException] {
        return [ordered]@{ State = 'Absent'; Type = $null; Data = $null }
    } catch [System.UnauthorizedAccessException] {
        return [ordered]@{ State = 'Inaccessible'; Type = $null; Data = $null }
    } catch { return [ordered]@{ State = 'Unknown'; Type = $null; Data = $null; ErrorType = $_.Exception.GetType().Name } }
}
function Sha256Text([string] $Value) {
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function ExecutablePath([string] $Command) {
    if ([string]::IsNullOrWhiteSpace($Command) -or $Command -eq 'Any') { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($expanded -match '^\s*"([^"]+\.exe)"(?:\s|$)') { $path = $Matches[1] }
    elseif ($expanded -match '^\s*(.+?\.exe)(?:\s|$)') { $path = $Matches[1] }
    else { return $null }
    if (-not [IO.Path]::IsPathFullyQualified($path)) { return $null }
    try { return [IO.Path]::GetFullPath($path).ToLowerInvariant() }
    catch { return $null }
}
function ExecutableHash([string] $Command) {
    $path = ExecutablePath $Command
    if ($path) { return Sha256Text $path }
    return $null
}
function HashValues($Values) {
    return @($Values | ForEach-Object { Sha256Text ([string]$_) } | Sort-Object)
}
function AdapterCategory([string] $Name, [string] $Description) {
    $label = "$Name $Description"
    if ($label -match '(?i)loopback pseudo-interface') { return 'Loopback' }
    if ($label -match '(?i)bluetooth|\bPAN\b') { return 'BluetoothPAN' }
    if ($label -match '(?i)cellular|WWAN|mobile|\bLTE\b|\b5G\b|modem') { return 'Mobile' }
    if ($label -match '(?i)\bUSB\b|RNDIS|tether|\bNCM\b') { return 'USB' }
    if ($label -match '(?i)VPN|\bTAP\b|\bTUN\b|Wintun|WireGuard|OpenVPN|IPSec|WAN Miniport') { return 'VPN' }
    if ($label -match '(?i)vEthernet|virtual|Hyper-V|VMware|VirtualBox|bridge|container|\bWSL\b') { return 'VirtualOrBridge' }
    if ($label -match '(?i)Wi-Fi|wireless|802\.11|\bWLAN\b') { return 'WiFi' }
    if ($label -match '(?i)ethernet|802\.3|\bLAN\b') { return 'Ethernet' }
    return 'Other'
}

$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$tcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$rdpLocal = RegistryValue $base 'fDenyTSConnections'
$rdpPolicy = RegistryValue $policy 'fDenyTSConnections'
$rdpPort = RegistryValue $tcp 'PortNumber'
$ports = @(3389, 3392)
if ($rdpPort.State -eq 'Accessible' -and $rdpPort.Data -is [int] -and $rdpPort.Data -ge 1 -and $rdpPort.Data -le 65535) {
    $ports += [int]$rdpPort.Data
}
$ports = @($ports | Select-Object -Unique)
$processSession = (Get-Process -Id $PID).SessionId
$child = [ChildStreamReadOnlyWts]::AssociatedChild()
$console = [ChildStreamReadOnlyWts]::WTSGetActiveConsoleSessionId()

$report = [ordered]@{
    Schema = 'ChildStream.ReadOnlyFeasibilityInventory.v3'
    CapturedUtc = [DateTime]::UtcNow.ToString('o')
    HostMutation = $false
    Windows = Observed { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop;
        [ordered]@{ State = 'Accessible'; Caption = $os.Caption; BuildNumber = [int]$os.BuildNumber; Version = $os.Version } }
    AccountBindingHash = Sha256Text ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    ChildFeature = [ChildStreamReadOnlyWts]::Feature()
    Sessions = [ordered]@{
        ProcessSessionId = $processSession
        ActiveConsoleSessionId = $console
        Current = [ChildStreamReadOnlyWts]::Session([uint32]$processSession)
        CurrentProtocol = [ChildStreamReadOnlyWts]::CurrentProtocol()
        AssociatedChild = $child
        AssociatedChildDetails = if ($child.State -eq 'Accessible') { [ChildStreamReadOnlyWts]::Session([uint32]$child.SessionId) } else { $null }
        Enumerated = [ChildStreamReadOnlyWts]::Sessions()
    }
    Rdp = [ordered]@{
        LocalDenyConnections = $rdpLocal
        PolicyDenyConnections = $rdpPolicy
        TcpPort = $rdpPort
        Services = Observed {
            $selected = @(Get-CimInstance Win32_Service -ErrorAction Stop |
                Where-Object { $_.Name -in 'TermService','UmRdpService','SessionEnv' })
            $term = $selected | Where-Object Name -eq 'TermService' | Select-Object -First 1
            $termPath = if ($term) { ExecutablePath $term.PathName } else { $null }
            $systemHost = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\svchost.exe')).ToLowerInvariant()
            [ordered]@{ State = 'Accessible'; Items = @($selected | Select-Object Name, State, StartMode);
                TermServiceImageHash = if ($termPath) { Sha256Text $termPath } else { $null };
                TermServiceImageState = if ($termPath) { 'Accessible' } else { 'Unknown' };
                TermServiceIsClassicHost = [bool]($termPath -and $termPath -eq $systemHost) }
        }
        TcpListener = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalPort -in $ports } | Select-Object LocalAddress, LocalPort, State) } }
        UdpEndpoint = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetUDPEndpoint -ErrorAction Stop |
            Where-Object { $_.LocalPort -in $ports } | Select-Object LocalAddress, LocalPort) } }
        FirewallProfiles = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object { [ordered]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled;
                DefaultInboundAction = [string]$_.DefaultInboundAction } }) } }
        Firewall = Observed {
            $broadAllowCount = 0
            $selectedInboundAllowCount = 0
            $unknownHeaderCount = 0
            $items = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop | ForEach-Object {
                $rule = $_
                $enabled = [string]$rule.Enabled; $direction = [string]$rule.Direction; $action = [string]$rule.Action
                if ($enabled -notin @('True','False') -or $direction -notin @('Inbound','Outbound') -or
                    $action -notin @('Allow','Block')) { $unknownHeaderCount++ }
                $rdpName = $rule.Name -like 'RemoteDesktop-*' -or $rule.Name -like 'MCX-TERMSRV*' -or
                    $rule.DisplayGroup -like '*Remote Desktop*'
                if (-not ($enabled -eq 'True' -and $direction -eq 'Inbound' -and $action -eq 'Allow') -and
                    -not $rdpName) { return }
                if ($enabled -eq 'True' -and $direction -eq 'Inbound' -and $action -eq 'Allow') {
                    $selectedInboundAllowCount++
                }
                $filter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
                $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
                $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
                $interface = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
                $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
                $security = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
                $broad = @($filter.LocalPort) -contains 'Any'
                if ($enabled -eq 'True' -and $direction -eq 'Inbound' -and $action -eq 'Allow' -and $broad) {
                    $broadAllowCount++
                }
                $package = [string]$application.Package
                $securityPrincipals = @($security.LocalUser,$security.RemoteUser,$security.RemoteMachine) |
                    Where-Object { $_ -and [string]$_ -ne 'Any' }
                $owner = [string]$rule.Owner
                [ordered]@{ Name = [string]$rule.Name; Enabled = $enabled; Direction = $direction;
                    Action = $action; Profile = [string]$rule.Profile; Protocol = [string]$filter.Protocol;
                    LocalPort = @($filter.LocalPort | ForEach-Object { [string]$_ });
                    RemotePort = @($filter.RemotePort | ForEach-Object { [string]$_ });
                    LocalAddress = @($address.LocalAddress | ForEach-Object { [string]$_ });
                    RemoteAddress = @($address.RemoteAddress | ForEach-Object { [string]$_ });
                    ProgramState = if ([string]$application.Program -eq 'Any') { 'Any' }
                        elseif (ExecutableHash ([string]$application.Program)) { 'Accessible' } else { 'Unknown' };
                    ProgramHash = ExecutableHash ([string]$application.Program);
                    PackageState = if ([string]::IsNullOrEmpty($package) -or $package -eq 'Any') { 'Any' }
                        elseif ($package -match '^S-1-15-2(-\d+)+$') { 'AppPackage' } else { 'Unknown' };
                    PackageHash = if ($package -and $package -ne 'Any') { Sha256Text $package } else { $null };
                    Service = [string]$service.Service;
                    InterfaceAliasHashes = HashValues @($interface.InterfaceAlias);
                    InterfaceType = [string]$interfaceType.InterfaceType;
                    Authentication = [string]$security.Authentication;
                    Encryption = [string]$security.Encryption;
                    OverrideBlockRules = [string]$security.OverrideBlockRules;
                    SecurityScope = if ($securityPrincipals.Count -gt 0) { 'Restricted' } else { 'Any' };
                    SecurityPrincipalHash = if ($securityPrincipals.Count -gt 0) {
                        Sha256Text (($securityPrincipals | ForEach-Object { [string]$_ }) -join '|') } else { $null };
                    OwnerKind = if ($owner -match '^S-1-15-2(-\d+)+$') { 'AppPackage' }
                        elseif ([string]::IsNullOrEmpty($owner)) { 'Absent' } else { 'Other' };
                    OwnerHash = Sha256Text $owner;
                    PolicyAppIdHash = Sha256Text ([string]$rule.PolicyAppId);
                    RemoteDynamicAddressCount = @($rule.RemoteDynamicKeywordAddresses).Count;
                    EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy;
                    LocalOnlyMapping = [bool]$rule.LocalOnlyMapping;
                    LooseSourceMapping = [bool]$rule.LooseSourceMapping;
                    PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType;
                    PolicyStoreSourceHash = Sha256Text ([string]$rule.PolicyStoreSource);
                    PrimaryStatus = [string]$rule.PrimaryStatus; StatusCode = $rule.StatusCode;
                    EnforcementStatus = @($rule.EnforcementStatus | ForEach-Object { [string]$_ });
                    RdpNamed = [bool]$rdpName }
            })
            [ordered]@{ State = 'Accessible'; Items = $items; BroadInboundAllowCount = $broadAllowCount;
                SelectedInboundAllowCount = $selectedInboundAllowCount;
                UnknownHeaderCount = $unknownHeaderCount;
                Coverage = 'All enabled inbound allow rules plus named RDP rules from ActiveStore; all associated filters read; not a complete reachability proof' }
        }
        NetworkClosedAssessment = 'Unverified; local inventory cannot prove remote reachability or all listener and firewall paths'
    }
    Network = [ordered]@{
        Adapters = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetAdapter -Name '*' -IncludeHidden -ErrorAction Stop |
            ForEach-Object { [ordered]@{ InterfaceIndex = [int]$_.ifIndex;
                NameHash = Sha256Text ([string]$_.Name);
                DescriptionHash = Sha256Text ([string]$_.InterfaceDescription);
                InterfaceGuidHash = Sha256Text ([string]$_.InterfaceGuid);
                Category = AdapterCategory ([string]$_.Name) ([string]$_.InterfaceDescription);
                Status = [string]$_.Status; MediaConnectionState = [string]$_.MediaConnectionState } }) } }
        IpInterfaces = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetIPInterface -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop |
            ForEach-Object { [ordered]@{ InterfaceIndex = [int]$_.InterfaceIndex;
                CompartmentId = [int]$_.CompartmentId; AddressFamily = [string]$_.AddressFamily;
                AliasHash = Sha256Text ([string]$_.InterfaceAlias);
                LoopbackAlias = [bool]($_.InterfaceIndex -eq 1 -and $_.InterfaceAlias -eq 'Loopback Pseudo-Interface 1');
                ConnectionState = [string]$_.ConnectionState } }) } }
        IpAddresses = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetIPAddress -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop |
            ForEach-Object { [ordered]@{ InterfaceIndex = [int]$_.InterfaceIndex;
                CompartmentId = [int]$_.CompartmentId; AddressFamily = [string]$_.AddressFamily;
                Address = [string]$_.IPAddress; PrefixLength = [int]$_.PrefixLength;
                AddressState = [string]$_.AddressState } }) } }
        Routes = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop |
            ForEach-Object { [ordered]@{ InterfaceIndex = [int]$_.InterfaceIndex;
                CompartmentId = [int]$_.CompartmentId; AddressFamily = [string]$_.AddressFamily;
                DestinationPrefix = [string]$_.DestinationPrefix;
                NextHop = [string]$_.NextHop; State = [string]$_.State } }) } }
        Scope = 'Visible and hidden adapters plus active IPv4/IPv6 interfaces, addresses, and routes in all compartments; no connectivity inference from default routes alone'
    }
    Displays = Observed {
        Add-Type -AssemblyName System.Windows.Forms
        [ordered]@{ State = 'Accessible'; PhysicalIdentity = 'Unverified';
            Items = @([Windows.Forms.Screen]::AllScreens | ForEach-Object {
                [ordered]@{ Primary = $_.Primary; X = $_.Bounds.X; Y = $_.Bounds.Y;
                    Width = $_.Bounds.Width; Height = $_.Bounds.Height } }) }
    }
    Sunshine = Observed {
        $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)sunshine' -or $_.DisplayName -match '(?i)sunshine' -or
            $_.PathName -match '(?i)(^|[\\/])sunshine\.exe([\s"\x27]|$)'
        } | ForEach-Object { [ordered]@{ Name = $_.Name; State = $_.State; StartMode = $_.StartMode;
            CommandHash = Sha256Text $_.PathName } })
        $processes = @(Get-Process sunshine -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{ Id = $_.Id; SessionId = $_.SessionId; PathState = if ($_.Path) { 'Accessible' } else { 'Unknown' };
                PathHash = Sha256Text $_.Path } })
        [ordered]@{ State = 'Accessible'; Services = $services;
            Processes = $processes; ConfigurationContentsRead = $false }
    }
    Vdd = Observed {
        $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop)
        $items = @(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
            ($_.Class -eq 'Display' -and $_.FriendlyName -eq 'Virtual Display Driver' -and $_.InstanceId -like 'ROOT\*') -or
            ($_.Class -eq 'Monitor' -and $_.FriendlyName -eq 'Generic Monitor (VDD by MTT)' -and $_.InstanceId -like 'DISPLAY\*')
        } | ForEach-Object {
            $device = $_
            $driver = $drivers | Where-Object { $_.DeviceID -eq $device.InstanceId } | Select-Object -First 1
            [ordered]@{ Name = $device.FriendlyName; Status = $device.Status; Class = $device.Class;
                InstanceIdHash = Sha256Text $device.InstanceId; DriverProvider = $driver.DriverProviderName;
                DriverVersion = $driver.DriverVersion; InfName = $driver.InfName;
                IdentityState = if ($driver) { 'Accessible' } else { 'Unknown' } }
        })
        [ordered]@{ State = 'Accessible'; Items = $items; MatchRule = 'Display/Monitor class, exact name and PnP root, with signed-driver metadata' }
    }
}

[pscustomobject]$report | ConvertTo-Json -Depth 12
