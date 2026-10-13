<#
.SYNOPSIS
  Read-only, typed inventory for the proposed child-session experiment.
.DESCRIPTION
  Emits JSON only. It never calls child-session enable/connect/logoff APIs, writes a
  registry value, changes a firewall rule, or reads Sunshine pairing/config files.
  This adapter has not been run on the target host in this PR.
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

$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$tcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$rdpLocal = RegistryValue $base 'fDenyTSConnections'
$rdpPolicy = RegistryValue $policy 'fDenyTSConnections'
$rdpPort = RegistryValue $tcp 'PortNumber'
$ports = @(3389)
if ($rdpPort.State -eq 'Accessible' -and $rdpPort.Data -is [int] -and $rdpPort.Data -ge 1 -and $rdpPort.Data -le 65535) {
    $ports += [int]$rdpPort.Data
}
$ports = @($ports | Select-Object -Unique)
$processSession = (Get-Process -Id $PID).SessionId
$child = [ChildStreamReadOnlyWts]::AssociatedChild()
$console = [ChildStreamReadOnlyWts]::WTSGetActiveConsoleSessionId()

$report = [ordered]@{
    Schema = 'ChildStream.ReadOnlyFeasibilityInventory.v1'
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
        AssociatedChild = $child
        AssociatedChildDetails = if ($child.State -eq 'Accessible') { [ChildStreamReadOnlyWts]::Session([uint32]$child.SessionId) } else { $null }
        Enumerated = [ChildStreamReadOnlyWts]::Sessions()
    }
    Rdp = [ordered]@{
        LocalDenyConnections = $rdpLocal
        PolicyDenyConnections = $rdpPolicy
        TcpPort = $rdpPort
        Listener = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalPort -in $ports } | Select-Object LocalAddress, LocalPort, State) } }
        Firewall = Observed {
            $items = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                $rule = $_
                $filter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                if ($filter.LocalPort -in $ports -or $rule.DisplayGroup -like '*Remote Desktop*') {
                    $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
                    [ordered]@{ Name = $rule.Name; Enabled = [string]$rule.Enabled; Direction = [string]$rule.Direction;
                        Action = [string]$rule.Action; Profile = [string]$rule.Profile; Protocol = [string]$filter.Protocol;
                        LocalPort = @($filter.LocalPort); RemoteAddress = @($address.RemoteAddress) }
                }
            })
            [ordered]@{ State = 'Accessible'; Items = $items }
        }
        NetworkClosedAssessment = 'Unverified; inspect policy, all listeners and effective firewall before approval'
    }
    Displays = Observed {
        Add-Type -AssemblyName System.Windows.Forms
        [ordered]@{ State = 'Accessible'; PhysicalIdentity = 'Unverified';
            Items = @([Windows.Forms.Screen]::AllScreens | ForEach-Object {
                [ordered]@{ Primary = $_.Primary; X = $_.Bounds.X; Y = $_.Bounds.Y;
                    Width = $_.Bounds.Width; Height = $_.Bounds.Height } }) }
    }
    Sunshine = Observed {
        $service = Get-CimInstance Win32_Service -Filter "Name = 'sunshine'" -ErrorAction Stop
        $processes = @(Get-Process sunshine -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{ Id = $_.Id; SessionId = $_.SessionId; PathHash = Sha256Text $_.Path } })
        [ordered]@{ State = 'Accessible'; ServicePresent = $null -ne $service;
            ServiceState = if ($service) { $service.State } else { $null };
            ServiceCommandHash = if ($service) { Sha256Text $service.PathName } else { $null };
            Processes = $processes; ConfigurationContentsRead = $false }
    }
    Vdd = Observed { [ordered]@{ State = 'Accessible'; Items = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
        Where-Object { $_.FriendlyName -match 'Virtual Display|IDD|VDD' } |
        ForEach-Object { [ordered]@{ Name = $_.FriendlyName; Status = $_.Status; Class = $_.Class } }) } }
}

[pscustomobject]$report | ConvertTo-Json -Depth 12
