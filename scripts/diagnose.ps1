<#
.SYNOPSIS
  Read-only ChildStream prerequisites and recovery inventory.
.DESCRIPTION
  Does not print passwords, Sunshine config contents, pairing data, or user names.
  It does not run ChildStream, Sunshine, or installer commands.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$sunshineExe = Join-Path $root 'Sunshine\Sunshine\sunshine.exe'
$sunshineConf = Join-Path $root 'Sunshine\Sunshine\config\sunshine.conf'
$startupHook = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup\childstream-sunshine.cmd'
$shortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Child Session.lnk'

# These APIs only read session state. They do not enable or create a session.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ChildStreamDiagnosticsNative {
    [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSIsChildSessionsEnabled(out bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSGetChildSessionId(out uint sessionId);
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
}
'@

function Read-RegistryValue([string] $Path, [string] $Name) {
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    } catch [System.Management.Automation.PSArgumentException] {
        return $null
    } catch [System.UnauthorizedAccessException] {
        return 'ACCESS_DENIED'
    }
}

$report = [ordered]@{
    Source = 'read-only ChildStream diagnostic'
    RepositoryRoot = $root
    OS = $null
    Session = [ordered]@{ CurrentProcessSessionId = (Get-Process -Id $PID).SessionId; ActiveConsoleSessionId = [ChildStreamDiagnosticsNative]::WTSGetActiveConsoleSessionId(); ChildSessionsEnabled = $null; AssociatedChildSessionId = $null; ApiError = $null }
    Registry = [ordered]@{
        RdpConnectionsDenied = Read-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        RdpPolicyConnectionsDenied = Read-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
        DwmFrameInterval = Read-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' 'DWMFRAMEINTERVAL'
        SuppressWhenMinimized = Read-RegistryValue 'HKCU:\Software\Microsoft\Terminal Server Client' 'RemoteDesktop_SuppressWhenMinimized'
    }
    Files = [ordered]@{
        PortableSunshinePresent = Test-Path -LiteralPath $sunshineExe -PathType Leaf
        PortableSunshineConfigPresent = Test-Path -LiteralPath $sunshineConf -PathType Leaf
        LegacyCredentialPresent = Test-Path -LiteralPath (Join-Path $root 'cred.bin') -PathType Leaf
        AllUsersStartupHookPresent = Test-Path -LiteralPath $startupHook -PathType Leaf
        DesktopShortcutPresent = Test-Path -LiteralPath $shortcut -PathType Leaf
    }
    Firewall = @()
    Ports = @()
    SunshineProcesses = @()
    VideoControllers = @()
    AudioDevices = @()
    VirtualGamepadCandidates = @()
    NeedsLiveVerification = @('child-session logon', 'RDP listener requirement', 'NVENC encoding', 'audio separation', 'controller forwarding', 'game performance')
    Recovery = @('Existing setup has no transaction journal; inventory and restore each prior host value manually before removal.')
}

$enabled = $false
$childId = [uint32]::MaxValue
if ([ChildStreamDiagnosticsNative]::WTSIsChildSessionsEnabled([ref]$enabled)) {
    $report.Session.ChildSessionsEnabled = $enabled
} else {
    $report.Session.ApiError = "WTSIsChildSessionsEnabled failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}
if ([ChildStreamDiagnosticsNative]::WTSGetChildSessionId([ref]$childId)) {
    if ($childId -ne [uint32]::MaxValue) { $report.Session.AssociatedChildSessionId = $childId }
} else {
    $report.Session.ApiError = "WTSGetChildSessionId failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

try { $report.OS = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber, Version }
catch { $report.OS = "UNAVAILABLE: $($_.Exception.Message)" }

try {
    $report.Firewall = @(Get-NetFirewallRule -DisplayName 'ChildStream Sunshine' -ErrorAction SilentlyContinue | ForEach-Object {
        $rule = $_
        $port = $rule | Get-NetFirewallPortFilter
        $address = $rule | Get-NetFirewallAddressFilter
        [pscustomobject]@{ DisplayName = $rule.DisplayName; Enabled = $rule.Enabled; Direction = $rule.Direction; Action = $rule.Action; Profile = $rule.Profile; Protocol = $port.Protocol; LocalPort = $port.LocalPort; RemoteAddress = $address.RemoteAddress }
    })
} catch { $report.Firewall = @("UNAVAILABLE: $($_.Exception.Message)") }

try {
    $report.Ports = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -in 3389,48984,48989,48990,49010 | Select-Object -Unique LocalAddress,LocalPort,State)
} catch { $report.Ports = @("UNAVAILABLE: $($_.Exception.Message)") }
try { $report.SunshineProcesses = @(Get-Process sunshine -ErrorAction SilentlyContinue | Select-Object Id,SessionId,Path) }
catch { $report.SunshineProcesses = @("UNAVAILABLE: $($_.Exception.Message)") }

try { $report.VideoControllers = @(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion) }
catch { $report.VideoControllers = @("UNAVAILABLE: $($_.Exception.Message)") }
try { $report.AudioDevices = @(Get-CimInstance Win32_SoundDevice | Select-Object Name,Status) }
catch { $report.AudioDevices = @("UNAVAILABLE: $($_.Exception.Message)") }
try { $report.VirtualGamepadCandidates = @(Get-PnpDevice -PresentOnly | Where-Object FriendlyName -Match 'ViGEm|Virtual Gamepad|Virtual HID' | Select-Object FriendlyName,Status) }
catch { $report.VirtualGamepadCandidates = @("UNAVAILABLE: $($_.Exception.Message)") }

[pscustomobject]$report | ConvertTo-Json -Depth 6
