# Read-only shape probe for a separately authorized operator pass. The default
# synthetic mode makes no Windows firewall, WTS, or CIM call.
[CmdletBinding()]
param(
    [ValidateSet('Synthetic','Read')][string] $Mode = 'Synthetic',
    [string] $NativeExecutable = (Join-Path $PSScriptRoot '..\tests\.artifacts\ChildStreamExclusionShape.exe')
)
$ErrorActionPreference = 'Stop'

function Describe-PropertyShape($item) {
    if ($null -eq $item) {
        return [ordered]@{ PropertyPresent = $false; Kind = 'NoProfileObject'; Count = $null; Type = $null }
    }
    $properties = @($item.PSObject.Properties.Match('DisabledInterfaceAliases'))
    if ($properties.Count -ne 1) {
        return [ordered]@{ PropertyPresent = $false; Kind = 'MissingOrAmbiguous'; Count = $null; Type = $null }
    }
    $value = $properties[0].Value
    if ($null -eq $value) {
        return [ordered]@{ PropertyPresent = $true; Kind = 'NullLike'; Count = $null; Type = $null }
    }
    if ($value -is [array]) {
        return [ordered]@{ PropertyPresent = $true; Kind = 'Array'; Count = $value.Count;
            Type = $value.GetType().FullName }
    }
    return [ordered]@{ PropertyPresent = $true; Kind = 'Other'; Count = $null;
        Type = $value.GetType().FullName }
}

if ($Mode -eq 'Synthetic') {
    [ordered]@{
        Schema = 'ChildStream.ExclusionShapeSynthetic.v1'
        Missing = Describe-PropertyShape ([pscustomobject]@{})
        Null = Describe-PropertyShape ([pscustomobject]@{ DisabledInterfaceAliases = $null })
        Empty = Describe-PropertyShape ([pscustomobject]@{ DisabledInterfaceAliases = @() })
        Nonempty = Describe-PropertyShape ([pscustomobject]@{ DisabledInterfaceAliases = @('hidden') })
    } | ConvertTo-Json -Depth 5 -Compress
    return
}

# Neither this guard nor the native utility elevates the operator. A failure
# stops before any profile read. Protocol 0 and exact active console session
# replace the unreliable SESSIONNAME environment-variable check.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ChildStreamExclusionConsole {
  [DllImport("wtsapi32.dll", EntryPoint="WTSQuerySessionInformationW", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool Query(IntPtr server, uint session, int infoClass,
                                  out IntPtr data, out int bytes);
  [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr data);
  [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
}
'@
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$session = [uint32][Diagnostics.Process]::GetCurrentProcess().SessionId
$active = [ChildStreamExclusionConsole]::WTSGetActiveConsoleSessionId()
$buffer = [IntPtr]::Zero
$length = 0
$protocol = $null
$queried = [ChildStreamExclusionConsole]::Query([IntPtr]::Zero, $session, 16,
    [ref]$buffer, [ref]$length)
try {
    if ($queried -and $buffer -ne [IntPtr]::Zero -and $length -ge 2) {
        $protocol = [uint16][Runtime.InteropServices.Marshal]::ReadInt16($buffer)
    }
}
finally { if ($buffer -ne [IntPtr]::Zero) { [ChildStreamExclusionConsole]::WTSFreeMemory($buffer) } }
if ($identity.Name -ne 'JASON-DESKTOP\Jason' -or -not $elevated -or $protocol -ne 0 -or
    $session -ne $active -or $active -eq [uint32]::MaxValue) {
    throw 'Same-account elevated physical-console context was not established; no exclusion read was attempted.'
}
if (-not (Test-Path -LiteralPath $NativeExecutable -PathType Leaf)) {
    throw 'The reviewed native shape executable is unavailable.'
}
$nativeHash = (Get-FileHash -LiteralPath $NativeExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
$nativeText = & $NativeExecutable --read
if ($LASTEXITCODE -ne 0) { throw "Native exclusion-shape read failed with exit code $LASTEXITCODE." }
$native = $nativeText | ConvertFrom-Json
if ($native.Schema -ne 'ChildStream.ExclusionVariantShape.v1' -or @($native.Profiles).Count -ne 3) {
    throw 'Native exclusion-shape output is incomplete.'
}
$profiles = @()
foreach ($spec in @(@{ Name='Domain'; Bit=1 }, @{ Name='Private'; Bit=2 },
                    @{ Name='Public'; Bit=4 })) {
    $nativeRow = @($native.Profiles | Where-Object ProfileBit -eq $spec.Bit)
    if ($nativeRow.Count -ne 1) { throw 'Native profile shape attribution is ambiguous.' }
    try {
        $rows = @(Get-NetFirewallProfile -Name $spec.Name -PolicyStore ActiveStore -ErrorAction Stop)
        $cim = if ($rows.Count -eq 1) { Describe-PropertyShape $rows[0] } else {
            [ordered]@{ PropertyPresent = $false; Kind = 'ProfileCountNotOne'; Count = $null; Type = $null }
        }
        $profiles += [ordered]@{ Profile = $spec.Name; Native = $nativeRow[0];
            CimProfileCount = $rows.Count; Cim = $cim }
    } catch {
        $profiles += [ordered]@{ Profile = $spec.Name; Native = $nativeRow[0];
            CimProfileCount = $null; Cim = [ordered]@{ Kind = 'ReadError';
                ErrorType = $_.Exception.GetType().Name } }
    }
}
[ordered]@{ Schema = 'ChildStream.ProfileExclusionShape.v1';
    Utc = [DateTime]::UtcNow.ToString('o'); NativeExecutableSha256 = $nativeHash;
    Profiles = $profiles } | ConvertTo-Json -Depth 8 -Compress
