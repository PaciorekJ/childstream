<#
.SYNOPSIS
  Redacted read-only source-shape report for a physical-console operator.
.DESCRIPTION
  Queries property availability and the existing network-boundary predicates.
  Emits counts, booleans and verdicts only; no account, interface, address,
  route, container, firewall-rule or fingerprint values are emitted.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Shape([scriptblock]$Read, [string[]]$Properties) {
    try {
        $items = @(& $Read)
        $coverage = [ordered]@{}
        foreach ($property in $Properties) {
            $coverage[$property] = if ($items.Count -eq 0) { $null }
                else { @($items | Where-Object {
                    $member = $_.PSObject.Properties[$property]
                    $null -ne $member -and $null -ne $member.Value -and
                        -not [string]::IsNullOrWhiteSpace([string]$member.Value)
                }).Count -eq $items.Count }
        }
        return [pscustomobject]@{ State = 'Accessible'; Count = $items.Count; CompletePropertyCoverage = $coverage }
    }
    catch {
        return [pscustomobject]@{ State = 'Inaccessible'; Count = $null; CompletePropertyCoverage = $null;
            ErrorType = $_.Exception.GetType().Name }
    }
}

$inventory = (& pwsh -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'feasibility-inventory.ps1') |
    ConvertFrom-Json -ErrorAction Stop)
$physicalConsole = $inventory.Sessions.ProcessSessionId -eq $inventory.Sessions.ActiveConsoleSessionId -and
    $inventory.Sessions.CurrentProtocol.State -eq 'Accessible' -and
    $inventory.Sessions.CurrentProtocol.Value -eq 0
if (-not $physicalConsole) { throw 'Run only from the physical Windows console, not RDP or a remote session.' }

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$diagnostic = (& pwsh -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'network-boundary-diagnostic.ps1') |
    ConvertFrom-Json -ErrorAction Stop)
$hnsShapeRead = try {
    $json = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $PSScriptRoot 'hns-readonly.ps1') 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $json) { throw 'HNS source is unavailable.' }
    ($json -join "`n") | ConvertFrom-Json -ErrorAction Stop
} catch { $null }

$report = [ordered]@{
    Schema = 'ChildStream.NetworkSourceShape.v1'
    HostMutation = $false
    PhysicalConsole = $true
    AlreadyElevated = $isElevated
    DiagnosticHostMutation = $diagnostic.HostMutation
    StageAPlanAuthorized = $diagnostic.StageAPlanAuthorized
    CompleteFingerprintPresent = -not [string]::IsNullOrEmpty([string]$diagnostic.CurrentNetworkFingerprint)
    Collection = $diagnostic.Collection
    Conditions = $diagnostic.Conditions
    Predicates = @($diagnostic.Predicates | Select-Object Id,Verdict)
    SourceShapes = [ordered]@{
        NetAdapter = Shape { Get-NetAdapter -Name '*' -IncludeHidden -ErrorAction Stop } @(
            'ifIndex','MacAddress','PnPDeviceID','Virtual','HardwareInterface','InterfaceDescription','InterfaceGuid')
        VMSwitch = Shape { Get-VMSwitch -ErrorAction Stop } @(
            'Id','Name','SwitchType','NetAdapterInterfaceGuid')
        HyperVHostPort = Shape { Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop } @(
            'Id','MacAddress','SwitchName','SwitchId')
        HyperVVmPort = Shape { Get-VMNetworkAdapter -VMName '*' -ErrorAction Stop } @(
            'Id','VMName','SwitchName','SwitchId')
        HnsNetwork = Shape { if ($null -eq $hnsShapeRead) { throw 'HNS source is unavailable.' }; $hnsShapeRead.Networks } @(
            'ID','Type','NetworkAdapterName')
        HnsEndpoint = Shape { if ($null -eq $hnsShapeRead) { throw 'HNS source is unavailable.' }; $hnsShapeRead.Endpoints } @(
            'ID','VirtualNetwork','State')
        BridgeBinding = Shape { Get-NetAdapterBinding -Name '*' -IncludeHidden -AllBindings -ComponentID ms_bridge -ErrorAction Stop } @(
            'Enabled','ComponentID')
        IpForwarding = Shape { Get-NetIPInterface -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop } @(
            'InterfaceIndex','CompartmentId','AddressFamily','Forwarding')
    }
}
[pscustomobject]$report | ConvertTo-Json -Depth 8
