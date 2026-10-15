<# Read-only Windows PowerShell 5.1 bridge for the inbox HostNetworkingService module. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
try {
    Import-Module HostNetworkingService -ErrorAction Stop
    $networks = @(Get-HnsNetwork -ErrorAction Stop | Select-Object ID,Name,Type,NetworkAdapterName)
    $endpoints = @(Get-HnsEndpoint -ErrorAction Stop | Select-Object ID,VirtualNetwork,VirtualNetworkName,State)
    [pscustomobject]@{ Schema = 'ChildStream.HnsReadOnly.v1'; HostMutation = $false;
        Networks = $networks; Endpoints = $endpoints } | ConvertTo-Json -Depth 8 -Compress
}
catch {
    # Preserve only the exception type in local diagnostics; no host identifiers.
    [Console]::Error.WriteLine($_.Exception.GetType().Name)
    exit 1
}
