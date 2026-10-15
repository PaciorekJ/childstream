$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$artifacts = Join-Path $PSScriptRoot '.artifacts'
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'The .NET Framework C# compiler is unavailable.' }
$sources = @(Join-Path $root 'src\ChildStream.cs'), @(Join-Path $root 'src\ChildSessionLifecycle.cs'), @(Join-Path $root 'src\SessionSignOutGuard.cs'), @(Join-Path $root 'src\LegacyCredentialCleanup.cs'), @(Join-Path $root 'src\InstallerFoundation.cs'), @(Join-Path $root 'src\InstallerInventory.cs'), @(Join-Path $root 'src\TransactionOwnership.cs'), @(Join-Path $root 'src\PortableSunshine.cs'), @(Join-Path $root 'src\PortableExtractionTransaction.cs'), @(Join-Path $root 'src\ProductIntegration.cs'), @(Join-Path $root 'src\ProductAcceptance.cs'), @(Join-Path $root 'src\WindowsOwnedInstallerHost.cs')
$productReferences = @('/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:Microsoft.CSharp.dll','/r:System.IO.Compression.dll','/r:System.IO.Compression.FileSystem.dll','/r:System.Management.dll','/r:System.ServiceProcess.dll')
& $csc /nologo /target:exe /main:Program "/out:$artifacts\ChildStream.exe" $productReferences $sources
if ($LASTEXITCODE -ne 0) { throw 'Launcher compilation failed.' }
& $csc /nologo /target:exe /main:LauncherLogicTests "/out:$artifacts\LauncherLogicTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'LauncherLogicTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Offline test compilation failed.' }
& (Join-Path $artifacts 'LauncherLogicTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline launcher tests failed.' }
& $csc /nologo /target:exe /main:InstallerFoundationTests "/out:$artifacts\InstallerFoundationTests.exe" (Join-Path $root 'src\InstallerFoundation.cs') (Join-Path $root 'src\InstallerInventory.cs') (Join-Path $root 'src\TransactionOwnership.cs') (Join-Path $PSScriptRoot 'InstallerFoundationTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Installer test compilation failed.' }
& (Join-Path $artifacts 'InstallerFoundationTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline installer tests failed.' }
& $csc /nologo /target:exe /main:ProductIntegrationTests "/out:$artifacts\ProductIntegrationTests.exe" /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll /r:System.Management.dll /r:System.ServiceProcess.dll (Join-Path $root 'src\InstallerFoundation.cs') (Join-Path $root 'src\InstallerInventory.cs') (Join-Path $root 'src\TransactionOwnership.cs') (Join-Path $root 'src\ChildSessionLifecycle.cs') (Join-Path $root 'src\PortableSunshine.cs') (Join-Path $root 'src\PortableExtractionTransaction.cs') (Join-Path $root 'src\ProductIntegration.cs') (Join-Path $root 'src\ProductAcceptance.cs') (Join-Path $root 'src\WindowsOwnedInstallerHost.cs') (Join-Path $PSScriptRoot 'ProductIntegrationTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Product integration test compilation failed.' }
& (Join-Path $artifacts 'ProductIntegrationTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline product integration tests failed.' }
& $csc /nologo /target:exe /main:FeasibilityProbeTests "/out:$artifacts\FeasibilityProbeTests.exe" /r:System.Windows.Forms.dll /r:System.Web.Extensions.dll /r:Microsoft.CSharp.dll (Join-Path $root 'src\FeasibilityProbe.cs') (Join-Path $root 'src\WindowsFeasibilityHost.cs') (Join-Path $root 'src\FirewallRdpAssessment.cs') (Join-Path $root 'src\NetworkIsolationAssessment.cs') (Join-Path $root 'src\FeasibilityProbeProgram.cs') (Join-Path $root 'src\InstallerFoundation.cs') (Join-Path $root 'src\TransactionOwnership.cs') (Join-Path $root 'src\ChildSessionLifecycle.cs') (Join-Path $PSScriptRoot 'FeasibilityProbeTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Feasibility probe test compilation failed.' }
& (Join-Path $artifacts 'FeasibilityProbeTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline feasibility probe tests failed.' }
& $csc /nologo /target:exe /main:FeasibilityProbeProgram "/out:$artifacts\ChildStreamFeasibilityProbe.exe" /r:System.Windows.Forms.dll /r:System.Web.Extensions.dll /r:Microsoft.CSharp.dll (Join-Path $root 'src\FeasibilityProbe.cs') (Join-Path $root 'src\WindowsFeasibilityHost.cs') (Join-Path $root 'src\FirewallRdpAssessment.cs') (Join-Path $root 'src\NetworkIsolationAssessment.cs') (Join-Path $root 'src\FeasibilityProbeProgram.cs') (Join-Path $root 'src\InstallerFoundation.cs') (Join-Path $root 'src\TransactionOwnership.cs') (Join-Path $root 'src\ChildSessionLifecycle.cs')
if ($LASTEXITCODE -ne 0) { throw 'Windows feasibility adapter compilation failed.' }
$inventorySource = Get-Content (Join-Path $root 'scripts\feasibility-inventory.ps1') -Raw
$inventoryTokens = $null
$inventoryErrors = $null
[System.Management.Automation.Language.Parser]::ParseInput($inventorySource, [ref]$inventoryTokens, [ref]$inventoryErrors) | Out-Null
if ($inventoryErrors.Count -ne 0) { throw "Read-only inventory syntax failed: $($inventoryErrors[0].Message)" }
$nativeShim = [regex]::Match($inventorySource, "(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
if (-not $nativeShim.Success) { throw 'Read-only inventory native shim is missing.' }
Add-Type -TypeDefinition $nativeShim.Groups[1].Value -ErrorAction Stop
Write-Output 'Read-only inventory syntax and native shim compilation passed (host API calls not run).'
& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'NetworkBoundaryDiagnosticTests.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Network boundary diagnostic regression tests failed.' }
foreach ($scriptName in @('network-boundary-diagnostic.ps1','network-source-shape.ps1','hns-readonly.ps1')) {
    $diagnosticPath = Join-Path $root "scripts\$scriptName"
    $diagnosticTokens = $null
    $diagnosticErrors = $null
    $diagnosticAst = [System.Management.Automation.Language.Parser]::ParseFile($diagnosticPath,
        [ref]$diagnosticTokens, [ref]$diagnosticErrors)
    if ($diagnosticErrors.Count -ne 0) { throw "$scriptName syntax failed: $($diagnosticErrors[0].Message)" }
    $writes = @($diagnosticAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -match '^(Set|New|Remove|Disable|Enable|Stop|Restart|Start|Connect|Disconnect)-'
    }, $true))
    if ($writes.Count -ne 0) { throw "$scriptName contains a host-mutation command: $($writes[0].GetCommandName())" }
}
if (Test-Path -LiteralPath (Join-Path $root 'scripts\workload-inventory.ps1')) {
    throw 'Retired cross-project workload inventory must not be present.'
}
Write-Output 'Read-only network, source-shape and HNS syntax/mutation-command audit passed.'
