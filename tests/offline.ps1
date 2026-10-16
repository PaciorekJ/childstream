$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$artifacts = Join-Path $PSScriptRoot '.artifacts'
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'The .NET Framework C# compiler is unavailable.' }
$sources = @(Join-Path $root 'src\ChildStream.cs'), @(Join-Path $root 'src\MoonlightPairing.cs'), @(Join-Path $root 'src\MoonlightPairingDialog.cs'), @(Join-Path $root 'src\ChildSessionLifecycle.cs'), @(Join-Path $root 'src\SessionSignOutGuard.cs'), @(Join-Path $root 'src\LegacyCredentialCleanup.cs'), @(Join-Path $root 'src\InstallerFoundation.cs'), @(Join-Path $root 'src\InstallerInventory.cs'), @(Join-Path $root 'src\TransactionOwnership.cs'), @(Join-Path $root 'src\PortableSunshine.cs'), @(Join-Path $root 'src\PortableExtractionTransaction.cs'), @(Join-Path $root 'src\ProductIntegration.cs'), @(Join-Path $root 'src\ProductAcceptance.cs'), @(Join-Path $root 'src\WindowsAudioEndpoints.cs'), @(Join-Path $root 'src\ChildRuntimeBootstrap.cs'), @(Join-Path $root 'src\WindowsOwnedInstallerHost.cs')
$productReferences = @('/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll','/r:Microsoft.CSharp.dll','/r:System.IO.Compression.dll','/r:System.IO.Compression.FileSystem.dll','/r:System.Management.dll','/r:System.ServiceProcess.dll','/r:System.Security.dll')
$sources += (Join-Path $root 'src\FirstRun.cs')
$sources += (Join-Path $root 'src\SunshinePairingTransport.cs')
$sources += (Join-Path $root 'src\WindowsProcessToken.cs')
$sources += (Join-Path $root 'src\SunshineIdentityStore.cs')
$sources += (Join-Path $root 'src\SunshineDisplayCatalog.cs')
$sources += (Join-Path $root 'src\ChildAgentProtocol.cs')
$sources += (Join-Path $root 'src\ChildAgentRuntime.cs')
$sources += (Join-Path $root 'src\GameAudioRoute.cs')
$sources += (Join-Path $root 'src\WindowsGameAudioSessions.cs')
$sources += (Join-Path $root 'src\WindowsChildAgentOperations.cs')
$sources += (Join-Path $root 'src\AgentPairingBridge.cs')
$sources += (Join-Path $root 'src\ChildAgentTaskInstaller.cs')
$sources += (Join-Path $root 'src\SetupBoundary.cs')
$sources += (Join-Path $root 'src\BoundedPipe.cs')
$sources += (Join-Path $root 'src\ProductInstall.cs')
$sources += (Join-Path $root 'src\ProductBundle.cs')
$sources += (Join-Path $root 'src\ProductInstallProgram.cs')
$sources += (Join-Path $root 'src\LanFirewallTransaction.cs')
$sources += (Join-Path $root 'src\WindowsLanFirewallHost.cs')
$sources += (Join-Path $root 'src\InstallDialog.cs')
$sources += (Join-Path $root 'src\CapabilitySelectionDialog.cs')
$sources += (Join-Path $root 'src\SetupDialog.cs')
$sources += (Join-Path $root 'src\WindowsSteamDiscovery.cs')
$sources += (Join-Path $root 'src\FeasibilityProbe.cs')
$sources += (Join-Path $root 'src\WindowsFeasibilityHost.cs')
$sources += (Join-Path $root 'src\FirewallRdpAssessment.cs')
$sources += (Join-Path $root 'src\NetworkIsolationAssessment.cs')
$sources += (Join-Path $root 'src\FeasibilityProbeProgram.cs')
$manifest = Join-Path $root 'src\ChildStream.manifest'
& $csc /nologo /target:exe /main:Program "/out:$artifacts\ChildStream.exe" "/win32manifest:$manifest" $productReferences $sources
if ($LASTEXITCODE -ne 0) { throw 'Launcher compilation failed.' }
& $csc /nologo /target:exe /main:SetupHelperProgram "/out:$artifacts\ChildStreamSetup.exe" "/win32manifest:$(Join-Path $root 'src\ChildStreamSetup.manifest')" $productReferences $sources
if ($LASTEXITCODE -ne 0) { throw 'Scoped setup helper compilation failed.' }
& $csc /nologo /target:exe /main:ProductInstallProgram "/out:$artifacts\ChildStreamBootstrap.exe" "/win32manifest:$manifest" $productReferences $sources
if ($LASTEXITCODE -ne 0) { throw 'Product bootstrap compilation failed.' }
& $csc /nologo /target:exe /main:ManifestTests "/out:$artifacts\ManifestTests.exe" (Join-Path $PSScriptRoot 'ManifestTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'PE manifest verifier compilation failed.' }
& (Join-Path $artifacts 'ManifestTests.exe') (Join-Path $artifacts 'ChildStream.exe') (Join-Path $artifacts 'ChildStreamSetup.exe')
if ($LASTEXITCODE -ne 0) { throw 'Embedded executable manifests are invalid.' }
& (Join-Path $artifacts 'ChildStream.exe') -child-agent invalid-request
if ($LASTEXITCODE -ne 2) { throw 'Shipping child-agent entry did not reject an invalid launch request.' }
& $csc /nologo /target:exe /main:LauncherLogicTests "/out:$artifacts\LauncherLogicTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'LauncherLogicTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Offline test compilation failed.' }
& (Join-Path $artifacts 'LauncherLogicTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline launcher tests failed.' }
& $csc /nologo /target:exe /main:LeastPrivilegeTests "/out:$artifacts\LeastPrivilegeTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'LeastPrivilegeTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Least-privilege test compilation failed.' }
if ($env:CI -eq 'true' -or $env:CHILDSTREAM_RUN_PRIVATE_IDENTITY -eq '1') {
    $env:CHILDSTREAM_PRIVATE_IDENTITY_TEST = '1'
}
& (Join-Path $artifacts 'LeastPrivilegeTests.exe') (Join-Path $artifacts 'screenshots')
if ($LASTEXITCODE -ne 0) { throw 'Least-privilege UI/transport tests failed.' }
& $csc /nologo /define:TEST_ONLY /target:exe /main:UiJourneyTests "/out:$artifacts\UiJourneyTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'UiJourneyTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Guided UI fixture compilation failed.' }
& (Join-Path $artifacts 'UiJourneyTests.exe') (Join-Path $artifacts 'screenshots')
if ($LASTEXITCODE -ne 0) { throw 'Rendered guided UI fixture tests failed.' }
& $csc /nologo /target:exe /main:SunshineTransportTests "/out:$artifacts\SunshineTransportTests.exe" /r:System.Web.Extensions.dll (Join-Path $root 'src\MoonlightPairing.cs') (Join-Path $root 'src\SunshinePairingTransport.cs') (Join-Path $PSScriptRoot 'SunshineTransportTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Ephemeral TLS fixture compilation failed.' }
if ($env:CI -eq 'true' -or $env:CHILDSTREAM_RUN_LOOPBACK_TLS -eq '1') {
    $env:CHILDSTREAM_TLS_FIXTURE_SCRIPT = Join-Path $PSScriptRoot 'tls-fixture.py'
}
& (Join-Path $artifacts 'SunshineTransportTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Ephemeral TLS transport tests failed.' }
& $csc /nologo /target:exe /main:MoonlightPairingTests "/out:$artifacts\MoonlightPairingTests.exe" /r:System.Web.Extensions.dll (Join-Path $root 'src\MoonlightPairing.cs') (Join-Path $PSScriptRoot 'MoonlightPairingTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Pairing test compilation failed.' }
& (Join-Path $artifacts 'MoonlightPairingTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline pairing tests failed.' }
& $csc /nologo /target:exe /main:InstallerFoundationTests "/out:$artifacts\InstallerFoundationTests.exe" (Join-Path $root 'src\InstallerFoundation.cs') (Join-Path $root 'src\InstallerInventory.cs') (Join-Path $root 'src\TransactionOwnership.cs') (Join-Path $PSScriptRoot 'InstallerFoundationTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Installer test compilation failed.' }
& (Join-Path $artifacts 'InstallerFoundationTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline installer tests failed.' }
& $csc /nologo /define:TEST_ONLY /target:exe /main:ProductIntegrationTests "/out:$artifacts\ProductIntegrationTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'ProductIntegrationTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Product integration test compilation failed.' }
& (Join-Path $artifacts 'ProductIntegrationTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline product integration tests failed.' }
& $csc /nologo /target:exe /main:UserPackageTests "/out:$artifacts\UserPackageTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'UserPackageTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'User bundle production-admission test compilation failed.' }
& $csc /nologo /define:TEST_ONLY /target:exe /main:LanFirewallTests "/out:$artifacts\LanFirewallTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'LanFirewallTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'LAN firewall transaction test compilation failed.' }
& (Join-Path $artifacts 'LanFirewallTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'LAN firewall transaction fixture tests failed.' }
& $csc /nologo /target:exe /main:ControllerWitnessProgram "/out:$artifacts\ChildStreamControllerWitness.exe" /r:System.Web.Extensions.dll (Join-Path $root 'src\ControllerWitness.cs')
if ($LASTEXITCODE -ne 0) { throw 'Opt-in controller witness compilation failed.' }
& $csc /nologo /target:exe /main:ControllerWitnessTests "/out:$artifacts\ControllerWitnessTests.exe" /r:System.Web.Extensions.dll (Join-Path $root 'src\ControllerWitness.cs') (Join-Path $PSScriptRoot 'ControllerWitnessTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Synthetic controller witness test compilation failed.' }
& (Join-Path $artifacts 'ControllerWitnessTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Synthetic controller witness tests failed.' }
& $csc /nologo /target:exe /main:IntegratedRuntimeTests "/out:$artifacts\IntegratedRuntimeTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'IntegratedRuntimeTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Integrated runtime test compilation failed.' }
& (Join-Path $artifacts 'IntegratedRuntimeTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Integrated runtime tests failed.' }
& $csc /nologo /target:exe /main:SetupBoundaryTests "/out:$artifacts\SetupBoundaryTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'SetupBoundaryTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Scoped setup test compilation failed.' }
& (Join-Path $artifacts 'SetupBoundaryTests.exe') (Join-Path $artifacts 'screenshots')
if ($LASTEXITCODE -ne 0) { throw 'Scoped setup tests failed.' }
& $csc /nologo /target:exe /main:SetupPipeTests "/out:$artifacts\SetupPipeTests.exe" $productReferences $sources (Join-Path $PSScriptRoot 'SetupPipeTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Actual named-pipe test compilation failed.' }
if ($env:CI -eq 'true' -or $env:CHILDSTREAM_RUN_LOCAL_PIPE -eq '1') {
    & (Join-Path $artifacts 'SetupPipeTests.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Actual named-pipe deadline tests failed.' }
} else { Write-Output 'Actual named-pipe tests SKIPPED (restricted local fixture token).' }
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
