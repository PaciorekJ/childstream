$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$artifacts = Join-Path $PSScriptRoot '.artifacts'
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'The .NET Framework C# compiler is unavailable.' }
$sources = @(Join-Path $root 'src\ChildStream.cs'), @(Join-Path $root 'src\ChildSessionLifecycle.cs'), @(Join-Path $root 'src\SessionSignOutGuard.cs'), @(Join-Path $root 'src\LegacyCredentialCleanup.cs')
& $csc /nologo /target:exe /main:Program "/out:$artifacts\ChildStream.exe" /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:Microsoft.CSharp.dll $sources
if ($LASTEXITCODE -ne 0) { throw 'Launcher compilation failed.' }
& $csc /nologo /target:exe /main:LauncherLogicTests "/out:$artifacts\LauncherLogicTests.exe" /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:Microsoft.CSharp.dll $sources (Join-Path $PSScriptRoot 'LauncherLogicTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Offline test compilation failed.' }
& (Join-Path $artifacts 'LauncherLogicTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline launcher tests failed.' }
& $csc /nologo /target:exe /main:InstallerFoundationTests "/out:$artifacts\InstallerFoundationTests.exe" (Join-Path $root 'src\InstallerFoundation.cs') (Join-Path $root 'src\InstallerInventory.cs') (Join-Path $PSScriptRoot 'InstallerFoundationTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Installer test compilation failed.' }
& (Join-Path $artifacts 'InstallerFoundationTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Offline installer tests failed.' }
