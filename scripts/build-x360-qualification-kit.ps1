param([switch]$BuildNative)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$sha = (git -C $root rev-parse HEAD).Trim()
$dirty = -not [string]::IsNullOrWhiteSpace((git -C $root status --porcelain))
$out = Join-Path $root 'tests/.artifacts/x360-qualification'
$bin = Join-Path $out 'bin'
$generated = Join-Path $out 'X360KitBuild.generated.cs'
New-Item -ItemType Directory -Path $bin -Force | Out-Null
$sourceIdentity = if ($dirty) { "$sha-DIRTY-LOCAL" } else { $sha }
@"
internal static class X360KitBuild { internal const string SourceSha = "$sourceIdentity"; }
"@ | Set-Content -LiteralPath $generated -Encoding UTF8
$csc = Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'Framework x64 C# compiler unavailable.' }
$sources = @(
  (Join-Path $root 'qualification/X360QualificationCore.cs'),
  (Join-Path $root 'qualification/WindowsKitAdapters.cs'),
  (Join-Path $root 'qualification/X360QualificationProgram.cs'),
  (Join-Path $root 'qualification/X360QualificationTests.cs'),
  (Join-Path $root 'src/ControllerWitness.cs'), $generated
)
& $csc /nologo /target:exe /platform:x64 /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll `
  /main:X360QualificationProgram "/out:$(Join-Path $bin 'ChildStreamX360Kit.exe')" $sources
if ($LASTEXITCODE -ne 0) { throw 'Kit managed compilation failed.' }
& (Join-Path $bin 'ChildStreamX360Kit.exe') --help
if ($LASTEXITCODE -ne 0) { throw 'Safe help invocation failed.' }
& (Join-Path $bin 'ChildStreamX360Kit.exe') --self-test
if ($LASTEXITCODE -ne 0) { throw 'Synthetic qualification tests failed.' }
if (-not $BuildNative) {
  Write-Output 'Managed kit compiled and synthetic-tested. Native DLL and ZIP require -BuildNative on an MSVC Windows builder.'
  return
}
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'MSVC discovery unavailable.' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $vs) { throw 'MSVC x64 C++ toolchain unavailable.' }
$vcvars = Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat'
$vendor = Join-Path $root 'qualification/vendor/ViGEmClient'
$native = Join-Path $bin 'ViGEmClient.dll'
$compile = 'call "' + $vcvars + '" >nul && cl /nologo /LD /EHsc /std:c++17 /DVIGEM_DYNAMIC /DVIGEM_EXPORTS /I"' + `
  (Join-Path $vendor 'include') + '" /Fo"' + (Join-Path $out 'ViGEmClient.obj') + '" /Fe"' + $native + '" "' + `
  (Join-Path $vendor 'src/ViGEmClient.cpp') + '" /link setupapi.lib /IMPLIB:"' + (Join-Path $out 'ViGEmClient.lib') + '"'
& cmd.exe /d /c $compile
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $native)) { throw 'Pinned native ViGEmClient build failed.' }

$package = Join-Path $out 'package'
New-Item -ItemType Directory -Path $package -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $bin 'ChildStreamX360Kit.exe') -Destination $package
Copy-Item -LiteralPath $native -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'qualification/README.md') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'qualification/FUTURE-EXPERIMENT.md') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $package 'ChildStream-LICENSE')
Copy-Item -LiteralPath (Join-Path $vendor 'LICENSE') -Destination (Join-Path $package 'ViGEmClient-LICENSE')
New-Item -ItemType Directory -Path (Join-Path $package 'source') -Force | Out-Null
foreach ($path in $sources) {
  $name = Split-Path $path -Leaf
  Copy-Item -LiteralPath $path -Destination (Join-Path $package 'source' $name)
}
Copy-Item -LiteralPath (Join-Path $vendor 'include') -Destination (Join-Path $package 'source/ViGEmClient-include') -Recurse
Copy-Item -LiteralPath (Join-Path $vendor 'src') -Destination (Join-Path $package 'source/ViGEmClient-src') -Recurse
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | Sort-Object FullName | ForEach-Object {
  [ordered]@{ path = $_.FullName.Substring($package.Length + 1).Replace('\','/'); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$manifest = [ordered]@{
  label = 'REVIEW-ONLY QUALIFICATION KIT — LIVE EXECUTION NOT AUTHORIZED'
  origin = 'SYNTHETIC-BUILD-ONLY'; sourceSha = $sha; dirtySource = $dirty
  sunshineSource = '3d6e1d6008bd4a24906283ab25fcd0becc0a1c07'
  vigemClientSource = '8d71f6740ffff4671cdadbca255ce528e3cd3fef'
  libvirtualhidNotUsed = 'dfff3ea8c34022c915799740806c17c0ed5c2492'
  test = 'ChildStreamX360Kit.exe --self-test; substituted effects only'
  files = $files
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding UTF8
$zip = Join-Path $out "ChildStream-X360-qualification-review-only-$sha.zip"
Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zip -Force
Write-Output "Review-only kit: $zip"
Write-Output "SHA256: $((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant())"
