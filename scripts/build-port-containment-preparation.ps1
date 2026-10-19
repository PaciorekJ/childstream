param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$sha = (git -C $root rev-parse HEAD).Trim()
$dirty = -not [string]::IsNullOrWhiteSpace((git -C $root status --porcelain))
$out = Join-Path $root 'tests/.artifacts/port-containment'
$package = Join-Path $out ('package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $package -Force | Out-Null
$csc = Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'Framework x64 C# compiler unavailable.' }
$source = Join-Path $root 'qualification/PortContainmentProbe.cs'
$tests = Join-Path $root 'qualification/PortContainmentProbeTests.cs'
$exe = Join-Path $package 'ChildStreamPortProbe.exe'
$testExe = Join-Path $out 'PortContainmentProbeTests.exe'
& $csc /nologo /target:exe /platform:x64 /main:PortContainmentProbeProgram "/out:$exe" $source
if ($LASTEXITCODE -ne 0) { throw 'Review-only receiver compilation failed.' }
& $csc /nologo /target:exe /platform:x64 /main:PortContainmentProbeTests "/out:$testExe" $source $tests
if ($LASTEXITCODE -ne 0) { throw 'Substituted test compilation failed.' }
& $exe --help
if ($LASTEXITCODE -ne 0) { throw 'No-socket help path failed.' }
& $testExe
if ($LASTEXITCODE -ne 0) { throw 'Substituted probe tests failed.' }
$included = @(
    @{ source = $source; target = 'source/PortContainmentProbe.cs' },
    @{ source = $tests; target = 'source/PortContainmentProbeTests.cs' },
    @{ source = (Join-Path $root 'scripts/build-port-containment-preparation.ps1'); target = 'source/build-port-containment-preparation.ps1' },
    @{ source = (Join-Path $root 'qualification/PORT-CONTAINMENT-EXPERIMENT.md'); target = 'START-HERE.md' },
    @{ source = (Join-Path $root 'LICENSE'); target = 'ChildStream-LICENSE' }
)
foreach ($entry in $included) {
    $target = Join-Path $package $entry.target
    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $entry.source -Destination $target -Force
}
Copy-Item -LiteralPath $testExe -Destination (Join-Path $package 'PortContainmentProbeTests.exe') -Force
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | Sort-Object FullName | ForEach-Object {
    [ordered]@{
        path = $_.FullName.Substring($package.Length + 1).Replace('\','/')
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
})
$manifest = [ordered]@{
    label = 'REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED'
    sourceSha = $sha
    dirtySource = $dirty
    dependency = 'Windows .NET Framework x64 compiler and framework runtime; no downloaded dependency'
    validation = 'No-socket help and substituted C# checks only; no native enforcement test'
    files = $files
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding UTF8
$zip = Join-Path $out "ChildStream-port-containment-review-only-$sha.zip"
Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zip -Force
Write-Output "Review-only preparation: $zip"
Write-Output "SHA256: $((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant())"
Write-Output "Source: $sha; dirty: $dirty"
