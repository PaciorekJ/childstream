<# Builds a user-facing ZIP from exact committed ChildStream binaries and the
   official pinned portable Sunshine prerelease. Does not execute either app. #>
[CmdletBinding()]
param(
    [string] $SunshineArchive,
    [string] $OutputDirectory
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$sha = (git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$') { throw 'Source SHA unavailable.' }
if ((git -C $root status --porcelain).Count -ne 0) { throw 'User package requires a clean, committed source tree.' }
$candidate = Join-Path $root "tests\.artifacts\candidate\ChildStream-candidate-$sha.zip"
if (-not (Test-Path -LiteralPath $candidate)) { throw 'Build and verify the exact-source candidate first.' }
if (-not $SunshineArchive) {
    $SunshineArchive = Join-Path $root 'tests\.artifacts\upstream-audio\v2026.1018.5342\Sunshine-Windows-AMD64-lite.zip'
}
$expectedSunshine = '5637d74c6f0d80bb133c0d6d4df7c49c663c0f860b4e96efcb9d1d9c207ea649'
if (-not (Test-Path -LiteralPath $SunshineArchive)) {
    New-Item -ItemType Directory -Force (Split-Path $SunshineArchive -Parent) | Out-Null
    $partial = "$SunshineArchive.partial"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    try {
        Invoke-WebRequest -Uri 'https://github.com/LizardByte/Sunshine/releases/download/v2026.1018.5342/Sunshine-Windows-AMD64-lite.zip' -OutFile $partial
        if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSunshine) {
            throw 'Downloaded Sunshine archive digest differs from the independently pinned official asset.'
        }
        Move-Item -LiteralPath $partial -Destination $SunshineArchive
    }
    catch { if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }; throw }
}
if ((Get-FileHash -LiteralPath $SunshineArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSunshine) {
    throw 'Pinned Sunshine archive digest differs.'
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$candidateDigest = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
& (Join-Path $PSScriptRoot 'verify-candidate.ps1') -Path $candidate -ExpectedSha256 $candidateDigest -ExpectedSourceSha $sha | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Exact-source candidate verification failed.' }
$sunshineZip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $SunshineArchive))
try {
    $sunshineExe = $sunshineZip.GetEntry('Sunshine/sunshine.exe')
    if (-not $sunshineExe) { throw 'Sunshine lite archive layout changed.' }
    $stream = $sunshineExe.Open()
    try { $exeDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() }
    finally { $stream.Dispose() }
    if ($exeDigest -ne '7200207666836abb1646831809ef7b4744d0b40c7cc5aed09ba7ebc0edc05081') {
        throw 'Sunshine executable differs from the qualified capture-only binary.'
    }
}
finally { $sunshineZip.Dispose() }
& (Join-Path $root 'tests\.artifacts\ProductIntegrationTests.exe') $SunshineArchive
if ($LASTEXITCODE -ne 0) { throw 'Pinned Sunshine archive failed production package admission.' }
$zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $candidate))
try {
    $metadata = $zip.GetEntry('candidate.json')
    if (-not $metadata) { throw 'Candidate provenance is missing.' }
    $reader = [IO.StreamReader]::new($metadata.Open())
    try { $pin = $reader.ReadToEnd() | ConvertFrom-Json }
    finally { $reader.Dispose() }
    if ($pin.sourceSha -ne $sha -or $pin.sunshineArchiveSha256 -ne $expectedSunshine -or
        $pin.sunshineExecutableSha256 -ne $exeDigest -or -not $pin.sunshineCaptureOnly) {
        throw 'Candidate and bundled Sunshine pin do not agree.'
    }
    $launcher = $zip.GetEntry('bin/ChildStream.exe')
    $bootstrap = $zip.GetEntry('bin/ChildStreamBootstrap.exe')
    if (-not $launcher -or -not $bootstrap) { throw 'Candidate entry executables are absent.' }
    if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'tests\.artifacts\distribution' }
    New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
    $out = Join-Path $OutputDirectory ("ChildStream-Windows-x64-$($sha.Substring(0,12)).zip")
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
    $entries = [ordered]@{}
    foreach ($item in @(@('ChildStream.exe',$launcher),@('ChildStreamBootstrap.exe',$bootstrap))) {
        $memory = [IO.MemoryStream]::new()
        $input = $item[1].Open()
        try { $input.CopyTo($memory); $entries[$item[0]] = $memory.ToArray() }
        finally { $input.Dispose(); $memory.Dispose() }
    }
    $entries['payload/ChildStream-candidate.zip'] = [IO.File]::ReadAllBytes($candidate)
    $entries['payload/Sunshine-Windows-AMD64-lite.zip'] = [IO.File]::ReadAllBytes($SunshineArchive)
    foreach ($name in @('LICENSE','THIRD-PARTY-NOTICES.md')) {
        $entries[$name] = [IO.File]::ReadAllBytes((Join-Path $root $name))
    }
    foreach ($name in @('LICENSE','NOTICE')) {
        $entries["third-party/Sunshine/$name"] = [IO.File]::ReadAllBytes((Join-Path $root "third_party\sunshine-license\$name"))
    }
    $entries['START-HERE.txt'] = [Text.Encoding]::UTF8.GetBytes(
        "ChildStream Windows x64 engineering candidate`r`n`r`nExtract this entire ZIP to a persistent folder and open ChildStream.exe.`r`n" +
        "The app verifies bundled payloads, plans its own-file installation, and asks for explicit approval before Windows UAC.`r`n" +
        "Windows child-session setup, LAN exposure and live streaming require separate approval and hardware acceptance.`r`n" +
        "This distribution is unsigned. Independently verify its published ZIP SHA-256 before running elevated code.`r`n")
    function Digest([byte[]]$bytes) { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() }
    $descriptor = [ordered]@{
        schema = 'ChildStream.UserBundle.v1'; sourceSha = $sha
        candidateSha256 = Digest $entries['payload/ChildStream-candidate.zip']
        sunshineSha256 = Digest $entries['payload/Sunshine-Windows-AMD64-lite.zip']
        launcherSha256 = Digest $entries['ChildStream.exe']
        bootstrapSha256 = Digest $entries['ChildStreamBootstrap.exe']
        sunshinePrerelease = $true; sunshineSourceCommit = '3d6e1d6008bd4a24906283ab25fcd0becc0a1c07'
    }
    $entries['bundle.json'] = [Text.Encoding]::UTF8.GetBytes(($descriptor | ConvertTo-Json -Compress) + "`n")
    $file = [IO.File]::Open($out,[IO.FileMode]::CreateNew)
    try {
        $bundle = [IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$false)
        try {
            foreach ($name in ($entries.Keys | Sort-Object)) {
                $entry = $bundle.CreateEntry($name,[IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(1980,1,1,0,0,0,[TimeSpan]::Zero)
                $stream = $entry.Open()
                try { $bytes = $entries[$name]; $stream.Write($bytes,0,$bytes.Length) }
                finally { $stream.Dispose() }
            }
        }
        finally { $bundle.Dispose() }
    }
    finally { $file.Dispose() }
    Write-Output "User package: $out"
    Write-Output "Package SHA256: $((Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLowerInvariant())"
    Write-Output "Source SHA: $sha"
    Write-Output "Pinned prerelease Sunshine archive SHA256: $expectedSunshine"
    $extract = Join-Path $OutputDirectory ("verify-$($sha.Substring(0,12))")
    if (Test-Path -LiteralPath $extract) { throw 'A prior extracted package verification directory exists; preserve it for review.' }
    [IO.Compression.ZipFile]::ExtractToDirectory($out, $extract)
    & (Join-Path $root 'tests\.artifacts\UserPackageTests.exe') $extract
    if ($LASTEXITCODE -ne 0) { throw 'Extracted user package failed production bundle admission.' }
}
finally { $zip.Dispose() }
