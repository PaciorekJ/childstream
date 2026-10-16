<# Builds an unsigned, uninstalled source/binary candidate inside tests/.artifacts.
   It never downloads software, runs an installer, or changes Windows settings. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ((git -C $root status --porcelain).Count -ne 0) {
    throw 'Candidate packaging requires a clean, committed source tree.'
}
$sha = (git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$') { throw 'Git source identity is unavailable.' }
& (Join-Path $root 'tests\offline.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Offline suite failed; no candidate was packaged.' }
$outDir = Join-Path $root 'tests\.artifacts\candidate'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$zipPath = Join-Path $outDir ("ChildStream-candidate-$sha.zip")
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
$tracked = @(git -C $root ls-files --cached --full-name | Where-Object { $_ -match '^(src|scripts|docs|tests|third_party|\.github)/|^README\.md$|^LICENSE$|^THIRD-PARTY-NOTICES\.md$' })
if ($LASTEXITCODE -ne 0) { throw 'Tracked-file inventory failed.' }
$entries = [ordered]@{}
$sortedTracked = [string[]]@($tracked)
[Array]::Sort($sortedTracked, [StringComparer]::Ordinal)
function Read-CommittedBlob([string] $relative) {
    # Read the committed bytes, not the checkout's platform-dependent CRLF
    # conversion. ArgumentList avoids shell quoting and stdout is binary.
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('cat-file')
    $start.ArgumentList.Add('blob')
    $start.ArgumentList.Add("HEAD:$relative")
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $buffer = [System.IO.MemoryStream]::new()
        try {
            $process.StandardOutput.BaseStream.CopyTo($buffer)
            $errorText = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
            if ($process.ExitCode -ne 0) { throw "Cannot read committed blob $relative`: $errorText" }
            return ,$buffer.ToArray()
        }
        finally { $buffer.Dispose() }
    }
    finally { $process.Dispose() }
}
foreach ($relative in $sortedTracked) {
    $full = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Missing tracked file: $relative" }
    $entries[$relative.Replace('\','/')] = Read-CommittedBlob $relative
}
foreach ($name in @('ChildStream.exe','ChildStreamSetup.exe','ChildStreamBootstrap.exe','ChildStreamFeasibilityProbe.exe','ChildStreamControllerWitness.exe')) {
    $full = Join-Path $root "tests\.artifacts\$name"
    $entries["bin/$name"] = [System.IO.File]::ReadAllBytes($full)
}
$pin = [ordered]@{
    sourceSha = $sha
    unsigned = $true
    installed = $false
    hardwareVerified = $false
    sunshineVersion = 'v2026.1015.174736'
    sunshineSourceCommit = '178a0467da1dde750b182be4ae10ff8f8245ad01'
    sunshineAudioMergeCommit = 'fd45d2dd853d4f9310616112d78168226df6099c'
    sunshinePrerelease = $true
    sunshineCaptureOnly = $true
    sunshineAsset = 'Sunshine-Windows-AMD64-lite.zip'
    sunshineSource = 'https://github.com/LizardByte/Sunshine/releases/download/v2026.1015.174736/Sunshine-Windows-AMD64-lite.zip'
    sunshineArchiveSha256 = '35fa21069c314896e9b476e16e42fe4d60986dc3926b54e80d1c693e40d314cc'
    sunshineExecutableSha256 = '424cb1bbfe994c7676ff03957f1b3e1e79d218264677ec0b8959b5c809523c8c'
    sunshineExecutableSigned = $false
}
$entries['candidate.json'] = [System.Text.Encoding]::UTF8.GetBytes(($pin | ConvertTo-Json -Depth 4 -Compress) + "`n")
$manifest = foreach ($pair in $entries.GetEnumerator()) {
    [ordered]@{ path = $pair.Key; sha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($pair.Value)).ToLowerInvariant(); bytes = $pair.Value.Length }
}
$entries['manifest.json'] = [System.Text.Encoding]::UTF8.GetBytes((@($manifest) | ConvertTo-Json -Depth 5 -Compress) + "`n")
Add-Type -AssemblyName System.IO.Compression
$file = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
try {
    $zip = [System.IO.Compression.ZipArchive]::new($file, [System.IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        $sortedNames = [string[]]@($entries.Keys)
        [Array]::Sort($sortedNames, [StringComparer]::Ordinal)
        foreach ($name in $sortedNames) {
            $entry = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new(1980,1,1,0,0,0,[TimeSpan]::Zero)
            $stream = $entry.Open()
            try { $bytes = $entries[$name]; $stream.Write($bytes, 0, $bytes.Length) }
            finally { $stream.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}
finally { $file.Dispose() }
$digest = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
& (Join-Path $PSScriptRoot 'verify-candidate.ps1') -Path $zipPath -ExpectedSha256 $digest -ExpectedSourceSha $sha | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Candidate verification failed.' }
Write-Output "Candidate: $zipPath"
Write-Output "Source SHA: $sha"
Write-Output "Candidate SHA256: $digest"
Write-Output 'Unsigned, uninstalled, hardware unverified; no Sunshine binary included.'
