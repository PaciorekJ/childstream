<# Read-only verifier for the inner ChildStream candidate ZIP. The expected digest
   must come from a separately trusted CI/review record, not from this archive. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $ExpectedSourceSha
)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $Path).Path
$actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $ExpectedSha256.ToLowerInvariant()) { throw 'Candidate ZIP SHA-256 differs from the independently expected digest.' }
Add-Type -AssemblyName System.IO.Compression
$zip = [System.IO.Compression.ZipFile]::OpenRead($resolved)
try {
    if ($zip.Entries.Count -lt 5 -or $zip.Entries.Count -gt 1024) { throw 'Candidate entry count is invalid.' }
    $entries = [System.Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = 0L
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName
        if ($name -notmatch '^(src|scripts|docs|tests|\.github|bin)/|^(README\.md|LICENSE|THIRD-PARTY-NOTICES\.md|candidate\.json|manifest\.json)$' -or
            $name -match '(^|/)\.\.?(/|$)|\\|:|\x00' -or $name.EndsWith('/') -or
            $entry.Length -lt 0 -or $entry.Length -gt 100MB -or $entries.ContainsKey($name)) {
            throw "Unsafe or duplicate candidate path: $name"
        }
        $total += $entry.Length
        if ($total -gt 500MB) { throw 'Candidate expanded size exceeds the review limit.' }
        $stream = $entry.Open()
        try {
            $memory = [IO.MemoryStream]::new()
            try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
            finally { $memory.Dispose() }
        } finally { $stream.Dispose() }
        if ($bytes.Length -ne $entry.Length) { throw "Candidate entry length changed: $name" }
        $entries.Add($name, $bytes)
    }
    foreach ($required in @('manifest.json','candidate.json','LICENSE','THIRD-PARTY-NOTICES.md','bin/ChildStream.exe','bin/ChildStreamSetup.exe','bin/ChildStreamBootstrap.exe','bin/ChildStreamFeasibilityProbe.exe','bin/ChildStreamControllerWitness.exe')) {
        if (-not $entries.ContainsKey($required)) { throw "Required candidate file missing: $required" }
    }
    $candidate = [Text.Encoding]::UTF8.GetString($entries['candidate.json']) | ConvertFrom-Json
    if ($candidate.sourceSha -ne $ExpectedSourceSha.ToLowerInvariant() -or
        $candidate.unsigned -ne $true -or $candidate.installed -ne $false -or
        $candidate.hardwareVerified -ne $false) { throw 'Candidate source or release-status metadata is invalid.' }
    $manifest = @([Text.Encoding]::UTF8.GetString($entries['manifest.json']) | ConvertFrom-Json)
    if ($manifest.Count -ne $entries.Count - 1) { throw 'Candidate manifest does not cover every payload entry.' }
    $covered = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $manifest) {
        $name = [string]$item.path
        if ($name -eq 'manifest.json' -or -not $covered.Add($name) -or -not $entries.ContainsKey($name) -or
            [long]$item.bytes -ne $entries[$name].Length) { throw "Invalid manifest entry: $name" }
        $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($entries[$name])).ToLowerInvariant()
        if ($digest -ne [string]$item.sha256) { throw "Candidate entry digest mismatch: $name" }
    }
    Write-Output "PASS: candidate ZIP SHA-256 $actual; source $($candidate.sourceSha); $($manifest.Count) payload entries; unsigned/uninstalled/hardware-unverified."
} finally { $zip.Dispose() }
