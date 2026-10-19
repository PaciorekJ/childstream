$ErrorActionPreference = 'Stop'
$script = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\profile-exclusion-shape.ps1'
$result = & pwsh -NoProfile -File $script -Mode Synthetic | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $result.Schema -ne 'ChildStream.ExclusionShapeSynthetic.v1') {
    throw 'Exclusion shape synthetic output is unavailable.'
}
if ($result.Missing.PropertyPresent -or $result.Missing.Kind -ne 'MissingOrAmbiguous' -or
    -not $result.Null.PropertyPresent -or $result.Null.Kind -ne 'NullLike' -or
    -not $result.Empty.PropertyPresent -or $result.Empty.Kind -ne 'Array' -or
    $result.Empty.Count -ne 0 -or $result.Nonempty.Count -ne 1) {
    throw 'Exclusion collector collapsed missing, null, empty and nonempty cases.'
}
Write-Output 'Exclusion property-presence and collection-shape synthetic checks passed.'
