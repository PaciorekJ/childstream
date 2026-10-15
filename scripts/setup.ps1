<#
.SYNOPSIS
  Offline-safe entry point while the legacy installer is being replaced.
.DESCRIPTION
  The former script enabled RDP, downloaded an unpinned Sunshine release,
  overwrote configuration, and created broad persistent startup/firewall rules.
  There is no safe unattended migration from those effects. This entry point
  intentionally performs no installation or host mutation.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Apply', 'Recover', 'Uninstall')]
    [string] $Mode = 'Validate'
)

$ErrorActionPreference = 'Stop'
$diagnostics = Join-Path $PSScriptRoot 'diagnose.ps1'
if ($Mode -eq 'Validate') {
    & $diagnostics
    return
}

throw "ChildStream $Mode is blocked: the owned-file and archive adapters are candidate source only. Child bootstrap, streaming posture and live rollback acceptance remain unverified. See docs/product-integration.md and docs/live-acceptance.md. No host changes were made."
