<#
.SYNOPSIS
  Capture exact Docker/WSL workload metadata before any proposed Stage A pause.
.DESCRIPTION
  Read-only with respect to Docker, WSL and Windows configuration. Writes one
  private local report; does not stop or start workloads, persist environment
  variables, copy volume contents, or certify that application data is flushed.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
function DockerLines([string[]]$Arguments) {
    $result = @(& docker @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Docker read failed: $($result -join ' ')" }
    return @($result | ForEach-Object { [string]$_ })
}
function WslDistributions {
    $lines = @(wsl --list --verbose 2>&1 | ForEach-Object { ([string]$_) -replace [char]0, '' })
    if ($LASTEXITCODE -ne 0 -or -not ($lines -match '\bNAME\s+STATE\s+VERSION\b')) {
        throw 'WSL distribution listing failed or was unparseable.'
    }
    $distributions = @()
    foreach ($line in $lines) {
        if ($line -match '^\s*\*?\s*(.*?)\s{2,}(Running|Stopped)\s+([12])\s*$') {
            $distributions += [pscustomobject]@{
                Name = $Matches[1].Trim(); State = $Matches[2]; Version = [int]$Matches[3]
                HumanOwner = 'Unverified'; PendingShellOrServiceWrites = 'Unverified'
                PersistentData = 'Distribution VHD and user files; location/backup require owner review'
                StopProcedure = 'Owner must close/flush work before exact wsl --terminate NAME'
                ResumeProcedure = 'Owner launches only this originally running distribution after reconnect'
            }
        } elseif ($line.Trim() -and $line -notmatch '\bNAME\s+STATE\s+VERSION\b') {
            throw 'WSL distribution state was unparseable.'
        }
    }
    return @($distributions)
}
function DockerIds {
    $ids = @(DockerLines @('ps','--quiet','--no-trunc'))
    foreach ($id in $ids) {
        if ($id -notmatch '^[0-9a-f]{64}$') { throw 'Docker returned an invalid container ID.' }
    }
    return @($ids)
}

$sourceSha = [string]((& git rev-parse HEAD 2>$null | Select-Object -First 1))
if ($sourceSha.Trim() -notmatch '^[0-9a-f]{40}$') { throw 'Exact checkout SHA is unavailable.' }
$sourceSha = $sourceSha.Trim()
$dirty = @(& git status --porcelain=v1 2>$null)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) {
    throw 'Workload inventory requires a clean published checkout; no report was written.'
}
$beforeWsl = @(WslDistributions)
$beforeIds = @(DockerIds)
$containers = @()
foreach ($id in $beforeIds) {
    # The full inspect object is held only in memory. Env, secrets and raw
    # container configuration are never serialized to the report.
    $raw = @(DockerLines @('inspect','--format','{{json .}}',$id))
    if ($raw.Count -ne 1) { throw "Docker inspect was incomplete for $id." }
    $item = $raw[0] | ConvertFrom-Json -ErrorAction Stop
    if ($item.Id -ne $id -or -not $item.State.Running) { throw "Docker state changed during inspect for $id." }
    $labels = $item.Config.Labels
    $mounts = @($item.Mounts | ForEach-Object {
        [pscustomobject]@{ Type = $_.Type; Name = $_.Name; Source = $_.Source;
            Destination = $_.Destination; ReadWrite = [bool]$_.RW }
    })
    $published = @($item.NetworkSettings.Ports.PSObject.Properties | ForEach-Object {
        $containerPort = $_.Name
        foreach ($binding in @($_.Value)) {
            if ($null -ne $binding) { [pscustomobject]@{
                ContainerPort = $containerPort; HostIp = $binding.HostIp; HostPort = $binding.HostPort } }
        }
    })
    $containers += [pscustomobject]@{
        Id = $id; Name = ([string]$item.Name).TrimStart('/'); Image = $item.Config.Image
        ComposeProject = $labels.'com.docker.compose.project'
        ComposeService = $labels.'com.docker.compose.service'
        ComposeWorkingDirectory = $labels.'com.docker.compose.project.working_dir'
        ComposeConfigFiles = $labels.'com.docker.compose.project.config_files'
        HumanOwner = 'Unverified'; OwnerApprovalRequired = $true
        Status = $item.State.Status; StartedAt = $item.State.StartedAt
        HealthCheckConfigured = $null -ne $item.Config.Healthcheck
        HealthStatus = if ($null -ne $item.State.Health) { $item.State.Health.Status } else { 'NotConfigured' }
        RestartPolicy = $item.HostConfig.RestartPolicy.Name
        RestartMaximumRetryCount = $item.HostConfig.RestartPolicy.MaximumRetryCount
        StopSignal = $item.Config.StopSignal; StopTimeout = $item.HostConfig.StopTimeout
        Mounts = $mounts; PublishedPorts = $published
        WritableLayerOrPendingWrites = 'Unverified'
        VolumeBackupAndDataFlush = 'Unverified; owner must identify application-specific safe pause'
        StopProcedure = 'Owner-reviewed Compose stop or exact docker stop ID only after data flush'
        ResumeProcedure = 'Owner-reviewed existing Compose project or exact docker start ID; verify health and data'
    }
}
$afterIds = @(DockerIds)
$afterWsl = @(WslDistributions)
$sameIds = ($beforeIds.Count -eq $afterIds.Count -and
    (@($beforeIds | Sort-Object) -join "`n") -ceq (@($afterIds | Sort-Object) -join "`n"))
$wslState = { param($entries) (@($entries | ForEach-Object { "$($_.Name):$($_.State):$($_.Version)" } | Sort-Object) -join "`n") }
$sameWsl = (& $wslState $beforeWsl) -ceq (& $wslState $afterWsl)
$report = [ordered]@{
    Schema = 'ChildStream.WorkloadInventory.v1'
    HostConfigurationMutation = $false
    LocalPrivateReportWritten = $true
    CapturedUtc = [DateTime]::UtcNow.ToString('o')
    SourceSha = $sourceSha
    Complete = [bool]($sameIds -and $sameWsl)
    RunningContainerCount = $containers.Count
    RunningWslCount = @($beforeWsl | Where-Object State -eq 'Running').Count
    Containers = $containers
    WslDistributions = $beforeWsl
    HumanOwnershipAndDataFlushVerified = $false
    OfflineSignInVerified = $false
    Note = 'Metadata is read-only. It does not certify ownership, application durability, a safe stop, or offline sign-in.'
}

$directory = Join-Path $env:LOCALAPPDATA 'ChildStream-Workload-Preflight'
$newDirectory = -not (Test-Path -LiteralPath $directory -PathType Container)
if ($newDirectory) { $null = [IO.Directory]::CreateDirectory($directory) }
$acl = Get-Acl -LiteralPath $directory -ErrorAction Stop
$allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
$owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if ($owner -notin $allowed) { throw 'Private inventory directory owner is unsafe.' }
if ($newDirectory) {
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sid in $allowed) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $directory -AclObject $acl -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $directory -ErrorAction Stop
}
foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed) {
        throw 'Private inventory directory grants access to an unapproved principal.'
    }
}
$name = 'workloads-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
    [Guid]::NewGuid().ToString('N') + '.json'
$path = Join-Path $directory $name
$json = $report | ConvertTo-Json -Depth 20 -Compress
[IO.File]::WriteAllText($path, $json, [Text.UTF8Encoding]::new($false))
$fileAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
foreach ($rule in $fileAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed) {
        [IO.File]::Delete($path)
        throw 'Private inventory file grants access to an unapproved principal.'
    }
}
Write-Output ([pscustomobject]@{ Schema = $report.Schema; PrivatePath = $path;
    Complete = $report.Complete; RunningContainers = $report.RunningContainerCount;
    RunningWsl = $report.RunningWslCount; OwnerReviewRequired = $true;
    OfflineSignInVerified = $false } | ConvertTo-Json -Compress)
