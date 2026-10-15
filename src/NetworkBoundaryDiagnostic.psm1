Set-StrictMode -Version Latest

function Read-Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Read-Items($Section) {
    $items = Read-Field $Section 'Items'
    if ($null -eq $items) { return @() }
    return @($items)
}

function Test-ChildStreamArrayField($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) {
        return $Object.Contains($Name) -and $Object[$Name] -is [array]
    }
    $property = $Object.PSObject.Properties[$Name]
    return $null -ne $property -and $property.Value -is [array]
}

function New-Predicate([string]$Id, [string]$Condition, [string]$Verdict, [string[]]$Evidence) {
    [pscustomobject]@{ Id = $Id; Condition = $Condition; Verdict = $Verdict; Evidence = @($Evidence) }
}

function Normalize-Mac($Value) {
    $digits = ([string]$Value) -replace '[^0-9a-fA-F]', ''
    if ($digits.Length -ne 12 -or $digits -eq '000000000000') { return '' }
    return $digits.ToUpperInvariant()
}

function Read-ExceptionStatus($Exception) {
    if ($null -eq $Exception) { return $null }
    $property = $Exception.PSObject.Properties['StatusCode']
    if ($null -eq $property) { return $null }
    return [string]$property.Value
}

function Get-ChildStreamDockerErrorClass([string]$Message) {
    if ($Message -match '(?i)permission denied|access is denied|unauthorized|forbidden') { return 'AccessDenied' }
    if ($Message -match '(?i)cannot connect to the docker daemon|is the docker daemon running|the system cannot find the file|pipe.*not found|daemon is not running') { return 'DaemonUnavailable' }
    return 'Unknown'
}

function Resolve-ChildStreamDockerObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Docker,
        [Parameter(Mandatory)]$DockerProcesses,
        [Parameter(Mandatory)]$Wsl,
        [Parameter(Mandatory)]$HnsEndpoints,
        [Parameter(Mandatory)]$PortProxy,
        [Parameter(Mandatory)]$Forwarding,
        [Parameter(Mandatory)]$DockerListeners
    )
    if ((Read-Field $Docker 'State') -eq 'Accessible') { return $Docker }
    $corroborated = (Read-Field $Docker 'State') -eq 'Inaccessible' -and
        (Read-Field $Docker 'ErrorClass') -eq 'DaemonUnavailable' -and
        (Read-Field $DockerProcesses 'State') -eq 'Accessible' -and
        (Test-ChildStreamArrayField $DockerProcesses 'Items') -and
        @(Read-Items $DockerProcesses).Count -eq 0 -and
        (Read-Field $Wsl 'State') -eq 'Accessible' -and
        (Test-ChildStreamArrayField $Wsl 'RunningDistributions') -and
        @((Read-Field $Wsl 'RunningDistributions') | Where-Object { $_ }).Count -eq 0 -and
        (Read-Field $HnsEndpoints 'State') -eq 'Accessible' -and
        (Test-ChildStreamArrayField $HnsEndpoints 'Items') -and
        @(Read-Items $HnsEndpoints).Count -eq 0 -and
        (Read-Field $PortProxy 'State') -eq 'Accessible' -and
        (Test-ChildStreamArrayField $PortProxy 'Items') -and
        @(Read-Items $PortProxy).Count -eq 0 -and
        (Read-Field $DockerListeners 'State') -eq 'Accessible' -and
        $null -ne (Read-Field $DockerListeners 'DockerOwnedTcpCount') -and
        $null -ne (Read-Field $DockerListeners 'DockerOwnedUdpCount') -and
        (Read-Field $DockerListeners 'DockerOwnedTcpCount') -eq 0 -and
        (Read-Field $DockerListeners 'DockerOwnedUdpCount') -eq 0 -and
        (Read-Field $Forwarding 'HnsState') -eq 'Accessible' -and
        (Read-Field $Forwarding 'NetNatState') -eq 'Accessible' -and
        (Read-Field $Forwarding 'PortProxyState') -eq 'Accessible' -and
        (Read-Field $Forwarding 'BridgeBindingState') -eq 'Accessible' -and
        (Read-Field $Forwarding 'IpForwardingState') -eq 'Accessible' -and
        (Read-Field $Forwarding 'BridgeGraphReviewed') -eq $true -and
        (Read-Field $Forwarding 'UnreviewedForwardingPaths') -eq 0
    if (-not $corroborated) { return $Docker }
    [pscustomobject]@{
        State = 'VerifiedStopped'
        RunningContainerCount = $null
        PublishedBindings = @()
        ErrorClass = 'DaemonUnavailable'
        Evidence = 'No Docker process, running WSL distribution, HNS endpoint, portproxy, unreviewed forwarding path, or Docker-owned listener; all sources accessible.'
    }
}

function Get-ChildStreamBridgeBindingObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Adapters,
        [Parameter(Mandatory)]$Addresses,
        [Parameter(Mandatory)]$Routes,
        [scriptblock]$QueryBinding = {
            param($Adapter)
            # Query all bindings: a filtered ms_bridge query returning nothing
            # cannot distinguish absence from an unsupported adapter/provider.
            $exactName = [System.Management.Automation.WildcardPattern]::Escape([string]$Adapter.Label)
            @(Get-NetAdapterBinding -Name $exactName -IncludeHidden -AllBindings -ErrorAction Stop)
        }
    )
    if ((Read-Field $Adapters 'State') -ne 'Accessible' -or
        (Read-Field $Addresses 'State') -ne 'Accessible' -or
        (Read-Field $Routes 'State') -ne 'Accessible') {
        return [pscustomobject]@{ State = 'Inaccessible'; QueryMode = 'PerRelevantAdapter';
            Items = @(); Queried = @(); Failures = @([pscustomobject]@{
                InterfaceIndex = $null; ErrorType = 'SourceInventoryInaccessible';
                ErrorId = 'SourceInventoryInaccessible'; HResult = $null;
                InnerErrorType = $null; InnerHResult = $null; CimStatus = $null;
                InnerCimStatus = $null }) }
    }
    $pathIndices = @{}
    foreach ($item in (@(Read-Items $Addresses) + @(Read-Items $Routes))) {
        $pathIndices[[string](Read-Field $item 'InterfaceIndex')] = $true
    }
    $items = [System.Collections.Generic.List[object]]::new()
    $queried = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[object]]::new()
    foreach ($adapter in (Read-Items $Adapters)) {
        $index = Read-Field $adapter 'InterfaceIndex'
        $relevant = (Read-Field $adapter 'HardwareInterface') -eq $true -or
            [string](Read-Field $adapter 'Status') -eq 'Up' -or
            $pathIndices.ContainsKey([string]$index)
        if (-not $relevant) { continue }
        $name = [string](Read-Field $adapter 'Label')
        if ($null -eq $index -or [int]$index -lt 1 -or [string]::IsNullOrWhiteSpace($name)) {
            $failures.Add([pscustomobject]@{ InterfaceIndex = $index; ErrorType = 'MissingAdapterIdentity';
                ErrorId = 'MissingAdapterIdentity'; HResult = $null;
                InnerErrorType = $null; InnerHResult = $null; CimStatus = $null;
                InnerCimStatus = $null })
            continue
        }
        $queried.Add([pscustomobject]@{ InterfaceIndex = [int]$index })
        try {
            $all = @(& $QueryBinding $adapter)
            if ($all.Count -eq 0 -or @($all | Where-Object {
                [string](Read-Field $_ 'Name') -cne $name -or
                [string]::IsNullOrWhiteSpace([string](Read-Field $_ 'ComponentID')) -or
                $null -eq (Read-Field $_ 'Enabled')
            }).Count -gt 0) {
                $failures.Add([pscustomobject]@{ InterfaceIndex = [int]$index;
                    ErrorType = 'IncompleteBindingResult'; ErrorId = 'IncompleteBindingResult'; HResult = $null;
                    InnerErrorType = $null; InnerHResult = $null; CimStatus = $null;
                    InnerCimStatus = $null })
                continue
            }
            foreach ($binding in ($all | Where-Object { [string](Read-Field $_ 'ComponentID') -ieq 'ms_bridge' })) {
                $items.Add([pscustomobject]@{ InterfaceIndex = [int]$index;
                    ComponentID = 'ms_bridge'; Enabled = [bool](Read-Field $binding 'Enabled') })
            }
        }
        catch {
            $exception = $_.Exception
            $inner = $exception.InnerException
            $failures.Add([pscustomobject]@{ InterfaceIndex = [int]$index;
                ErrorType = $exception.GetType().Name;
                ErrorId = [string]$_.FullyQualifiedErrorId;
                HResult = $exception.HResult;
                InnerErrorType = if ($null -ne $inner) { $inner.GetType().Name } else { $null };
                InnerHResult = if ($null -ne $inner) { $inner.HResult } else { $null };
                CimStatus = Read-ExceptionStatus $exception;
                InnerCimStatus = Read-ExceptionStatus $inner })
        }
    }
    [pscustomobject]@{ State = if ($failures.Count) { 'Inaccessible' } else { 'Accessible' };
        QueryMode = 'PerRelevantAdapter'; Items = @($items); Queried = @($queried);
        Failures = @($failures) }
}

function ConvertTo-ChildStreamCanonicalText($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return ConvertTo-Json -InputObject $Value -Compress }
    if ($Value -is [bool]) { return ([string]$Value).ToLowerInvariant() }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($key in @($Value.Keys | Sort-Object -CaseSensitive)) {
            (ConvertTo-ChildStreamCanonicalText ([string]$key)) + ':' +
                (ConvertTo-ChildStreamCanonicalText $Value[$key])
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [pscustomobject]) {
        $parts = foreach ($property in @($Value.PSObject.Properties | Sort-Object Name -CaseSensitive)) {
            (ConvertTo-ChildStreamCanonicalText $property.Name) + ':' +
                (ConvertTo-ChildStreamCanonicalText $property.Value)
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = @($Value | ForEach-Object { ConvertTo-ChildStreamCanonicalText $_ } | Sort-Object -CaseSensitive)
        return '[' + ($parts -join ',') + ']'
    }
    return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
}

function Get-ChildStreamBoundaryFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Observation)
    $sources = [ordered]@{}
    foreach ($name in @('Adapters','IpInterfaces','IpAddresses','Routes','Switches','HostPorts',
        'VirtualMachines','VmPorts','Hns','HnsEndpoints','NetNat','PortProxy',
        'BridgeBindings','IpForwarding','Wsl','Docker','DockerProcesses','DockerListeners','Rdp')) {
        $section = Read-Field $Observation $name
        if ((Read-Field $section 'State') -ne 'Accessible' -and
            -not ($name -eq 'Docker' -and (Read-Field $section 'State') -eq 'VerifiedStopped')) { return $null }
        $sources[$name] = $section
    }
    $sources['AdapterCollectionConsistent'] = Read-Field $Observation 'AdapterCollectionConsistent'
    $sources['Forwarding'] = Read-Field $Observation 'Forwarding'
    $sources['OperatorPhysicalSeveranceConfirmed'] = Read-Field $Observation 'OperatorPhysicalSeveranceConfirmed'
    $sources['RdpEvidence'] = Read-Field $Observation 'RdpEvidence'
    if ($sources['AdapterCollectionConsistent'] -ne $true -or $null -eq $sources['Forwarding'] -or
        $null -eq $sources['OperatorPhysicalSeveranceConfirmed'] -or $null -eq $sources['RdpEvidence']) { return $null }
    foreach ($name in @('Firewall','FirewallProfiles','LocalDenyConnections','Services','TcpListener','UdpEndpoint')) {
        if ((Read-Field (Read-Field $sources['RdpEvidence'] $name) 'State') -ne 'Accessible') { return $null }
    }
    if ((Read-Field (Read-Field $sources['RdpEvidence'] 'PolicyDenyConnections') 'State') -notin @('Accessible','Absent')) { return $null }
    $canonical = ConvertTo-ChildStreamCanonicalText $sources
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-ChildStreamNetworkBoundaryDiagnostic {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Observation)

    $predicates = [System.Collections.Generic.List[object]]::new()
    $adapters = Read-Field $Observation 'Adapters'
    $interfaces = Read-Field $Observation 'IpInterfaces'
    $addresses = Read-Field $Observation 'IpAddresses'
    $routes = Read-Field $Observation 'Routes'
    $switches = Read-Field $Observation 'Switches'
    $hostPorts = Read-Field $Observation 'HostPorts'
    $vms = Read-Field $Observation 'VirtualMachines'
    $vmPorts = Read-Field $Observation 'VmPorts'
    $hns = Read-Field $Observation 'Hns'
    $hnsEndpoints = Read-Field $Observation 'HnsEndpoints'
    $wsl = Read-Field $Observation 'Wsl'
    $docker = Read-Field $Observation 'Docker'
    $dockerProcesses = Read-Field $Observation 'DockerProcesses'
    $dockerListeners = Read-Field $Observation 'DockerListeners'
    $rdp = Read-Field $Observation 'Rdp'
    $forwarding = Read-Field $Observation 'Forwarding'

    $networkKnown = (Read-Field $adapters 'State') -eq 'Accessible' -and
        (Read-Field $interfaces 'State') -eq 'Accessible' -and
        (Read-Field $addresses 'State') -eq 'Accessible' -and
        (Read-Field $routes 'State') -eq 'Accessible' -and
        (Read-Field $Observation 'AdapterCollectionConsistent') -eq $true -and
        @(Read-Items $interfaces).Count -gt 0 -and @(Read-Items $addresses).Count -gt 0 -and
        @(Read-Items $routes).Count -gt 0
    $physical = @()
    $activePhysical = @()
    $ambiguousPhysical = @()
    if ($networkKnown) {
        $seen = @{}
        foreach ($adapter in (Read-Items $adapters)) {
            $index = Read-Field $adapter 'InterfaceIndex'
            $status = [string](Read-Field $adapter 'Status')
            if ($null -eq $index -or [int]$index -lt 1 -or $seen.ContainsKey([string]$index) -or
                $null -eq (Read-Field $adapter 'HardwareInterface') -or
                $null -eq (Read-Field $adapter 'Virtual') -or
                $status -notin @('Up', 'Disconnected', 'Disabled', 'Down', 'Not Present', 'NotPresent', 'LowerLayerDown')) {
                $networkKnown = $false
                break
            }
            $seen[[string]$index] = $true
        }
    }
    if ($networkKnown) {
        $physical = @(Read-Items $adapters | Where-Object { (Read-Field $_ 'HardwareInterface') -eq $true })
        foreach ($adapter in $physical) {
            $status = [string](Read-Field $adapter 'Status')
            $media = [string](Read-Field $adapter 'MediaConnectionState')
            if ($status -eq 'Up' -or $media -eq 'Connected') { $activePhysical += $adapter }
            elseif ($status -notin @('Disconnected', 'Disabled', 'Down', 'Not Present', 'NotPresent', 'LowerLayerDown')) {
                $ambiguousPhysical += $adapter
            }
        }
    }
    $coverage = if (-not $networkKnown -or $physical.Count -eq 0) { 'Unknown' } else { 'Pass' }
    $predicates.Add((New-Predicate 'network-inventory-complete' 'External' $coverage @(
        "Adapters=$((Read-Field $adapters 'State')); Interfaces=$((Read-Field $interfaces 'State')); Addresses=$((Read-Field $addresses 'State')); Routes=$((Read-Field $routes 'State')); adapter-snapshots-consistent=$((Read-Field $Observation 'AdapterCollectionConsistent')); physical-count=$($physical.Count)")))
    $physicalVerdict = if ($coverage -ne 'Pass') { 'Unknown' } elseif ($activePhysical.Count) { 'Fail' } elseif ($ambiguousPhysical.Count) { 'Unknown' } else { 'Pass' }
    $predicates.Add((New-Predicate 'physical-uplinks-down' 'External' $physicalVerdict @(
        $activePhysical | ForEach-Object { "ifIndex=$($_.InterfaceIndex) status=$($_.Status) media=$($_.MediaConnectionState)" }
        $ambiguousPhysical | ForEach-Object { "ifIndex=$($_.InterfaceIndex) ambiguous-status=$($_.Status)" })))

    $operatorConfirmed = (Read-Field $Observation 'OperatorPhysicalSeveranceConfirmed') -eq $true
    $predicates.Add((New-Predicate 'physical-severance-confirmed' 'External' $(if ($operatorConfirmed) { 'Pass' } else { 'Unknown' }) @(
        $(if ($operatorConfirmed) { 'Operator recorded independent cable/radio/tether inspection.' } else { 'Independent cable/radio/tether inspection has not been recorded.' }))))

    $switchState = Read-Field $switches 'State'
    $externalSwitches = @(Read-Items $switches | Where-Object { (Read-Field $_ 'SwitchType') -eq 'External' })
    $unknownSwitches = @(Read-Items $switches | Where-Object { (Read-Field $_ 'SwitchType') -notin @('Internal', 'Private', 'External') })
    $switchVerdict = if ($switchState -ne 'Accessible' -or $unknownSwitches.Count) { 'Unknown' } elseif ($externalSwitches.Count) { 'Fail' } else { 'Pass' }
    $predicates.Add((New-Predicate 'switches-have-no-external-bridge' 'External' $switchVerdict @(
        $(if ($switchState -ne 'Accessible') { "Switch inventory=$switchState" } else { "Switches=$(@(Read-Items $switches).Count); external=$($externalSwitches.Count); unknown=$($unknownSwitches.Count)" }))))

    $addressIndices = @{}
    foreach ($entry in (Read-Items $addresses)) { $addressIndices[[string](Read-Field $entry 'InterfaceIndex')] = $true }
    $routeIndices = @{}
    foreach ($entry in (Read-Items $routes)) { $routeIndices[[string](Read-Field $entry 'InterfaceIndex')] = $true }
    $physicalIndices = @($physical | ForEach-Object { [string](Read-Field $_ 'InterfaceIndex') })
    $activePhysicalIndices = @($activePhysical | ForEach-Object { [string](Read-Field $_ 'InterfaceIndex') })
    $retainedPhysicalPaths = @($physicalIndices | Where-Object { $_ -notin $activePhysicalIndices -and
        ($addressIndices.ContainsKey($_) -or $routeIndices.ContainsKey($_)) })
    $predicates.Add((New-Predicate 'physical-route-link-corroboration' 'External' $(
        if (-not $networkKnown) { 'Unknown' } elseif ($activePhysical.Count) { 'Fail' }
        elseif ($ambiguousPhysical.Count) { 'Unknown' } else { 'Pass' }) @(
        $activePhysicalIndices | ForEach-Object { "ifIndex=$_ has an active physical link; local-subnet reachability matters without a default route." }
        $retainedPhysicalPaths | ForEach-Object { "ifIndex=$_ has a retained address or route; its physical link is observed down and must remain so." })))
    $adapterIndices = @{}
    foreach ($adapter in (Read-Items $adapters)) { $adapterIndices[[string](Read-Field $adapter 'InterfaceIndex')] = $true }
    $orphanPaths = @($addressIndices.Keys + $routeIndices.Keys | Sort-Object -Unique | Where-Object {
        $_ -ne '1' -and -not $adapterIndices.ContainsKey($_)
    })
    $unclassifiedVirtual = @()
    $hostPortGraphKnown = (Read-Field $hostPorts 'State') -eq 'Accessible' -and
        $switchState -eq 'Accessible' -and (Read-Field $vmPorts 'State') -eq 'Accessible'
    $hostPortGraphConflicts = @()
    $hostPortByMac = @{}
    $adapterMacCounts = @{}
    $portIds = @{}
    foreach ($adapter in (Read-Items $adapters)) {
        $mac = Normalize-Mac (Read-Field $adapter 'MacAddress')
        if ($mac) { $adapterMacCounts[$mac] = 1 + [int]$adapterMacCounts[$mac] }
    }
    foreach ($port in (Read-Items $hostPorts)) {
        $mac = Normalize-Mac (Read-Field $port 'MacAddress')
        $portId = [string](Read-Field $port 'Id')
        $switchName = [string](Read-Field $port 'SwitchName')
        $switchId = [string](Read-Field $port 'SwitchId')
        $matches = @(Read-Items $switches | Where-Object {
            if ($switchId) { [string](Read-Field $_ 'Id') -eq $switchId }
            else { [string](Read-Field $_ 'Name') -ceq $switchName }
        })
        if (-not $portId -or $portIds.ContainsKey($portId) -or
            -not $switchName -or -not $switchId -or
            -not $mac -or $hostPortByMac.ContainsKey($mac) -or
            $adapterMacCounts[$mac] -ne 1 -or $matches.Count -ne 1 -or
            [string](Read-Field $matches[0] 'Name') -cne $switchName -or
            $matches[0].SwitchType -notin @('Internal','Private')) {
            $hostPortGraphConflicts += "host port with MAC=$mac has ambiguous adapter or switch identity"
            continue
        }
        $portIds[$portId] = $true
        $hostPortByMac[$mac] = $port
    }
    if (-not $hostPortGraphKnown) { $hostPortGraphConflicts += 'Hyper-V host/guest port or switch inventory is inaccessible.' }
    $graphVerdict = if ($hostPortGraphConflicts.Count) { 'Unknown' } else { 'Pass' }
    $predicates.Add((New-Predicate 'hyperv-host-port-graph' 'External' $graphVerdict @($hostPortGraphConflicts)))
    foreach ($adapter in (Read-Items $adapters)) {
        if ((Read-Field $adapter 'HardwareInterface') -eq $true -or (Read-Field $adapter 'Status') -ne 'Up') { continue }
        $index = [string](Read-Field $adapter 'InterfaceIndex')
        $mac = Normalize-Mac (Read-Field $adapter 'MacAddress')
        $port = if ($mac -and $hostPortByMac.ContainsKey($mac)) { $hostPortByMac[$mac] } else { $null }
        $portSwitchName = if ($null -ne $port) { [string](Read-Field $port 'SwitchName') } else { '' }
        $isHostPort = $hostPortGraphKnown -and $null -ne $port -and
            (Read-Field $adapter 'Virtual') -eq $true -and
            [string](Read-Field $adapter 'InterfaceDescription') -cmatch '^Hyper-V Virtual Ethernet Adapter(?: #[1-9][0-9]*)?$' -and
            [string](Read-Field $adapter 'Label') -ceq "vEthernet ($portSwitchName)"
        if ($isHostPort) { continue }
        if ((Read-Field $adapter 'Virtual') -eq $true -and
            -not $addressIndices.ContainsKey($index) -and -not $routeIndices.ContainsKey($index) -and
            (Read-Field $forwarding 'BridgeBindingState') -eq 'Accessible' -and
            [int](Read-Field $forwarding 'EnabledBridgeBindingCount') -eq 0) { continue }
        $unclassifiedVirtual += "ifIndex=$index active nonphysical path lacks verified host-port identity or is addressed"
    }
    $virtualVerdict = if (-not $networkKnown -or $graphVerdict -ne 'Pass' -or
        $unclassifiedVirtual.Count -or $orphanPaths.Count) { 'Unknown' } else { 'Pass' }
    $predicates.Add((New-Predicate 'virtual-paths-attributed' 'External' $virtualVerdict @(
        $unclassifiedVirtual
        $orphanPaths | ForEach-Object { "ifIndex=$_ has an address or route but no adapter record." })))
    $forwardingKnown = (Read-Field $forwarding 'HnsState') -eq 'Accessible' -and
        (Read-Field $forwarding 'NetNatState') -eq 'Accessible' -and
        (Read-Field $forwarding 'PortProxyState') -eq 'Accessible' -and
        (Read-Field $forwarding 'HnsEndpointState') -eq 'Accessible' -and
        (Read-Field $forwarding 'BridgeBindingState') -eq 'Accessible' -and
        (Read-Field $forwarding 'IpForwardingState') -eq 'Accessible' -and
        (Read-Field $forwarding 'BridgeGraphReviewed') -eq $true
    $forwardingPaths = [int](Read-Field $forwarding 'UnreviewedForwardingPaths')
    $forwardingVerdict = if ($forwardingPaths -gt 0) { 'Fail' } elseif ($forwardingKnown) { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'nat-bridge-forwarding-mapped' 'External' $forwardingVerdict @(
        "HNS=$((Read-Field $forwarding 'HnsState')); endpoints=$((Read-Field $forwarding 'HnsEndpointState')); NetNat=$((Read-Field $forwarding 'NetNatState')); portproxy=$((Read-Field $forwarding 'PortProxyState')); bridge=$((Read-Field $forwarding 'BridgeBindingState')); IP-forwarding=$((Read-Field $forwarding 'IpForwardingState')); graph-reviewed=$((Read-Field $forwarding 'BridgeGraphReviewed')); unreviewed-paths=$forwardingPaths")))

    $endpointCount = @(Read-Items $hnsEndpoints).Count
    $endpointVerdict = if ($endpointCount) { 'Fail' }
        elseif ((Read-Field $hnsEndpoints 'State') -eq 'Accessible') { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'hns-endpoints-quiescent' 'GuestPath' $endpointVerdict @(
        "HNS-endpoint-inventory=$((Read-Field $hnsEndpoints 'State')); count=$endpointCount")))

    $hnsGraphProblems = @()
    if ((Read-Field $hns 'State') -eq 'Accessible' -and
        (Read-Field $hnsEndpoints 'State') -eq 'Accessible') {
        $networkIds = @{}
        foreach ($entry in (Read-Items $hns)) {
            $id = ([string](Read-Field $entry 'ID')).Trim('{}').ToUpperInvariant()
            if (-not $id -or $networkIds.ContainsKey($id)) {
                $hnsGraphProblems += 'HNS network has absent or duplicate identity.'
            } else { $networkIds[$id] = $true }
        }
        foreach ($entry in (Read-Items $hnsEndpoints)) {
            $id = ([string](Read-Field $entry 'VirtualNetwork')).Trim('{}').ToUpperInvariant()
            if (-not $id -or -not $networkIds.ContainsKey($id)) {
                $hnsGraphProblems += 'HNS endpoint has no unique network identity.'
            }
        }
    }
    $hnsGraphVerdict = if ((Read-Field $hns 'State') -ne 'Accessible' -or
        (Read-Field $hnsEndpoints 'State') -ne 'Accessible' -or $hnsGraphProblems.Count) {
        'Unknown'
    } else { 'Pass' }
    $predicates.Add((New-Predicate 'hns-endpoint-network-graph' 'GuestPath' $hnsGraphVerdict @($hnsGraphProblems)))

    $runningVms = @(Read-Items $vms | Where-Object { (Read-Field $_ 'State') -ne 'Off' })
    $runningWsl = @((Read-Field $wsl 'RunningDistributions')) | Where-Object { -not [string]::IsNullOrEmpty([string]$_) }
    $dockerStopped = (Read-Field $docker 'State') -eq 'VerifiedStopped'
    $runningDocker = if ($dockerStopped) { 0 } else { Read-Field $docker 'RunningContainerCount' }
    $guestKnown = (Read-Field $vms 'State') -eq 'Accessible' -and (Read-Field $wsl 'State') -eq 'Accessible' -and
        (Read-Field $docker 'State') -in @('Accessible','VerifiedStopped') -and $null -ne $runningDocker -and
        (Read-Field $dockerProcesses 'State') -eq 'Accessible' -and
        (Read-Field $dockerListeners 'State') -eq 'Accessible' -and
        (Read-Field $vmPorts 'State') -eq 'Accessible' -and (Read-Field $hns 'State') -eq 'Accessible'
    $guestPresent = $runningVms.Count -gt 0 -or @($runningWsl).Count -gt 0 -or [int]$runningDocker -gt 0 -or
        @(Read-Items $dockerProcesses).Count -gt 0 -or $endpointCount -gt 0
    $guestVerdict = if ($guestPresent) { 'Fail' } elseif ($guestKnown) { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'internal-guests-quiescent' 'GuestPath' $guestVerdict @(
        "VMs=$($runningVms.Count) VM-inventory=$((Read-Field $vms 'State')); WSL-running=$(@($runningWsl).Count) WSL-mode=$((Read-Field $wsl 'Mode')); Docker-containers=$runningDocker Docker-inventory=$((Read-Field $docker 'State')); Docker-processes=$(@(Read-Items $dockerProcesses).Count); HNS-endpoints=$endpointCount")))

    $published = @((Read-Field $docker 'PublishedBindings')) | Where-Object { -not [string]::IsNullOrEmpty([string]$_) }
    $forwardVerdict = if ($dockerStopped) { 'Pass' }
        elseif ((Read-Field $docker 'State') -ne 'Accessible') { 'Unknown' }
        elseif (@($published).Count) { 'Fail' } else { 'Pass' }
    $predicates.Add((New-Predicate 'docker-host-forwarding-absent' 'GuestPath' $forwardVerdict @(
        $published | ForEach-Object { "Published host binding: $_" })))

    $rdpKnown = (Read-Field $rdp 'State') -eq 'Accessible' -and $null -ne (Read-Field $rdp 'PolicyDenied') -and
        $null -ne (Read-Field $rdp 'TermServiceStopped') -and $null -ne (Read-Field $rdp 'TcpListenerCount') -and
        $null -ne (Read-Field $rdp 'UdpEndpointCount')
    $rdpBad = (Read-Field $rdp 'PolicyDenied') -eq $false -or (Read-Field $rdp 'TermServiceStopped') -eq $false -or
        [int](Read-Field $rdp 'TcpListenerCount') -gt 0 -or [int](Read-Field $rdp 'UdpEndpointCount') -gt 0
    $rdpVerdict = if ($rdpBad) { 'Fail' } elseif ($rdpKnown) { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'rdp-baseline-closed' 'RdpExposure' $rdpVerdict @(
        "PolicyDenied=$((Read-Field $rdp 'PolicyDenied')); TermServiceStopped=$((Read-Field $rdp 'TermServiceStopped')); TCP=$((Read-Field $rdp 'TcpListenerCount')); UDP=$((Read-Field $rdp 'UdpEndpointCount'))")))

    $internalRdpVerdict = if ($guestPresent) { 'Fail' } elseif ($guestKnown -and $switchVerdict -eq 'Pass' -and $rdpVerdict -eq 'Pass') { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'guest-to-host-rdp-exposure-excluded' 'RdpExposure' $internalRdpVerdict @(
        $(if ($guestPresent) { 'Active internal guests exist; existing potentially permissive or unknown firewall rules do not prove that an unexpected host RDP listener is unreachable.' }
          else { 'No active guest proven only when VM, WSL, and Docker inventories are complete.' }))))

    $expected = Read-Field $Observation 'ExpectedNetworkFingerprint'
    $current = Read-Field $Observation 'CurrentNetworkFingerprint'
    $driftVerdict = if ([string]::IsNullOrEmpty([string]$expected) -or [string]::IsNullOrEmpty([string]$current)) { 'Unknown' }
        elseif ($expected -ceq $current) { 'Pass' } else { 'Fail' }
    $predicates.Add((New-Predicate 'fresh-logon-network-unchanged' 'Continuity' $driftVerdict @(
        $(if ($driftVerdict -eq 'Fail') { 'Network fingerprint changed across the approval boundary.' } elseif ($driftVerdict -eq 'Unknown') { 'Approved baseline/current network fingerprint pair is unavailable.' } else { 'Network fingerprint matches approved baseline.' }))))

    $groups = @{}
    foreach ($condition in @('External', 'GuestPath', 'RdpExposure', 'Continuity')) {
        $items = @($predicates | Where-Object Condition -eq $condition)
        $groups[$condition] = if (@($items | Where-Object Verdict -eq 'Fail').Count) { 'Fail' }
            elseif (@($items | Where-Object Verdict -eq 'Unknown').Count) { 'Unknown' } else { 'Pass' }
    }
    $preapprovalIds = @('physical-severance-confirmed','fresh-logon-network-unchanged')
    $blockers = [pscustomobject]@{
        CurrentState = @($predicates | Where-Object { $_.Verdict -eq 'Fail' } | ForEach-Object Id)
        EvidenceGaps = @($predicates | Where-Object {
            $_.Verdict -eq 'Unknown' -and $_.Id -notin $preapprovalIds
        } | ForEach-Object Id)
        FutureBoundaryChecks = @($predicates | Where-Object {
            $_.Verdict -eq 'Unknown' -and $_.Id -in $preapprovalIds
        } | ForEach-Object Id)
    }
    [pscustomobject]@{
        Schema = 'ChildStream.NetworkBoundaryDiagnostic.v1'
        HostMutation = $false
        DiagnosticOnly = $true
        Conditions = $groups
        Predicates = @($predicates)
        BlockingFindings = $blockers
        # Existing Stage A enforcement remains the stricter, unchanged gate.
        StageAPlanAuthorized = $false
    }
}

Export-ModuleMember -Function Get-ChildStreamNetworkBoundaryDiagnostic,Get-ChildStreamBoundaryFingerprint,Get-ChildStreamBridgeBindingObservation,Resolve-ChildStreamDockerObservation,Get-ChildStreamDockerErrorClass
