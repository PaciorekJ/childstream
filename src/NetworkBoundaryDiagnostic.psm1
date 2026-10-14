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

function New-Predicate([string]$Id, [string]$Condition, [string]$Verdict, [string[]]$Evidence) {
    [pscustomobject]@{ Id = $Id; Condition = $Condition; Verdict = $Verdict; Evidence = @($Evidence) }
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
    $vms = Read-Field $Observation 'VirtualMachines'
    $wsl = Read-Field $Observation 'Wsl'
    $docker = Read-Field $Observation 'Docker'
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
        elseif ($retainedPhysicalPaths.Count) { 'Unknown' } else { 'Pass' }) @(
        $activePhysicalIndices | ForEach-Object { "ifIndex=$_ has an active physical link; local-subnet reachability matters without a default route." }
        $retainedPhysicalPaths | ForEach-Object { "ifIndex=$_ has retained address or route with physical link down; reachability not inferred." })))
    $adapterIndices = @{}
    foreach ($adapter in (Read-Items $adapters)) { $adapterIndices[[string](Read-Field $adapter 'InterfaceIndex')] = $true }
    $orphanPaths = @($addressIndices.Keys + $routeIndices.Keys | Sort-Object -Unique | Where-Object {
        $_ -ne '1' -and -not $adapterIndices.ContainsKey($_)
    })
    $unclassifiedVirtual = @()
    foreach ($adapter in (Read-Items $adapters)) {
        if ((Read-Field $adapter 'HardwareInterface') -eq $true -or (Read-Field $adapter 'Status') -ne 'Up') { continue }
        $index = [string](Read-Field $adapter 'InterfaceIndex')
        $role = [string](Read-Field $adapter 'VerifiedRole')
        $source = [string](Read-Field $adapter 'RoleEvidence')
        if (($role -eq 'InternalSwitchHost' -and $source -eq 'HyperVPortGraph') -or
            ($role -eq 'TunnelWithoutUnderlay' -and $source -eq 'UnderlayGraph')) { continue }
        if ($role -eq 'UnaddressedMiniport' -and $source -eq 'DriverAndPathGraph' -and
            -not $addressIndices.ContainsKey($index) -and -not $routeIndices.ContainsKey($index)) { continue }
        $unclassifiedVirtual += "ifIndex=$index role=$role evidence=$source address=$($addressIndices.ContainsKey($index)) route=$($routeIndices.ContainsKey($index))"
    }
    $virtualVerdict = if (-not $networkKnown -or $unclassifiedVirtual.Count -or $orphanPaths.Count) { 'Unknown' } else { 'Pass' }
    $predicates.Add((New-Predicate 'virtual-paths-attributed' 'External' $virtualVerdict @(
        $unclassifiedVirtual
        $orphanPaths | ForEach-Object { "ifIndex=$_ has an address or route but no adapter record." })))
    $forwardingKnown = (Read-Field $forwarding 'HnsState') -eq 'Accessible' -and
        (Read-Field $forwarding 'NetNatState') -eq 'Accessible' -and
        (Read-Field $forwarding 'PortProxyState') -eq 'Accessible' -and
        (Read-Field $forwarding 'BridgeGraphReviewed') -eq $true
    $forwardingPaths = [int](Read-Field $forwarding 'UnreviewedForwardingPaths')
    $forwardingVerdict = if ($forwardingPaths -gt 0) { 'Fail' } elseif ($forwardingKnown) { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'nat-bridge-forwarding-mapped' 'External' $forwardingVerdict @(
        "HNS=$((Read-Field $forwarding 'HnsState')); NetNat=$((Read-Field $forwarding 'NetNatState')); portproxy=$((Read-Field $forwarding 'PortProxyState')); bridge-graph-reviewed=$((Read-Field $forwarding 'BridgeGraphReviewed')); unreviewed-paths=$forwardingPaths")))

    $runningVms = @(Read-Items $vms | Where-Object { (Read-Field $_ 'State') -ne 'Off' })
    $runningWsl = @((Read-Field $wsl 'RunningDistributions')) | Where-Object { -not [string]::IsNullOrEmpty([string]$_) }
    $runningDocker = Read-Field $docker 'RunningContainerCount'
    $guestKnown = (Read-Field $vms 'State') -eq 'Accessible' -and (Read-Field $wsl 'State') -eq 'Accessible' -and
        (Read-Field $docker 'State') -eq 'Accessible' -and $null -ne $runningDocker
    $guestPresent = $runningVms.Count -gt 0 -or @($runningWsl).Count -gt 0 -or [int]$runningDocker -gt 0
    $guestVerdict = if ($guestPresent) { 'Fail' } elseif ($guestKnown) { 'Pass' } else { 'Unknown' }
    $predicates.Add((New-Predicate 'internal-guests-quiescent' 'GuestPath' $guestVerdict @(
        "VMs=$($runningVms.Count) VM-inventory=$((Read-Field $vms 'State')); WSL-running=$(@($runningWsl).Count) WSL-mode=$((Read-Field $wsl 'Mode')); Docker-containers=$runningDocker Docker-inventory=$((Read-Field $docker 'State'))")))

    $published = @((Read-Field $docker 'PublishedBindings')) | Where-Object { -not [string]::IsNullOrEmpty([string]$_) }
    $forwardVerdict = if ((Read-Field $docker 'State') -ne 'Accessible') { 'Unknown' } elseif (@($published).Count) { 'Fail' } else { 'Pass' }
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
    [pscustomobject]@{
        Schema = 'ChildStream.NetworkBoundaryDiagnostic.v1'
        HostMutation = $false
        DiagnosticOnly = $true
        Conditions = $groups
        Predicates = @($predicates)
        # Existing Stage A enforcement remains the stricter, unchanged gate.
        StageAPlanAuthorized = $false
    }
}

Export-ModuleMember -Function Get-ChildStreamNetworkBoundaryDiagnostic
