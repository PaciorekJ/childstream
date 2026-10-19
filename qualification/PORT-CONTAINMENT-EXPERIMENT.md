# ChildStream physical-LAN port-containment experiment — START HERE

**REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.** This package proposes one component experiment. It is not a ChildStream installer or feature-enable plan. The child-session feature, ordinary-RDP denial, TermService, existing firewall rules, and all protected workloads remain unchanged. No command in the future-execution sections below has run during preparation. The two new rules and receiver need a later exact, separate host-operation approval.

## Question, scope, and disposition

Can temporary all-application inbound blocks on the **freshly read configured ordinary-RDP port** produce a Windows Security 5152/5157 drop attributable to the exact experiment rule for one controlled physical-LAN TCP and UDP attempt, while a fixed-message local connection still reaches a minimal receiver? The preferred sender is the operator's **iPhone**, on the same physical Wi-Fi LAN as the PC. The iPhone is available and an app installation is possible; no app has been installed or used for this task.

This experiment deliberately omits the ordinary-RDP service and child feature. The receiver speaks only the fixed `CS-PROBE-v1` request and two-byte `OK` reply. Its success cannot qualify the shipping `TermService` rule, actual ActiveX child loopback, Tailscale, WSL/Docker/guest paths, forwarding into loopback, or Stage A/B. It does not interpret `S_OK + VT_EMPTY` as an empty effective firewall-exclusion set. The recorded 2026-10-18 native COM/CIM shape is retained, not reread. A matching **physical-interface packet event** can establish enforcement on that one path despite the unresolved metadata representation; a metadata readback alone cannot.

**Result names:** `SUPPORTS THE TESTED RULE` requires the exact-rule drop and local receipt for each explicitly tested protocol/family/address under an unchanged bound policy. `REJECTS THE TESTED RULE OR SETUP` means unintended LAN receipt or a separately and positively attributed block of the intended local connection. A failed local client alone cannot establish the latter. `INCONCLUSIVE` covers missing sender capability, local-client failure, no exact-rule event, another filter, saturation, ambiguous timing/interface, or insufficient collection. Report cleanup separately as `COMPLETE` or `INCOMPLETE`; a cleanup problem never becomes evidence for enforcement. No result admits feature writes or changes the shipping gate.

## Sender and receiver

The proposed iPhone sender is [Network Kit - TCP UDP debugger](https://apps.apple.com/us/app/network-kit-tcp-udp-debugger/id1631771142). Its App Store listing explicitly advertises TCP, TCP6, UDP and UDP6. The listing also discloses advertising, optional paid subscriptions to remove ads, and developer-reported use of identifiers and usage data for tracking; Apple says these privacy claims have not been verified. No purchase or subscription is proposed. The owner must review these material disclosures before any later installation decision. That listing does **not** establish that the installed version can record an actual source port, select the intended Wi-Fi path, or perform all four sends on this phone. The later operator must review/install it, allow [iOS Local Network access](https://support.apple.com/en-us/102229) if prompted, verify its exact TCP/UDP modes and IPv4/IPv6 literal-address behavior, and record the attempt time, destination literal address/port, protocol, and visible result. The phone's Wi-Fi IP and the Windows event's `SourceAddress`/`SourcePort` must corroborate the source; an absent source-port display in the app is not invented. Avoid its optional cloud-transfer feature. One attempt per case is sufficient; no scan or repeat flood. A browser or Moonlight is not a raw UDP sender. If the iPhone cannot send a family/protocol, that case remains **unavailable**, never passed. The IPv4 TCP+UDP pair is the minimum useful subset; IPv6 requires an assigned, reachable non-link-local host address and a confirmed iPhone IPv6 source. A missing IPv6 case means no dual-stack conclusion.

No existing ChildStream listener is suitable: its product endpoints carry application controls. `ChildStreamPortProbe.exe` is a separate .NET Framework x64 console receiver with no dependency download. Default/help perform no host read or socket operation. `receive` requires an explicit approval marker and literal same-family loopback/LAN addresses; the marker is **not** authorization. Each run binds only two exact addresses on one port, sets IPv6-only on IPv6 sockets, permits at most 8 accepted attempts and 120 seconds, uses a TCP backlog of 2, reads the fixed 11-byte TCP request across fragments or one UDP datagram of at most 32 bytes, and returns at most two fixed bytes for a valid request. Stream framing is exactly 11 ASCII request bytes, then exactly two ASCII response bytes; no line terminator is used. It prints one `READY` line containing both bound endpoints, PID and protocol. `RECEIVED` records connection/datagram observation independently of `MESSAGE` validation. It has no credential, file-transfer, command, proxy, elevation, firewall, persistence, or service path. One monotonic elapsed budget covers waiting, acceptance, request fragments, and response writes. Socket waits are sliced at 50 ms; Ctrl+C is observed between slices, with an intended response tolerance of roughly one slice plus Windows scheduling and disposal time, **not** a hard real-time bound. `STOP_REQUESTED` precedes exact-owned socket disposal; `STOPPED` follows successful disposal, and `SHUTDOWN_FAILED` identifies a disposal error. A measurement may be incomplete even when shutdown succeeds. The receiver is still a listening socket, so a later approved run must begin **only after** effective protection is verified.

## Exact rule candidate and limits

Two **experiment-owned** local PersistentStore rules, named `ChildStream.PortExperiment.TCP.v1` and `ChildStream.PortExperiment.UDP.v1`, are proposed. Each is enabled, inbound, Block, protocol TCP or UDP, local port equal to the fresh configured RDP port, any remote port, local address `Any`, and remote addresses `0.0.0.0-126.255.255.255`, `128.0.0.0-255.255.255.255`, `::`, and `::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` (the current source's nonloopback set). Program and service restrictions are omitted, which [matches any program or service](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule). Profile `Any`, interface type `Any`, interface alias unrestricted, edge traversal `Block`, no IPsec authentication or allow-bypass. These predicates intentionally differ from shipping `TermService` + all-local-ports rules. A narrower physical-interface or phone-IP rule would reduce impact but would not exercise this proposed nonloopback port rule. The names are unique and must be absent in both PersistentStore and ActiveStore before creation; no overwrite or adoption.

This port-wide block can deny inbound traffic to **any** application that owns the configured port on any interface, including protected work. It therefore requires a fresh, narrow no-occupant check across **all local TCP and UDP endpoints on that port**, confirmation that no relevant forwarding/listener claim is present in the approved narrow views, and a short approved window. If ownership is occupied, inaccessible, or ambiguous, **stop**; do not identify or inspect the application, stop it, reuse the port, or silently choose another port. A different port would test only port-filter mechanics, not the configured-RDP-port candidate, and needs a new review. The rule is wider than the physical-LAN evidence: a success cannot be transferred to an untested interface, remote-address range, IPv6 mapped address, tunnel, guest, or future policy state. Source `127/8`, `::1`, IPv4-mapped IPv6, local-to-LAN routing, and loopback forwarding have distinct behavior; only the explicitly logged local controls are observed.

[Microsoft's rule documentation](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) defines the selectors and says ActiveStore is resultant policy. Readback must show exactly one effective rule per name, all associated port/address/application/service/interface/security filters, enabled Block, local-rule participation, no relevant allow-bypass, and no incompatible profile/interface exclusion. Readback **does not** prove packet enforcement. The earlier COM `VT_EMPTY` remains an unresolved representation, so this component result rests on an attributable live drop rather than asserting exclusion metadata is empty. An exclusion or profile uncertainty that prevents effective attribution stops or makes the run inconclusive; it never becomes an admission pass.

## Measurement and private evidence

Before a packet: record the receiver's single `READY` line with both exact addresses, port, protocol, PID and UTC, the physical interface index and assigned host IP, the phone Wi-Fi source IP, approved rule names and readback, and Security-log audit availability. The receiver must not start until both exact rules are effective. The separate `control-tcp` command sends ASCII `CS-PROBE-v1` to `127.0.0.1` or `::1` on the same port, accumulates exactly two response bytes under one 1–5 second connect/write/read budget, and requires `CONTROL_STOPPED|...|MEASUREMENT=ACK_OK` plus the receiver's `RECEIVED|...|LOCAL|...|TCP_CONNECTED` and `MESSAGE|...|LOCAL|FIXED_MESSAGE_ACKED` records. UDP uses the separate one-datagram control below. A local client error, incomplete reply, timeout or cancellation is a failed or incomplete local measurement, never evidence of firewall rejection. The iPhone sends one packet/connection to the literal **host physical Wi-Fi address**; the app's timestamp/destination/mode plus the Security event tuple identify its attempt. Receiver `LAN` receipt is a failure of containment, not success.

Query only Security event IDs **5152/5157** and log-clear **1102** in the exact experiment window, bounded to at most 4,096 recent records. If the window overflows, the log is cleared, audit is off, relevant records are malformed, or there is no event, mark **INCONCLUSIVE**. Do not enable auditing as part of this preferred experiment. [Microsoft documents](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation) `FilterOrigin` and `InterfaceIndex` on current Windows 5152/5157 events and the auditing prerequisite. A supporting event must have Security provider provenance, unique record ID/time after rule readback and sender attempt, inbound direction, protocol 6 or 17, destination host address and configured port, phone source address (and source port when available), physical interface index, and `FilterOrigin` exactly equal to the experiment rule **Name** for that protocol. The payload string is **not** a Security-event field; correlate by native tuple and tight time window, not a fabricated nonce. A timeout, absent listener, stealth/default filter, or another rule's origin is inconclusive for the candidate. Receiver/app logs and only filtered relevant event fields stay in a private owner-controlled directory; retain until review, then delete on a separately approved schedule. Do not export a whole Security log, packet capture, unrelated events, or protected-workload data.

## Future execution, for separate approval only

**REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.** The following is the preferred ordered sequence. It is a proposal, not a command to run now. A later approval must bind the reviewed ZIP SHA-256, current source SHA, exact RDP port, LAN interface/index/addresses, iPhone source addresses and tested families, rule names, duration, and operator recovery owner. Do not run this while the prerequisites are unresolved.

1. **Fresh narrow reads, no effects.** At the physical console under the same account, verify the package hashes; read `WTSIsChildSessionsEnabled` (must remain disabled), ordinary-RDP denied policy, TermService state, all TCP/UDP endpoint occupancy on the freshly read configured RDP port, the physical Wi-Fi address/index, active firewall profiles/local-rule merge/bypass status, exact-name rule absence in both stores, and Security 5152/5157 auditing and log health. Compare with the recorded baseline; any drift, occupied port, unavailable read, or missing audit prerequisite stops before mutation. Do not inspect who owns a conflicting endpoint or any protected workload. A forwarded-loopback path is outside this experiment and is not declared absent. The previous 3389/TermService/no-listener snapshot is historical only. Confirm the iPhone is on the same physical LAN, has an independent IPv4 source, and, only if testing IPv6, assigned non-link-local IPv6 source/reachability. Record the exact plan and rollback operator privately.
2. **Approval and intent.** Obtain separate approval for the two exact local firewall rules, 4 receiver runs at most, phone app installation/permission and one sender attempt per supported case, bounded Security-log read, and exact-owned cleanup. Cap the entire rule-active window at **15 minutes**; each receiver run lasts at most 60 seconds. Write a private receipt **before** the first rule: original RDP/feature/service/listener/port state, rule absence, exact rule predicates and plan hash, package hash, operator, UTC, and intended expiry. A receipt is not permission to proceed if a gate fails. If the window expires, stop new runs and begin the reviewed exact-owned cleanup check.
3. **Rule creation only, then readback.** On an approved elevated console, use the freshly read `$rdpPort` (never hard-code 3389):

   ```powershell
   # REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
   $remote = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
   New-NetFirewallRule -PolicyStore PersistentStore -Name 'ChildStream.PortExperiment.TCP.v1' -DisplayName 'ChildStream.PortExperiment.TCP.v1' -Description 'Reviewed short-lived ChildStream physical-LAN port experiment' -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol TCP -LocalPort $rdpPort -LocalAddress Any -RemoteAddress $remote -InterfaceType Any -EdgeTraversalPolicy Block
   New-NetFirewallRule -PolicyStore PersistentStore -Name 'ChildStream.PortExperiment.UDP.v1' -DisplayName 'ChildStream.PortExperiment.UDP.v1' -Description 'Reviewed short-lived ChildStream physical-LAN port experiment' -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol UDP -LocalPort $rdpPort -LocalAddress Any -RemoteAddress $remote -InterfaceType Any -EdgeTraversalPolicy Block
   ```

   Stop without starting the receiver unless the exact one-per-name PersistentStore **and ActiveStore** rules and associated port/address/program/service/interface/security filters read back as proposed and policy participation is credible. Any partial creation has its own receipt and exact-owned recovery; never delete a preexisting rule. Explicit Block normally outranks Allow, but authenticated allow-bypass, disabled profile/rule merge, excluded interface, or third-party filtering can change effective behavior. The packet event remains decisive for the tested path.
4. **Receiver and controls.** Start one reviewed process per case only after readback. The proposed commands below show one IPv4 TCP run; replace `TCP` with `UDP` and, only if feasible, use `::1` plus the assigned non-link-local physical IPv6 address for IPv6. The literal `LAN_IPv4`/`LAN_IPv6` is captured in the approved plan, not guessed. Keep the window to 60 seconds and at most four received attempts per run.

   ```powershell
   # REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
   & .\ChildStreamPortProbe.exe receive --reviewed-live-approval YES --protocol TCP --local 127.0.0.1 --lan LAN_IPv4 --port $rdpPort --seconds 60 --max-attempts 4
   ```

   In a second physical-console shell during the single `READY` line, run the matching TCP or UDP local control below and require its exact ACK and receiver `LOCAL` records. Then direct exactly one approved iPhone TCP/UDP send to the matching physical host address/port. Record the iPhone app's attempt time and result. The receiver must either remain without a `LAN` receipt or report an unintended receipt. A failed local check or unexpected remote receipt stops further sends. No unprotected remote-listener baseline is part of this plan. On deadline, cancellation or attempt cap, require a terminal `STOPPED` line and confirm the exact PID/endpoints are gone; `SHUTDOWN_FAILED`, missing terminal status or an incomplete measurement require separate review.
5. **Bounded evidence and classification.** On the already approved elevated console, query only the bounded Security IDs/time window; keep only candidate tuples and 1102, with event record IDs/times. Require unique origin/tuple/interface attribution per actually sent case. If 4,096 records are reached or query fails, mark inconclusive. Compare to receiver and iPhone records, explicitly list v4/v6 TCP/UDP coverage and each missing case. Never infer a firewall drop from the iPhone's timeout.
6. **Exact-owned stop and recovery.** Wait for `STOPPED` or use Ctrl+C on the **recorded receiver PID**; confirm those exact bound endpoints are gone. Recheck feature/policy, TermService and RDP listeners against the private baseline. If any changed unexpectedly, **stop**, preserve experiment-owned blocking rules and receipt, and seek a separately reviewed repair/recovery decision; do not start, stop or repair TermService, alter RDP, or automatically remove protection. If the baseline is unchanged, compare each installed experiment rule with its receipt and remove **only the exact two names/definitions** from PersistentStore, then verify absence from both stores and the original baseline. Do not remove shipping or unrelated rules. If removal/readback fails, mark cleanup incomplete and preserve the receipt for exact-state retry; do not claim restored. No feature journal exists and no Stage A restore command applies.

The later approved implementation can use the existing ChildStream exact-rule/filter readers for the readback and private receipt. The command sketch above is intentionally not an auto-executing script: its actual preflight values and separate approval have not been supplied. If auditing is disabled, **stop before rule creation** and request a separate narrowly reviewed temporary audit-policy plan with original-state snapshot and restoration; this package does not enable it. If local-rule merge or interface applicability remains unknown, no feature admission follows even if a single physical event is observed.

### Proposed command details for the later approved window

**REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.** These are exact command shapes with values supplied only by the later signed-off private plan. A value discrepancy stops the run. The read commands do not themselves authorize the two writes above or receiver execution.

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
# Narrow baseline, in elevated same-account physical-console PowerShell 7.
$rdpPort = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop).PortNumber
if ($rdpPort -lt 1 -or $rdpPort -gt 65535) { throw 'Invalid configured RDP port' }
$deny = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
if ($deny -ne 1) { throw 'Ordinary RDP is not locally denied' }
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
if (Test-Path -LiteralPath $policyPath) {
  $p = Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop
  if ($null -ne $p.fDenyTSConnections -and [int]$p.fDenyTSConnections -ne 1) { throw 'RDP policy does not deny' }
}
$term = Get-Service -Name TermService -ErrorAction Stop
$tcpOccupancy = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object LocalPort -eq $rdpPort)
$udpOccupancy = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object LocalPort -eq $rdpPort)
if ($tcpOccupancy.Count -ne 0 -or $udpOccupancy.Count -ne 0) { throw 'Configured port occupied; stop without inspecting owner' }
$names = @('ChildStream.PortExperiment.TCP.v1','ChildStream.PortExperiment.UDP.v1')
foreach ($store in @('PersistentStore','ActiveStore')) {
  $existing = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object { $names -contains $_.Name })
  if ($existing.Count -ne 0) { throw 'Experiment rule identity already exists' }
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
if ($profiles.Count -ne 3 -or @($profiles | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.AllowLocalFirewallRules -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block' }).Count -ne 0) { throw 'Effective profile/merge precondition incomplete' }
auditpol /get /subcategory:'Filtering Platform Packet Drop'
if ($LASTEXITCODE -ne 0) { throw 'Packet-drop audit state unreadable; stop' }
auditpol /get /subcategory:'Filtering Platform Connection'
if ($LASTEXITCODE -ne 0) { throw 'Connection audit state unreadable; stop' }
# Review audit output; failure auditing must already be enabled. No audit write here.
```

The feature query must use the reviewed `WTSIsChildSessionsEnabled` P/Invoke (the earlier elevated read found `false`); if it cannot be performed or differs, stop. The proposed exact query, with no write, is:

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class ChildStreamPortExperimentWts {
  [DllImport("wtsapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool WTSIsChildSessionsEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);
}
'@
$enabled = $false
$ok = [ChildStreamPortExperimentWts]::WTSIsChildSessionsEnabled([ref]$enabled)
if (-not $ok -or $enabled) { throw 'Child feature unknown or changed; stop' }
```

Physical Wi-Fi adapter/index and address are obtained from a **named physical adapter only**, e.g. `Get-NetAdapter -Name '<reviewed alias>'` and `Get-NetIPAddress -InterfaceIndex <its index>`, then compared with the private plan. This avoids enumerating guests or protected workloads. `Get-WinEvent -ListLog Security` may establish log accessibility; inability to read it stops. Profile exclusion representation remains unknown; it is not silently coerced.

After both rules exist, these are the proposed **exact-name** readback commands. Require one rule in each store per name and compare every returned filter field with the approved predicates. Any missing filter, nonlocal source, policy error, bypass, or ambiguity stops before a receiver starts.

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
foreach ($name in $names) {
  $persistent = @(Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop)
  $active = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop)
  if ($persistent.Count -ne 1 -or $active.Count -ne 1) { throw 'Rule not uniquely effective' }
  $active[0] | Get-NetFirewallPortFilter
  $active[0] | Get-NetFirewallAddressFilter
  $active[0] | Get-NetFirewallApplicationFilter
  $active[0] | Get-NetFirewallServiceFilter
  $active[0] | Get-NetFirewallInterfaceFilter
  $active[0] | Get-NetFirewallInterfaceTypeFilter
  $active[0] | Get-NetFirewallSecurityFilter
}
```

The controls below apply **after** the receiver prints `READY`. Run only the matching protocol's control in its own receiver run. Substitute `::1` and `InterNetworkV6` only for separately reviewed IPv6 cases. The compiled TCP control uses one total elapsed budget across connect, write and fragmented response reads. Neither control sends a remote packet.

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
# For a TCP receiver run only; --reviewed-live-approval is a marker, not authorization.
& .\ChildStreamPortProbe.exe control-tcp --reviewed-live-approval YES --local 127.0.0.1 --port $rdpPort --seconds 5
if ($LASTEXITCODE -ne 0) { throw 'Local TCP control incomplete; no firewall conclusion' }
```

For a **UDP receiver run only**, the one-datagram control is:

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
$message = [Text.Encoding]::ASCII.GetBytes('CS-PROBE-v1')
$local = [Net.IPAddress]::Parse('127.0.0.1')
$udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
try {
  $udp.Client.ReceiveTimeout = 1000
  $udp.Connect($local,$rdpPort)
  [void]$udp.Send($message,$message.Length)
  $peer = [Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
  $reply = $udp.Receive([ref]$peer)
  if ([Text.Encoding]::ASCII.GetString($reply) -ne 'OK') { throw 'Local UDP control failed' }
} finally { $udp.Dispose() }
```

The UDP control uses per-call timeout and does not establish an overall elapsed-time bound; if it fails, the local measurement is incomplete and no firewall conclusion follows. After the phone attempts, freeze the UTC start/end from the private receipt and receiver. Query only this interval; include the log-clear event and fail on 4,097 records rather than silently truncate. Keep only exact-name or expected-tuple fields locally. This event query is a proposed narrow collection, not a pass/fail parser:

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=5152,5157,1102;StartTime=$windowStart;EndTime=$windowEnd} -MaxEvents 4097 -ErrorAction Stop)
if ($events.Count -ge 4097 -or @($events | Where-Object Id -eq 1102).Count -ne 0) { throw 'Event window incomplete' }
$relevant = foreach ($event in $events) {
  if ($event.Id -eq 1102) { continue }
  [xml]$xml = $event.ToXml()
  $fields = @{}
  foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
  if (($names -contains $fields.FilterOrigin) -or
      ($fields.DestPort -eq [string]$rdpPort -and $fields.DestAddress -eq $reviewedHostIp -and $fields.SourceAddress -eq $reviewedPhoneIp)) {
    [pscustomobject]@{ RecordId=$event.RecordId; Utc=$event.TimeCreated.ToUniversalTime().ToString('o'); Id=$event.Id;
      Direction=$fields.Direction; Protocol=$fields.Protocol; SourceAddress=$fields.SourceAddress; SourcePort=$fields.SourcePort;
      DestAddress=$fields.DestAddress; DestPort=$fields.DestPort; InterfaceIndex=$fields.InterfaceIndex; FilterOrigin=$fields.FilterOrigin }
  }
}
# Store only $relevant in the private receipt directory. Independently check provider,
# unique record IDs, exact time/tuple/interface/family, and exact FilterOrigin.
```

Cleanup is proposed only **after exact-PID receiver exit and a fresh unchanged feature/RDP/TermService/listener check**. The names must still be unique and byte-for-byte receipt-matching before this command. If there is drift, do not execute it automatically.

```powershell
# REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED
foreach ($name in $names) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop }
foreach ($store in @('PersistentStore','ActiveStore')) {
  $remaining = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object { $names -contains $_.Name })
  if ($remaining.Count -ne 0) { throw 'Exact-owned cleanup incomplete' }
}
```

## Stop conditions and owner decisions

Stop before rules for an occupied or uncertain configured port, unavailable security event audit, absent physical sender capability, policy/rule-name conflict, unexpected listener/service/feature state, or incomplete exact-state snapshot. Stop after rules before receiver for failed effective readback. Stop during sends for unexpected LAN receipt, local-control failure, changed RDP/service/feature/listener state, or receiver identity/bind ambiguity. Always report enforcement and cleanup separately.

1. **Client decision, later:** Review installation/use of the named iPhone utility and its Local Network permission solely for one physical-LAN TCP/UDP attempt per supported family to this PC's exact physical address/port. Its listing discloses advertising, optional paid remove-ads subscriptions, and developer-reported identifier/usage tracking; no purchase is required or authorized here. No phone change is authorized by this preparation. If the app cannot demonstrate a case, mark it unavailable; do not substitute a browser or claim a complete dual-stack result.
2. **Host-operation decision, later:** After fresh preflight and a private exact plan, approve or decline the two named short-lived all-application port rules, fixed-message receiver, local control, bounded Security read, and exact-owned cleanup. Expected effect: temporary inbound denial on the configured port across interfaces/profiles for nonloopback sources; another application using that port could be affected, so any occupancy uncertainty stops. Recovery: stop exact PID, verify unchanged RDP/feature/service/listener state, remove only receipt-matching experiment rules, verify absence. Pass/reject/inconclusive meanings are above. This decision unlocks **only** the component experiment.
3. **Conditional audit decision:** Only if the future read-only preflight finds required 5152/5157 failure auditing unavailable, review a separate bounded audit-policy change with original-state capture, expected event-volume/privacy impact, and exact restoration before any packet test. Recommended default is **stop/inconclusive** and return the fact. This package does not request or perform that change.

## Acceptance packet — EXPERIMENT PREPARATION ONLY

- Source baseline for this correction: `b7f6bc3d7dbf1aeefe08e64aad5217fa06b7ed1f`; the package manifest records the exact later build SHA and dirty flag. Only this experiment-only receiver, local control, substituted tests, builder, CI step, and starting document are in scope. Shipping application/TermService policy, X360 kit, audio, feature gate, and controller disabled state are unchanged.
- No current-PC host reads, sockets, phone contact, policy changes, receiver execution, packet sends, Security-event collection, or hardware acceptance occurred during preparation. The compiled `--help` path and synthetic tests are the only executable validation.
- The iPhone sender is a **proposed** existing app with advertised TCP/TCP6/UDP/UDP6 modes; its installed behavior, source-port visibility, Wi-Fi/IPv6 path, and permission are not verified. The exact host configured port and audit availability are historical/unknown until separately approved preflight.
- Acceptance for this package means the method and its limitations are reviewable. It does **not** authorize execution, update PR #4 readiness, close the current-PC qualification, or prove Stage A/B safety.

Primary references: [Microsoft rule selectors and ActiveStore](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule), [Microsoft Filter Origin and auditing](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation), [Apple Local Network permission](https://support.apple.com/en-us/102229), and the [iPhone utility listing](https://apps.apple.com/us/app/network-kit-tcp-udp-debugger/id1631771142).
