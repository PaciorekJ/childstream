using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

// This is intentionally a narrow adapter. It has no registry, firewall, service,
// display, Sunshine, or RDP configuration writer.
internal interface IProbeNative
{
    bool IsFeatureEnabled(out bool enabled);
    bool EnableFeature(bool enabled);
    bool GetChildId(out uint id);
    long? LogonTime(uint id);
    bool Logoff(uint id);
    int LastError { get; }
}

internal sealed class ProbeNative : IProbeNative
{
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSIsChildSessionsEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSEnableChildSessions([MarshalAs(UnmanagedType.Bool)] bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSGetChildSessionId(out uint id);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSLogoffSession(IntPtr server, uint id, bool wait);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    private static extern bool Query(IntPtr server, uint id, int infoClass, out IntPtr data, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr data);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Level1
    {
        public uint SessionId; public int State; public int Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string Station;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string Domain;
        public long LogonTime;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct InfoEx { public uint Level; public Level1 Data; }
    public int LastError { get { return Marshal.GetLastWin32Error(); } }
    public bool IsFeatureEnabled(out bool enabled) { return WTSIsChildSessionsEnabled(out enabled); }
    public bool EnableFeature(bool enabled) { return WTSEnableChildSessions(enabled); }
    public bool GetChildId(out uint id) { return WTSGetChildSessionId(out id); }
    public bool Logoff(uint id) { return WTSLogoffSession(IntPtr.Zero, id, true); }
    public long? LogonTime(uint id)
    {
        IntPtr data; int bytes;
        if (!Query(IntPtr.Zero, id, 25, out data, out bytes)) return null;
        try
        {
            if (data == IntPtr.Zero || bytes < Marshal.SizeOf(typeof(InfoEx))) return null;
            InfoEx info = (InfoEx)Marshal.PtrToStructure(data, typeof(InfoEx));
            return info.Level == 1 && info.Data.SessionId == id && info.Data.LogonTime > 0
                ? (long?)info.Data.LogonTime : null;
        }
        finally { if (data != IntPtr.Zero) WTSFreeMemory(data); }
    }
}

internal interface IProbeInventory { string ReadJson(); }
internal interface IProbeBoundaryInventory { string ReadBoundaryJson(bool operatorConfirmedPhysicalSeverance); }
internal sealed class ScriptProbeInventory : IProbeInventory, IProbeBoundaryInventory
{
    private readonly string script;
    internal ScriptProbeInventory(string scriptPath) { script = Path.GetFullPath(scriptPath); }
    internal static string Run(string path, string arguments, string description)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Reviewed read-only script is missing.", path);
        string pwsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "PowerShell", "7", "pwsh.exe");
        InstallerPolicy.ValidateCanonicalFilePath(pwsh);
        if (!File.Exists(pwsh) || (File.GetAttributes(pwsh) & FileAttributes.ReparsePoint) != 0)
            throw new FileNotFoundException("Protected PowerShell 7 interpreter is unavailable.", pwsh);
        var start = new ProcessStartInfo(pwsh, "-NoProfile -NonInteractive -File \"" + path + "\"" + arguments)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (Process process = Process.Start(start))
        {
            var errorRead = process.StandardError.ReadToEndAsync();
            var outputRead = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(180000))
            {
                try { process.Kill(); } catch (InvalidOperationException) { }
                throw new TimeoutException(description + " timed out.");
            }
            string output = outputRead.GetAwaiter().GetResult();
            if (process.ExitCode != 0) throw new InvalidOperationException(description + " failed: " + errorRead.GetAwaiter().GetResult());
            if (output.Length > 8 * 1024 * 1024) throw new InvalidDataException(description + " exceeds size limit.");
            return output;
        }
    }
    public string ReadJson() { return Run(script, "", "Read-only inventory"); }
    public string ReadBoundaryJson(bool operatorConfirmedPhysicalSeverance)
    {
        string boundary = Path.Combine(Path.GetDirectoryName(script), "network-boundary-diagnostic.ps1");
        return Run(boundary, " -IncludeInventory" +
            (operatorConfirmedPhysicalSeverance ? " -OperatorConfirmedPhysicalSeverance" : ""),
            "Read-only boundary capture");
    }
}

internal sealed class WindowsFeasibilityHost : IFeasibilityHost
{
    private readonly IProbeInventory inventory;
    private readonly IProbeNative native;
    private readonly Func<bool> isAdministrator;
    private readonly string requestingAccountBinding;
    internal WindowsFeasibilityHost(IProbeInventory inventory, IProbeNative native,
        Func<bool> isAdministrator = null, string requestingAccountBinding = null)
    { this.inventory = inventory; this.native = native;
      this.requestingAccountBinding = requestingAccountBinding;
      this.isAdministrator = isAdministrator ?? (() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)); }
    public bool HasAdministratorPrivilege
    {
        get { return isAdministrator(); }
    }
    private static Dictionary<string, object> Obj(object value)
    { return value as Dictionary<string, object> ?? new Dictionary<string, object>(); }
    private static object At(object value, string key)
    { object found; return Obj(value).TryGetValue(key, out found) ? found : null; }
    private static string Str(object value) { return value == null ? null : Convert.ToString(value); }
    private static long Num(object value) { return value == null ? -1 : Convert.ToInt64(value); }
    private static bool Is(object value, string state) { return Str(At(value, "State")) == state; }
    private static object[] Items(object value)
    { return At(value, "Items") as object[] ?? new object[0]; }
    private static string Canonical(object value)
    {
        if (value == null) return "null";
        var map = value as Dictionary<string, object>;
        if (map != null) return "{" + String.Join(",", map.Keys.OrderBy(x => x, StringComparer.Ordinal)
            .Select(x => new JavaScriptSerializer().Serialize(x) + ":" + Canonical(map[x]))) + "}";
        var list = value as IEnumerable;
        if (list != null && !(value is string))
        {
            var entries = new List<string>();
            foreach (object item in list) entries.Add(Canonical(item));
            entries.Sort(StringComparer.Ordinal);
            return "[" + String.Join(",", entries) + "]";
        }
        if (value is bool) return (bool)value ? "true" : "false";
        if (value is string) return new JavaScriptSerializer().Serialize(value);
        if (value is IConvertible) return Convert.ToString(value, CultureInfo.InvariantCulture);
        throw new InvalidDataException("Unsupported inventory fingerprint value.");
    }
    private static string Digest(object value)
    { return ProbeCodec.Hash(Encoding.UTF8.GetBytes(Canonical(value))); }

    internal static ProbeSnapshot ParseBoundaryCapture(string json)
    {
        var parser = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 };
        object capture = parser.DeserializeObject(json);
        if (Str(At(capture, "Schema")) != "ChildStream.BoundaryCapture.v1" ||
            !(At(capture, "HostMutation") is bool) || (bool)At(capture, "HostMutation"))
            throw new InvalidDataException("Unexpected boundary capture schema or mutation marker.");
        object original = At(capture, "Inventory"), boundary = At(capture, "Boundary"),
            observation = At(capture, "Observation");
        if (original == null || boundary == null || observation == null ||
            Str(At(boundary, "Schema")) != "ChildStream.NetworkBoundaryDiagnostic.v1" ||
            !(At(boundary, "HostMutation") is bool) || (bool)At(boundary, "HostMutation") ||
            !(At(boundary, "DiagnosticOnly") is bool) || !(bool)At(boundary, "DiagnosticOnly") ||
            !(At(boundary, "StageAPlanAuthorized") is bool) || (bool)At(boundary, "StageAPlanAuthorized"))
            throw new InvalidDataException("Boundary diagnostic provenance is incomplete.");

        string[] requiredSources = { "Inventory", "HyperVSwitches", "HyperVVirtualMachines",
            "HyperVHostPorts", "HyperVVmPorts", "Wsl", "Docker", "Hns", "HnsEndpoints",
            "NetNat", "PortProxy", "BridgeBindings", "IpForwarding", "DockerProcesses", "DockerListeners" };
        object collection = At(boundary, "Collection");
        bool collectionComplete = requiredSources.All(name => Str(At(collection, name)) == "Accessible" ||
            name == "Docker" && Str(At(collection, name)) == "VerifiedStopped");
        object bridge = At(boundary, "BridgeBindingDiagnostic");
        object[] adapters = Items(At(observation, "Adapters"));
        var pathIndices = new HashSet<long>(Items(At(observation, "IpAddresses"))
            .Concat(Items(At(observation, "Routes"))).Select(x => Num(At(x, "InterfaceIndex"))));
        var relevant = new HashSet<long>();
        bool relevantIdentified = adapters.Length > 0 &&
            adapters.Select(x => Num(At(x, "InterfaceIndex"))).Distinct().Count() == adapters.Length;
        foreach (object adapter in adapters)
        {
            long index = Num(At(adapter, "InterfaceIndex"));
            if (index < 1) { relevantIdentified = false; continue; }
            if (At(adapter, "HardwareInterface") is bool && (bool)At(adapter, "HardwareInterface") ||
                Str(At(adapter, "Status")) == "Up" || pathIndices.Contains(index))
                if (!relevant.Add(index)) relevantIdentified = false;
        }
        object bridgeObservation = At(observation, "BridgeBindings");
        object[] queried = At(bridgeObservation, "Queried") as object[];
        object[] failures = At(bridgeObservation, "Failures") as object[];
        var queriedIndices = queried == null ? new long[0] : queried.Select(x => Num(At(x, "InterfaceIndex"))).ToArray();
        bool bridgeComplete = relevantIdentified && relevant.Count > 0 &&
            Str(At(bridge, "QueryMode")) == "PerRelevantAdapter" &&
            Str(At(bridgeObservation, "QueryMode")) == "PerRelevantAdapter" &&
            Num(At(bridge, "QueriedCount")) == relevant.Count &&
            Num(At(bridge, "FailureCount")) == 0 &&
            queried != null && failures != null && failures.Length == 0 &&
            queriedIndices.Length == relevant.Count && queriedIndices.Distinct().Count() == relevant.Count &&
            queriedIndices.All(relevant.Contains);

        object conditions = At(boundary, "Conditions");
        string[] requiredPredicates = { "network-inventory-complete", "physical-uplinks-down",
            "physical-severance-confirmed", "switches-have-no-external-bridge",
            "physical-route-link-corroboration", "hyperv-host-port-graph",
            "virtual-paths-attributed", "nat-bridge-forwarding-mapped",
            "hns-endpoints-quiescent", "hns-endpoint-network-graph",
            "internal-guests-quiescent", "docker-host-forwarding-absent",
            "rdp-baseline-closed", "guest-to-host-rdp-exposure-excluded",
            "fresh-logon-network-unchanged" };
        object[] predicates = At(boundary, "Predicates") as object[];
        if (predicates == null || predicates.Length != requiredPredicates.Length ||
            predicates.Select(x => Str(At(x, "Id"))).Distinct(StringComparer.Ordinal).Count() != requiredPredicates.Length ||
            requiredPredicates.Any(id => predicates.Count(x => Str(At(x, "Id")) == id &&
                new[] { "Pass", "Fail", "Unknown" }.Contains(Str(At(x, "Verdict")))) != 1) ||
            requiredPredicates.Select((id, index) => new { id, index }).Any(required =>
                Str(At(predicates.Single(x => Str(At(x, "Id")) == required.id), "Condition")) !=
                (required.index < 8 ? "External" : required.index < 12 ? "GuestPath" :
                 required.index < 14 ? "RdpExposure" : "Continuity")))
            throw new InvalidDataException("Boundary predicate coverage is incomplete.");

        bool externalAndGuestPass = Str(At(conditions, "External")) == "Pass" &&
            Str(At(conditions, "GuestPath")) == "Pass" &&
            predicates.Where(x => Str(At(x, "Condition")) == "External" ||
                Str(At(x, "Condition")) == "GuestPath").All(x => Str(At(x, "Verdict")) == "Pass");
        if (Str(At(conditions, "Continuity")) != "Unknown" ||
            predicates.Count(x => Str(At(x, "Id")) == "fresh-logon-network-unchanged" &&
                Str(At(x, "Verdict")) == "Unknown") != 1)
            throw new InvalidDataException("Boundary continuity capture is inconsistent.");

        object network = At(original, "Network");
        object[] originalAdapters = Items(At(network, "Adapters"));
        Func<object, string> adapterState = entry => Num(At(entry, "InterfaceIndex")) + "|" +
            Str(At(entry, "Status")) + "|" + Str(At(entry, "MediaConnectionState"));
        if (network == null || At(original, "Rdp") == null ||
            !Is(At(network, "Adapters"), "Accessible") ||
            !Is(At(network, "IpInterfaces"), "Accessible") ||
            !Is(At(network, "IpAddresses"), "Accessible") ||
            !Is(At(network, "Routes"), "Accessible") ||
            originalAdapters.Length != adapters.Length ||
            !originalAdapters.Select(adapterState).OrderBy(x => x, StringComparer.Ordinal)
                .SequenceEqual(adapters.Select(adapterState).OrderBy(x => x, StringComparer.Ordinal)) ||
            Canonical(At(observation, "IpInterfaces")) != Canonical(At(network, "IpInterfaces")) ||
            Canonical(At(observation, "IpAddresses")) != Canonical(At(network, "IpAddresses")) ||
            Canonical(At(observation, "Routes")) != Canonical(At(network, "Routes")) ||
            Canonical(At(observation, "RdpEvidence")) != Canonical(At(original, "Rdp")))
            throw new InvalidDataException("Boundary observation does not match its Windows inventory.");
        string[] observedSources = { "Adapters", "IpInterfaces", "IpAddresses", "Routes", "Switches",
            "HostPorts", "VirtualMachines", "VmPorts", "Hns", "HnsEndpoints", "NetNat", "PortProxy",
            "BridgeBindings", "IpForwarding", "Wsl", "Docker", "DockerProcesses", "DockerListeners", "Rdp" };
        bool observedComplete = observedSources.All(name => Str(At(At(observation, name), "State")) == "Accessible" ||
            name == "Docker" && Str(At(At(observation, name), "State")) == "VerifiedStopped");
        object docker = At(observation, "Docker"), dockerListeners = At(observation, "DockerListeners");
        object forwarding = At(observation, "Forwarding");
        bool dockerStopped = Str(At(docker, "State")) == "VerifiedStopped";
        bool dockerObservedConsistent = Str(At(collection, "Docker")) == Str(At(docker, "State")) &&
            (dockerStopped || Str(At(docker, "State")) == "Accessible" &&
                Num(At(docker, "RunningContainerCount")) >= 0 &&
                At(docker, "PublishedBindings") is object[]);
        bool dockerStoppedCorroborated = !dockerStopped ||
            Str(At(docker, "ErrorClass")) == "DaemonUnavailable" &&
            At(docker, "RunningContainerCount") == null &&
            At(docker, "PublishedBindings") is object[] &&
            ((object[])At(docker, "PublishedBindings")).Length == 0 &&
            Str(At(collection, "Docker")) == "VerifiedStopped" &&
            Is(At(observation, "DockerProcesses"), "Accessible") &&
            At(At(observation, "DockerProcesses"), "Items") is object[] &&
            Items(At(observation, "DockerProcesses")).Length == 0 &&
            Is(At(observation, "Wsl"), "Accessible") &&
            At(At(observation, "Wsl"), "RunningDistributions") is object[] &&
            ((object[])At(At(observation, "Wsl"), "RunningDistributions")).Length == 0 &&
            Is(At(observation, "HnsEndpoints"), "Accessible") &&
            At(At(observation, "HnsEndpoints"), "Items") is object[] &&
            Items(At(observation, "HnsEndpoints")).Length == 0 &&
            Is(At(observation, "PortProxy"), "Accessible") &&
            At(At(observation, "PortProxy"), "Items") is object[] &&
            Items(At(observation, "PortProxy")).Length == 0 &&
            Is(dockerListeners, "Accessible") &&
            Num(At(dockerListeners, "DockerOwnedTcpCount")) == 0 &&
            Num(At(dockerListeners, "DockerOwnedUdpCount")) == 0 &&
            Str(At(forwarding, "HnsState")) == "Accessible" &&
            Str(At(forwarding, "NetNatState")) == "Accessible" &&
            Str(At(forwarding, "PortProxyState")) == "Accessible" &&
            Str(At(forwarding, "BridgeBindingState")) == "Accessible" &&
            Str(At(forwarding, "IpForwardingState")) == "Accessible" &&
            At(forwarding, "BridgeGraphReviewed") is bool &&
            (bool)At(forwarding, "BridgeGraphReviewed") &&
            Num(At(forwarding, "UnreviewedForwardingPaths")) == 0;
        string reported = Str(At(boundary, "CurrentNetworkFingerprint"));
        bool fingerprintComplete = !String.IsNullOrEmpty(reported) && reported.Length == 64 &&
            reported.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f') &&
            reported == Str(At(observation, "CurrentNetworkFingerprint"));

        ProbeSnapshot snapshot = ParseInventory(parser.Serialize(original));
        object observedRdp = At(observation, "Rdp");
        if (!(At(observedRdp, "PolicyDenied") is bool) ||
            (bool)At(observedRdp, "PolicyDenied") != snapshot.RdpPolicyDenied ||
            !(At(observedRdp, "TermServiceStopped") is bool) ||
            (bool)At(observedRdp, "TermServiceStopped") != snapshot.TermServiceStopped ||
            Num(At(observedRdp, "TcpListenerCount")) < 0 ||
            Num(At(observedRdp, "UdpEndpointCount")) < 0 ||
            ((Num(At(observedRdp, "TcpListenerCount")) == 0 &&
              Num(At(observedRdp, "UdpEndpointCount")) == 0) != snapshot.RdpListenersAbsent))
            throw new InvalidDataException("Boundary RDP observation conflicts with Windows inventory.");
        snapshot.BoundaryAccepted = collectionComplete && bridgeComplete && externalAndGuestPass &&
            observedComplete && dockerObservedConsistent && dockerStoppedCorroborated && fingerprintComplete &&
            At(observation, "OperatorPhysicalSeveranceConfirmed") is bool &&
            (bool)At(observation, "OperatorPhysicalSeveranceConfirmed") &&
            At(observation, "AdapterCollectionConsistent") is bool &&
            (bool)At(observation, "AdapterCollectionConsistent") &&
            At(At(observation, "Forwarding"), "BridgeGraphReviewed") is bool &&
            (bool)At(At(observation, "Forwarding"), "BridgeGraphReviewed") &&
            Num(At(At(observation, "Forwarding"), "UnreviewedForwardingPaths")) == 0;
        snapshot.BoundaryRdpAccepted = Str(At(conditions, "RdpExposure")) == "Pass" &&
            predicates.Where(x => Str(At(x, "Condition")) == "RdpExposure")
                .All(x => Str(At(x, "Verdict")) == "Pass");
        // Bind the complete private source observation, not merely a verdict or
        // a digest supplied by the diagnostic script.
        snapshot.NetworkFingerprint = Digest(observation);
        return snapshot;
    }

    internal static ProbeSnapshot ParseInventory(string json)
    {
        var parser = new JavaScriptSerializer { MaxJsonLength = 4 * 1024 * 1024 };
        object root = parser.DeserializeObject(json);
        if ((Str(At(root, "Schema")) != "ChildStream.ReadOnlyFeasibilityInventory.v2" &&
             Str(At(root, "Schema")) != "ChildStream.ReadOnlyFeasibilityInventory.v3") ||
            At(root, "HostMutation") == null || Convert.ToBoolean(At(root, "HostMutation")))
            throw new InvalidDataException("Unexpected inventory schema or mutation marker.");
        object windows = At(root, "Windows"), feature = At(root, "ChildFeature"), sessions = At(root, "Sessions");
        object current = At(sessions, "Current"), protocol = At(sessions, "CurrentProtocol"), child = At(sessions, "AssociatedChild");
        object enumerated = At(sessions, "Enumerated"), rdp = At(root, "Rdp");
        object local = At(rdp, "LocalDenyConnections"), policy = At(rdp, "PolicyDenyConnections");
        object tcp = At(rdp, "TcpListener"), udp = At(rdp, "UdpEndpoint");
        object firewall = At(rdp, "Firewall"), profiles = At(rdp, "FirewallProfiles"), services = At(rdp, "Services");
        object network = At(root, "Network");
        uint parent = checked((uint)Num(At(sessions, "ProcessSessionId")));
        uint console = checked((uint)Num(At(sessions, "ActiveConsoleSessionId")));
        object[] sessionItems = Items(enumerated);
        bool independent = Is(enumerated, "Accessible") && sessionItems.Length > 0 &&
            sessionItems.All(x => Num(At(x, "SessionId")) == 0 || Num(At(x, "SessionId")) == parent) &&
            sessionItems.Count(x => Num(At(x, "SessionId")) == parent) == 1;
        bool noRdpListeners = Is(tcp, "Accessible") && Is(udp, "Accessible") &&
            Items(tcp).Length == 0 && Items(udp).Length == 0;
        bool servicesKnown = Is(services, "Accessible") && Items(services).Any(x => Str(At(x, "Name")) == "TermService") &&
            Items(services).Where(x => Str(At(x, "Name")) == "TermService")
                .All(x => Str(At(x, "State")) == "Stopped");
        FirewallRdpAssessment firewallAssessment = FirewallRdpAssessment.Assess(profiles, firewall, services, At(rdp, "TcpPort"));
        NetworkIsolationAssessment networkAssessment = NetworkIsolationAssessment.Assess(network);
        bool firewallKnown = firewallAssessment.Accepted;
        // This means the local posture meets the reviewed narrow gate. It is not
        // a claim that every possible remote network route is closed.
        bool rdpDenied = Is(local, "Accessible") && Num(At(local, "Data")) == 1 &&
            (Is(policy, "Absent") || Is(policy, "Accessible") && Num(At(policy, "Data")) == 1);
        bool posture = rdpDenied && noRdpListeners && servicesKnown && firewallKnown;
        var s = new ProbeSnapshot {
            FeatureAccess = ParseAccess(feature), FeatureEnabled = At(feature, "Enabled") != null && Convert.ToBoolean(At(feature, "Enabled")),
            ParentSessionId = parent, ConsoleSessionId = console,
            ParentProtocolType = Is(protocol, "Accessible") ? checked((int)Num(At(protocol, "Value"))) : -1,
            ParentLogonTime = Num(At(current, "LogonTime")),
            AccountBinding = Str(At(root, "AccountBindingHash")),
            Edition = Is(windows, "Accessible") && Str(At(windows, "Caption")) == "Microsoft Windows 11 Pro" ? "Professional" : "Unknown",
            WindowsBuild = checked((int)Num(At(windows, "BuildNumber"))), LocalRdpPostureAccepted = posture,
            RdpPolicyDenied = rdpDenied, TermServiceStopped = servicesKnown,
            RdpListenersAbsent = noRdpListeners,
            FirewallObservationComplete = firewallAssessment.ProfilesAccepted && firewallAssessment.CoverageAccepted,
            NetworkIsolationAccepted = networkAssessment.Accepted,
            NetworkFingerprint = Digest(new object[] { At(network, "Adapters"), At(network, "IpInterfaces"),
                At(network, "IpAddresses"), At(network, "Routes") }),
            ChildAccess = ParseAccess(child), ChildApiErrorCode = checked((int)Num(At(child, "ErrorCode"))),
            IndependentNoUnexpectedSessions = independent,
            SessionInventoryFingerprint = Digest(enumerated),
            RdpRegistryFingerprint = Digest(new object[] { local, policy, At(rdp, "TcpPort") }),
            ListenerFingerprint = Digest(new object[] { tcp, udp, services }), FirewallFingerprint = Digest(firewallAssessment.Canonical),
            DisplayFingerprint = Digest(At(root, "Displays")),
            NativeResourceFingerprint = Digest(new object[] { At(At(root, "Sunshine"), "Services"), At(root, "Vdd") })
        };
        if (Is(child, "Accessible"))
        {
            object details = At(sessions, "AssociatedChildDetails");
            if (Is(details, "Accessible") && Num(At(details, "LogonTime")) > 0)
            {
                s.AssociatedChild = new ChildSessionIdentity(checked((uint)Num(At(child, "SessionId"))),
                    Num(At(details, "LogonTime")));
                long childId = s.AssociatedChild.Value.SessionId;
                s.IndependentOnlyAssociatedChild = childId != 0 && childId != parent &&
                    Is(enumerated, "Accessible") &&
                    sessionItems.All(x => Num(At(x, "SessionId")) == 0 ||
                        Num(At(x, "SessionId")) == parent || Num(At(x, "SessionId")) == childId) &&
                    sessionItems.Count(x => Num(At(x, "SessionId")) == parent) == 1 &&
                    sessionItems.Count(x => Num(At(x, "SessionId")) == childId) == 1;
            }
            else s.ChildAccess = ResourceAccess.Unknown;
        }
        if (!Is(current, "Accessible") || Num(At(current, "SessionId")) != parent) s.ParentLogonTime = -1;
        return s;
    }
    private static ResourceAccess ParseAccess(object value)
    {
        switch (Str(At(value, "State")))
        {
            case "Accessible": return ResourceAccess.Accessible;
            case "Absent": return ResourceAccess.Absent;
            case "Inaccessible": return ResourceAccess.Inaccessible;
            default: return ResourceAccess.Unknown;
        }
    }
    public ProbeSnapshot Capture()
    {
        ProbeSnapshot snapshot = ParseInventory(inventory.ReadJson());
        if (requestingAccountBinding != null) snapshot.AccountBinding = requestingAccountBinding;
        return snapshot;
    }
    public ProbeSnapshot CaptureBoundary(bool operatorConfirmedPhysicalSeverance)
    {
        var boundary = inventory as IProbeBoundaryInventory;
        if (boundary == null) throw new InvalidOperationException("Read-only boundary inventory is unavailable.");
        ProbeSnapshot snapshot = ParseBoundaryCapture(boundary.ReadBoundaryJson(operatorConfirmedPhysicalSeverance));
        if (requestingAccountBinding != null) snapshot.AccountBinding = requestingAccountBinding;
        return snapshot;
    }
    public bool CompareExchangeChildFeature(bool expected, bool desired)
    {
        if (!HasAdministratorPrivilege) throw new InvalidOperationException("Already elevated Administrator token required.");
        bool observed;
        if (!native.IsFeatureEnabled(out observed)) throw new Win32Exception(native.LastError, "Child-feature query failed.");
        if (observed != expected) return false;
        if (!native.EnableFeature(desired)) throw new Win32Exception(native.LastError, "Child-feature write failed.");
        return true;
    }
    public bool LogoffExact(ChildSessionIdentity expected)
    {
        uint id;
        if (!native.GetChildId(out id)) throw new Win32Exception(native.LastError, "Associated-child query failed.");
        if (id != expected.SessionId || native.LogonTime(id) != expected.LogonTime) return false;
        if (!native.Logoff(id)) throw new Win32Exception(native.LastError, "Exact-child logoff failed.");
        return true;
    }
    public ProbeConnectionResult ConnectWithoutPassword(Action observeBoundary, Action<ChildSessionIdentity> observedChild)
    { return ProbeActiveX.Connect(native, observeBoundary, observedChild); }
}

[ComImport, Guid("302D8188-0052-4807-806A-362B628F9AC5"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IProbeRdpExtendedSettings
{ void put_Property([MarshalAs(UnmanagedType.BStr)] string name, ref object value);
  void get_Property([MarshalAs(UnmanagedType.BStr)] string name, out object value); }
internal sealed class ProbeRdpBox : AxHost
{ internal ProbeRdpBox() : base("8B918B82-7985-4C24-89DF-C33AD2BBFBCD") { } internal object Ocx { get { return GetOcx(); } } }
internal static class ProbeRdpNoPrompt
{
    private static readonly Guid NonScriptable4 = new Guid("f50fa8aa-1c7d-4f59-b15c-a90cacae1fcb");
    private static readonly Guid NonScriptable5 = new Guid("4f6996d5-d7b1-412c-b0ff-063718566907");
    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode)]
    private static extern int LoadTypeLibEx(string path, int registrationKind, out ITypeLib library);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int PutVariantBool(IntPtr self, short value);

    private static short PutOffset(ITypeLib library, Guid interfaceId, string property)
    {
        ITypeInfo info = null;
        try
        {
            library.GetTypeInfoOfGuid(ref interfaceId, out info);
            IntPtr attrPointer; info.GetTypeAttr(out attrPointer);
            System.Runtime.InteropServices.ComTypes.TYPEATTR attr;
            try { attr = (System.Runtime.InteropServices.ComTypes.TYPEATTR)Marshal.PtrToStructure(attrPointer, typeof(System.Runtime.InteropServices.ComTypes.TYPEATTR)); }
            finally { info.ReleaseTypeAttr(attrPointer); }
            if (attr.typekind != System.Runtime.InteropServices.ComTypes.TYPEKIND.TKIND_INTERFACE) throw new InvalidOperationException("No-prompt COM type is not a vtable interface.");
            for (int index = 0; index < attr.cFuncs; index++)
            {
                IntPtr functionPointer; info.GetFuncDesc(index, out functionPointer);
                try
                {
                    System.Runtime.InteropServices.ComTypes.FUNCDESC function =
                        (System.Runtime.InteropServices.ComTypes.FUNCDESC)Marshal.PtrToStructure(functionPointer, typeof(System.Runtime.InteropServices.ComTypes.FUNCDESC));
                    var names = new string[1]; int count;
                    info.GetNames(function.memid, names, 1, out count);
                    if (count == 1 && names[0] == property &&
                        function.invkind == System.Runtime.InteropServices.ComTypes.INVOKEKIND.INVOKE_PROPERTYPUT && function.cParams == 1)
                    {
                        if (function.oVft < 3 * IntPtr.Size || function.oVft > 4096 ||
                            function.oVft % IntPtr.Size != 0)
                            throw new InvalidOperationException("No-prompt COM vtable offset is invalid.");
                        return function.oVft;
                    }
                }
                finally { info.ReleaseFuncDesc(functionPointer); }
            }
            throw new MissingMethodException("No-prompt COM property is unavailable: " + property);
        }
        finally { if (info != null) Marshal.ReleaseComObject(info); }
    }
    private static void SetFalse(object control, ITypeLib library, Guid interfaceId, string property)
    {
        short offset = PutOffset(library, interfaceId, property);
        IntPtr unknown = Marshal.GetIUnknownForObject(control), instance = IntPtr.Zero;
        try
        {
            Guid requested = interfaceId;
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(unknown, ref requested, out instance));
            IntPtr entry = Marshal.ReadIntPtr(Marshal.ReadIntPtr(instance), offset);
            if (entry == IntPtr.Zero) throw new InvalidOperationException("No-prompt COM entry is missing.");
            int hr = ((PutVariantBool)Marshal.GetDelegateForFunctionPointer(entry, typeof(PutVariantBool)))(instance, 0);
            Marshal.ThrowExceptionForHR(hr);
        }
        finally { if (instance != IntPtr.Zero) Marshal.Release(instance); Marshal.Release(unknown); }
    }
    internal static void Configure(object control)
    {
        ITypeLib library;
        Marshal.ThrowExceptionForHR(LoadTypeLibEx(Path.Combine(Environment.SystemDirectory, "mstscax.dll"), 2, out library));
        try
        {
            SetFalse(control, library, NonScriptable4, "PromptForCredsOnClient");
            SetFalse(control, library, NonScriptable4, "AllowCredentialSaving");
            SetFalse(control, library, NonScriptable5, "AllowPromptingForCredentials");
        }
        finally { Marshal.ReleaseComObject(library); }
    }
}
internal static class ProbeActiveX
{
    internal static ProbeConnectionResult Connect(IProbeNative native, Action observeBoundary,
        Action<ChildSessionIdentity> observedChild)
    {
        uint before;
        if (!native.GetChildId(out before) || before != uint.MaxValue)
            throw new InvalidOperationException("Positive no-child API result required immediately before ActiveX.");
        using (var form = new Form { Text = "ChildStream one-session feasibility", Width = 1000, Height = 700 })
        using (var box = new ProbeRdpBox { Dock = DockStyle.Fill })
        {
            form.Controls.Add(box); form.Show(); Application.DoEvents();
            dynamic ocx = box.Ocx;
            // Every prompt suppression setter is mandatory. A missing COM member
            // aborts before Connect; this path never supplies credentials.
            ocx.Server = "localhost";
            ocx.AdvancedSettings7.EnableCredSspSupport = true;
            ProbeRdpNoPrompt.Configure(box.Ocx);
            object child = true;
            ((IProbeRdpExtendedSettings)box.Ocx).put_Property("ConnectToChildSession", ref child);
            if (observedChild == null) throw new ArgumentNullException("observedChild");
            if (observeBoundary != null) observeBoundary(); // fail before creating a child
            Exception monitorError = null;
            object errorGate = new object();
            using (var stop = new CancellationTokenSource())
            {
                Task monitorTask = null;
                ProbeConnectionResult result = null;
                try
                {
                    ocx.Connect(); // asynchronous: return is not authentication evidence
                    DateTime deadline = DateTime.UtcNow.AddSeconds(45);
                    while (DateTime.UtcNow < deadline && !form.IsDisposed)
                    {
                        Application.DoEvents();
                        if (form.IsDisposed) break;
                        lock (errorGate) { if (monitorError != null) break; }
                        if ((int)ocx.Connected == 1)
                        {
                            uint id;
                            if (native.GetChildId(out id) && id != uint.MaxValue)
                            {
                                long? generation = native.LogonTime(id);
                                if (generation.HasValue && generation.Value > 0)
                                {
                                    var identity = new ChildSessionIdentity(id, generation.Value);
                                    observedChild(identity); // persist exact child before viewer interaction
                                    result = (int)ocx.Connected == 1 && !form.IsDisposed
                                        ? new ProbeConnectionResult { Outcome = ProbeConnectOutcome.AutomaticLogon,
                                            Identity = identity }
                                        : new ProbeConnectionResult { Outcome = ProbeConnectOutcome.Unknown,
                                            Identity = identity, ErrorCode = native.LastError };
                                    break;
                                }
                            }
                        }
                        Thread.Sleep(100);
                    }
                    if (result == null)
                        result = new ProbeConnectionResult { Outcome = ProbeConnectOutcome.Unknown,
                            ErrorCode = native.LastError };
                    else if (result.Outcome == ProbeConnectOutcome.AutomaticLogon && !form.IsDisposed)
                    {
                        // One independent capture was taken before Connect and
                        // observedChild checked the boundary after authentication.
                        // Start periodic captures only during interactive viewing;
                        // a concurrent full capture must not block the identity
                        // callback while the COM connection is being established.
                        if (observeBoundary != null)
                            monitorTask = Task.Run(() =>
                            {
                                while (!stop.IsCancellationRequested)
                                {
                                    try { observeBoundary(); }
                                    catch (Exception ex)
                                    {
                                        lock (errorGate) monitorError = ex;
                                        try { form.BeginInvoke((MethodInvoker)(() => form.Close())); }
                                        catch (InvalidOperationException) { }
                                        return;
                                    }
                                    if (stop.Token.WaitHandle.WaitOne(5000)) return;
                                }
                            });
                        form.Text = "ChildStream test viewer - close after interaction checks";
                        Application.Run(form);
                    }
                }
                finally
                {
                    stop.Cancel();
                    if (monitorTask != null) monitorTask.Wait();
                }
                lock (errorGate)
                    if (monitorError != null)
                        throw new InvalidOperationException("Isolated boundary changed during the viewer test.", monitorError);
                return result;
            }
        }
    }
}
