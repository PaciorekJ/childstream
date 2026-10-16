using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Net;
#pragma warning disable 0649 // Runtime observation records are populated by child-side adapters and tests.

internal enum CaptureBackend { DesktopDuplication, WindowsGraphicsCapture }

internal sealed class ChildProductOptions
{
    internal uint ParentSessionId;
    internal ChildSessionIdentity Child;
    internal string OwnedInstallationRoot, OwnedRoot, DisplayDeviceId, AudioEndpointId;
    internal bool DisplayActiveInChild, ViGEmBusPresent;
    internal ChildAudioEndpointInventory AudioInventory;
    internal CaptureBackend Capture;
    internal int Port = 48089;
    internal string BindAddress = "127.0.0.1";
    internal SunshineLanCandidate LanCandidate;
}

// This object only permits deterministic configuration generation. It is not
// evidence of firewall approval, Moonlight custom-port support, concurrent
// capture, or an authorized Sunshine launch.
internal sealed class SunshineLanCandidate
{
    internal ChildSessionIdentity Child;
    internal string BindAddress;
    internal int Port;
    internal bool BoundaryVerified;

    internal SunshinePortFamily Validate()
    {
        IPAddress address;
        if (Child.SessionId == 0 || Child.SessionId == uint.MaxValue || Child.LogonTime <= 0 ||
            !IPAddress.TryParse(BindAddress, out address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) ||
            !IsPrivateIpv4(address.GetAddressBytes()))
            throw new InvalidDataException("A concrete RFC1918 IPv4 LAN endpoint is required.");
        if (Port == 47989)
            throw new InvalidDataException("The native Sunshine default port family must remain separate.");
        var family = new SunshinePortFamily(Port);
        if (family.Overlaps(new SunshinePortFamily(47989)))
            throw new InvalidDataException("The ChildStream port family overlaps native Sunshine defaults.");
        return family;
    }

    private static bool IsPrivateIpv4(byte[] bytes)
    {
        return bytes.Length == 4 && (bytes[0] == 10 ||
            (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
            (bytes[0] == 192 && bytes[1] == 168));
    }
}

internal sealed class SunshinePortFamily
{
    internal readonly int BasePort;
    internal readonly int[] Tcp;
    internal readonly int[] Udp;
    internal SunshinePortFamily(int basePort)
    {
        if (basePort < 1029 || basePort > 65514)
            throw new InvalidDataException("Sunshine base port is outside its documented range.");
        BasePort = basePort;
        Tcp = new [] { basePort - 5, basePort, basePort + 1, basePort + 21 };
        Udp = new [] { basePort + 9, basePort + 10, basePort + 11, basePort + 13 };
    }
    internal bool Contains(string protocol, int port)
    {
        int[] ports = protocol == "TCP" ? Tcp : protocol == "UDP" ? Udp : null;
        return ports != null && Array.IndexOf(ports, port) >= 0;
    }
    internal bool Overlaps(SunshinePortFamily other)
    {
        foreach (int port in Tcp) if (Array.IndexOf(other.Tcp, port) >= 0) return true;
        foreach (int port in Udp) if (Array.IndexOf(other.Udp, port) >= 0) return true;
        return false;
    }
}

internal static class ChildProductConfiguration
{
    // Pinned Sunshine's Windows policy: choose its free ViGEmBus path explicitly
    // while controller reports remain off pending real cross-session acceptance.
    // This chooses a backend; it does not assert that Windows isolates its devices.
    internal static void AppendInputPolicy(Action<string, string> line, bool interactiveDesktop)
    {
        if (line == null) throw new ArgumentNullException("line");
        line("keyboard", interactiveDesktop ? "enabled" : "disabled");
        line("mouse", interactiveDesktop ? "enabled" : "disabled");
        line("controller", "disabled");
        line("gamepad_driver", "vigembus");
    }

    private static string SafePath(string root, string name)
    {
        string path = Path.Combine(root, name);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        return SafeValue(path, "Child configuration path");
    }

    private static string SafeValue(string value, string label)
    {
        if (String.IsNullOrWhiteSpace(value) || value.IndexOfAny(new [] { '\r', '\n', '\0', '=', '#', ';' }) >= 0)
            throw new InvalidDataException(label + " is empty or contains configuration syntax.");
        return value;
    }

    internal static string BuildSunshine(ChildProductOptions option)
    {
        if (option == null || option.Child.SessionId == 0 || option.Child.SessionId == uint.MaxValue ||
            option.Child.SessionId == option.ParentSessionId || option.Child.LogonTime <= 0)
            throw new InvalidDataException("An exact parent-associated child session is required.");
        if (String.IsNullOrEmpty(option.OwnedInstallationRoot) || !Path.IsPathRooted(option.OwnedInstallationRoot) ||
            !Path.IsPathRooted(option.OwnedRoot))
            throw new InvalidDataException("Child configuration root must be absolute.");
        string install = InstallerPolicy.ValidateCanonicalFilePath(option.OwnedInstallationRoot, true)
            .TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(install), "ChildStream", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFullPath(option.OwnedRoot),
                Path.Combine(install, "sessions", option.Child.SessionId + "-" + option.Child.LogonTime),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Child configuration must use its exact dedicated ChildStream session directory.");
        InstallerPolicy.ValidateCanonicalFilePath(option.OwnedRoot, true);
        Guid displayGuid;
        if (!option.DisplayActiveInChild || !Guid.TryParse(SafeValue(option.DisplayDeviceId, "Child display"), out displayGuid))
            throw new InvalidDataException("An active, child-observed Sunshine display GUID is required.");
        SafeValue(option.AudioEndpointId, "Child audio endpoint");
        if (option.AudioInventory == null || !option.AudioInventory.Complete ||
            option.AudioInventory.SessionId != option.Child.SessionId ||
            !option.AudioInventory.ActiveRenderIds.Contains(option.AudioEndpointId))
            throw new InvalidDataException("The selected audio sink must be an active child-observed render endpoint.");
        if (option.LanCandidate == null)
        {
            if (option.BindAddress != "127.0.0.1" ||
                new SunshinePortFamily(option.Port).Overlaps(new SunshinePortFamily(47989)))
                throw new InvalidDataException("Loopback ChildStream streaming needs a non-native port family.");
        }
        else
        {
            option.LanCandidate.Validate();
            if (!option.LanCandidate.BoundaryVerified || !option.LanCandidate.Child.Equals(option.Child) ||
                !String.Equals(option.LanCandidate.BindAddress, option.BindAddress, StringComparison.Ordinal) ||
                option.LanCandidate.Port != option.Port)
                throw new InvalidDataException("Approved LAN boundary does not match the exact child and endpoint.");
        }
        string root = Path.GetFullPath(option.OwnedRoot).TrimEnd(Path.DirectorySeparatorChar);
        string identityRoot = Path.Combine(install, "identity");
        InstallerPolicy.ValidateCanonicalFilePath(identityRoot, true);
        var config = new StringBuilder();
        Action<string, string> line = (key, value) => config.Append(key).Append(" = ").Append(value).Append('\n');
        line("sunshine_name", "ChildStream");
        line("address_family", "ipv4");
        // The pinned Sunshine release has one bind_address for GameStream and
        // its Web UI. A verified scoped firewall admission is mandatory before
        // wildcard IPv4 binding, so the local pinned admin client can stay on
        // loopback while the approved LAN can reach only streaming ports.
        line("bind_address", option.LanCandidate == null ? "127.0.0.1" : "0.0.0.0");
        line("port", option.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        line("origin_web_ui_allowed", "pc");
        line("upnp", "disabled");
        line("install_steam_audio_drivers", "disabled");
        line("file_apps", SafePath(root, "apps.json"));
        line("credentials_file", SafePath(identityRoot, "credentials.json"));
        line("file_state", SafePath(identityRoot, "sunshine_state.json"));
        line("log_path", SafePath(root, "sunshine.log"));
        line("pkey", SafePath(identityRoot, "sunshine.key"));
        line("cert", SafePath(identityRoot, "sunshine.cert"));
        line("output_name", "{" + displayGuid.ToString() + "}");
        line("dd_configuration_option", "verify_only");
        line("dd_resolution_option", "disabled");
        line("dd_refresh_rate_option", "disabled");
        line("capture", option.Capture == CaptureBackend.WindowsGraphicsCapture ? "wgc" : "ddx");
        line("encoder", "nvenc");
        line("audio_sink", option.AudioEndpointId);
        // The pinned capture-only backend never changes the Windows default or
        // installs a driver. Routing game output to this endpoint remains an
        // independent prerequisite; the child agent observes it separately.
        line("external_audio", "enabled");
        line("stream_audio", "enabled");
        AppendInputPolicy(line, true);
        line("gamepad", "x360");
        return config.ToString();
    }

    internal static string BuildApps()
    {
        // No shell commands in Sunshine's apps file. Steam launch is owned by the
        // child runtime after exact process/session checks, never by Moonlight.
        return "{\"env\":{},\"apps\":[{\"name\":\"Desktop\"}]}";
    }
}

internal sealed class ProductProcessIdentity
{
    internal int Pid;
    internal int SessionId;
    internal long StartTimeUtcTicks;
    internal string ExecutablePath;
    internal string ExecutableSha256;
}

internal interface IProductProcessHost
{
    int CurrentSessionId { get; }
    long? ReadSessionLogonTime(int sessionId);
    ProductProcessIdentity Read(int pid);
    ProductProcessIdentity Start(string executable, string arguments, string workingDirectory);
    bool RequestClose(int pid);
    bool WaitForExit(int pid, int milliseconds);
    void Kill(int pid);
}

internal sealed class ChildOwnedProcess
{
    private readonly IProductProcessHost host;
    private readonly ChildSessionIdentity child;
    private readonly string executable;
    private readonly string digest;
    private ProductProcessIdentity owned;
    internal string Failure { get; private set; }
    internal ProductProcessIdentity Identity { get { return owned; } }

    internal ChildOwnedProcess(IProductProcessHost host, ChildSessionIdentity child, string executable, string digest)
    {
        if (host == null || child.SessionId == 0 || child.SessionId == uint.MaxValue || child.LogonTime <= 0 ||
            String.IsNullOrWhiteSpace(executable) || !Path.IsPathRooted(executable) ||
            String.IsNullOrEmpty(digest) || digest.Length != 64 ||
            !System.Text.RegularExpressions.Regex.IsMatch(digest, "\\A[0-9a-fA-F]{64}\\z"))
            throw new InvalidDataException("An exact child, absolute executable and SHA-256 digest are required.");
        this.host = host; this.child = child; this.executable = Path.GetFullPath(executable); this.digest = digest;
    }

    private bool Same(ProductProcessIdentity actual)
    {
        return actual != null && owned != null && actual.Pid > 0 && actual.Pid == owned.Pid &&
            actual.SessionId == (int)child.SessionId && owned.StartTimeUtcTicks > 0 &&
            actual.StartTimeUtcTicks == owned.StartTimeUtcTicks &&
            String.Equals(Path.GetFullPath(actual.ExecutablePath), executable, StringComparison.OrdinalIgnoreCase) &&
            String.Equals(actual.ExecutableSha256, digest, StringComparison.OrdinalIgnoreCase);
    }

    private void RequireExactChildGeneration()
    {
        if (host.CurrentSessionId != (int)child.SessionId ||
            host.ReadSessionLogonTime((int)child.SessionId) != child.LogonTime)
            throw new InvalidOperationException("The current process is not in the exact child logon generation.");
    }

    internal void Start(string arguments)
    {
        if (owned != null) throw new InvalidOperationException("This child-owned process already has a start outcome.");
        RequireExactChildGeneration();
        owned = host.Start(executable, arguments, Path.GetDirectoryName(executable));
        RequireExactChildGeneration();
        if (owned == null || !Same(owned))
        {
            Failure = "Started process identity or session did not match the approved child.";
            throw new InvalidOperationException(Failure);
        }
    }

    internal void Attach(ProductProcessIdentity observed)
    {
        if (owned != null) throw new InvalidOperationException("This child-owned process already has an identity.");
        RequireExactChildGeneration();
        if (observed == null || observed.Pid <= 0 || observed.StartTimeUtcTicks <= 0)
            throw new InvalidOperationException("An exact child process observation is required.");
        owned = observed;
        bool matches;
        try { matches = Same(host.Read(observed.Pid)); RequireExactChildGeneration(); }
        catch { owned = null; throw; }
        if (!matches)
        {
            owned = null;
            throw new InvalidOperationException("Observed process identity changed before attachment.");
        }
    }

    internal bool VerifyRunning()
    {
        if (owned == null) return false;
        RequireExactChildGeneration();
        return Same(host.Read(owned.Pid)); // inaccessible is not evidence of absence
    }

    internal void Stop(int gracefulTimeoutMs)
    {
        if (owned == null || gracefulTimeoutMs < 0 || gracefulTimeoutMs > 30000)
            throw new InvalidOperationException("No owned process or invalid shutdown timeout.");
        RequireExactChildGeneration();
        ProductProcessIdentity current = host.Read(owned.Pid);
        if (current == null) return; // Verified absent. Inaccessible remains an error.
        if (!Same(current)) throw new InvalidOperationException("Process identity changed; refusing to stop an unrelated process.");
        host.RequestClose(owned.Pid);
        if (host.WaitForExit(owned.Pid, gracefulTimeoutMs)) return;
        RequireExactChildGeneration();
        current = host.Read(owned.Pid);
        if (!Same(current)) throw new InvalidOperationException("Process changed during shutdown; refusing termination.");
        host.Kill(owned.Pid);
        if (!host.WaitForExit(owned.Pid, 5000))
            throw new InvalidOperationException("Owned process termination was not verified.");
    }
}

internal sealed class WindowsProductProcessHost : IProductProcessHost
{
    public int CurrentSessionId { get { return Process.GetCurrentProcess().SessionId; } }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    private static extern bool WtsQuery(IntPtr server, uint sessionId, int infoClass, out IntPtr data, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr data);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsLevel1
    {
        public uint SessionId; public int State; public int Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string Station;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string Domain;
        public long LogonTime;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsInfoEx { public uint Level; public WtsLevel1 Data; }

    public long? ReadSessionLogonTime(int sessionId)
    {
        if (sessionId <= 0) return null;
        IntPtr data; int bytes;
        if (!WtsQuery(IntPtr.Zero, (uint)sessionId, 25, out data, out bytes)) return null;
        try
        {
            if (data == IntPtr.Zero || bytes < Marshal.SizeOf(typeof(WtsInfoEx))) return null;
            WtsInfoEx info = (WtsInfoEx)Marshal.PtrToStructure(data, typeof(WtsInfoEx));
            return info.Level == 1 && info.Data.SessionId == (uint)sessionId && info.Data.LogonTime > 0
                ? (long?)info.Data.LogonTime : null;
        }
        finally { if (data != IntPtr.Zero) WTSFreeMemory(data); }
    }

    public ProductProcessIdentity Read(int pid)
    {
        Process process;
        try { process = Process.GetProcessById(pid); }
        catch (ArgumentException) { return null; }
        using (process)
        {
            string path = process.MainModule.FileName;
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var sha = SHA256.Create())
                return new ProductProcessIdentity { Pid = process.Id, SessionId = process.SessionId,
                    StartTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks, ExecutablePath = path,
                    ExecutableSha256 = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant() };
        }
    }

    public ProductProcessIdentity Start(string executable, string arguments, string workingDirectory)
    {
        var info = new ProcessStartInfo(executable, arguments) { UseShellExecute = false,
            CreateNoWindow = false, WorkingDirectory = workingDirectory };
        using (Process process = Process.Start(info))
        {
            if (process == null) throw new InvalidOperationException("Windows returned no started process.");
            return Read(process.Id);
        }
    }

    public bool RequestClose(int pid)
    {
        using (Process process = Process.GetProcessById(pid)) return process.CloseMainWindow();
    }

    public bool WaitForExit(int pid, int milliseconds)
    {
        using (Process process = Process.GetProcessById(pid)) return process.WaitForExit(milliseconds);
    }

    public void Kill(int pid)
    {
        using (Process process = Process.GetProcessById(pid)) process.Kill();
    }
}

internal sealed class SunshineCollisionSnapshot
{
    internal bool ServiceObservationComplete, ProcessObservationComplete, PortObservationComplete;
    internal bool ExistingSunshineService, ExistingSunshineProcess;
    internal readonly HashSet<int> TcpListeners = new HashSet<int>();
    internal readonly HashSet<int> UdpListeners = new HashSet<int>();
}

internal static class SunshineStartupGate
{
    // Conservative subset of the published default family, including the UI and
    // microphone port. Runtime must also verify all newly opened listeners.
    internal static string Check(SunshineCollisionSnapshot state)
    {
        if (state == null || !state.ServiceObservationComplete || !state.ProcessObservationComplete ||
            !state.PortObservationComplete)
            return "Sunshine service, process, or listener ownership could not be fully observed.";
        if (state.ExistingSunshineService || state.ExistingSunshineProcess)
            return "An existing Sunshine instance is present; coexistence and port ownership are unvalidated.";
        foreach (int port in new [] { 47984, 47989, 47990, 48010 })
            if (state.TcpListeners.Contains(port)) return "TCP port " + port + " is already occupied.";
        foreach (int port in new [] { 47998, 47999, 48000, 48002 })
            if (state.UdpListeners.Contains(port)) return "UDP port " + port + " is already occupied.";
        return null;
    }

    // A collision-free family is only a source-level prerequisite. It does
    // not establish Moonlight compatibility or simultaneous GPU capture.
    internal static string CheckCandidate(SunshineCollisionSnapshot state, SunshineLanCandidate candidate)
    {
        if (state == null || !state.ServiceObservationComplete || !state.ProcessObservationComplete ||
            !state.PortObservationComplete || candidate == null)
            return "Sunshine coexistence inventory is incomplete.";
        SunshinePortFamily family;
        try { family = candidate.Validate(); }
        catch (Exception ex) { return ex.Message; }
        foreach (int port in family.Tcp)
            if (state.TcpListeners.Contains(port)) return "Candidate TCP port " + port + " is occupied.";
        foreach (int port in family.Udp)
            if (state.UdpListeners.Contains(port)) return "Candidate UDP port " + port + " is occupied.";
        return null;
    }
    internal static string CheckFamilyAvailable(SunshineCollisionSnapshot state, SunshinePortFamily family)
    {
        if (state == null || family == null || !state.ServiceObservationComplete ||
            !state.ProcessObservationComplete || !state.PortObservationComplete)
            return "Sunshine coexistence inventory is incomplete.";
        foreach (int port in family.Tcp)
            if (state.TcpListeners.Contains(port)) return "ChildStream TCP port " + port + " is occupied.";
        foreach (int port in family.Udp)
            if (state.UdpListeners.Contains(port)) return "ChildStream UDP port " + port + " is occupied.";
        return null;
    }
}

internal static class WindowsSunshineCollisionReader
{
    // Read only. Each source has an independent completeness bit; an inaccessible
    // WMI provider cannot masquerade as an empty listener table.
    internal static SunshineCollisionSnapshot Read()
    { return Read(new SunshinePortFamily(47989)); }

    private static string Filter(SunshinePortFamily family)
    {
        var ports = new HashSet<int>(family.Tcp);
        foreach (int port in family.Udp) ports.Add(port);
        var terms = new List<string>();
        foreach (int port in ports) terms.Add("LocalPort=" + port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return String.Join(" OR ", terms.ToArray());
    }

    internal static SunshineCollisionSnapshot Read(SunshinePortFamily family)
    {
        var result = new SunshineCollisionSnapshot();
        if (family == null) return result;
        try
        {
            using (var service = new ServiceController("SunshineService"))
            { var observed = service.Status; result.ExistingSunshineService = true; }
            result.ServiceObservationComplete = true;
        }
        catch (InvalidOperationException ex)
        {
            var win32 = ex.InnerException as Win32Exception;
            result.ServiceObservationComplete = win32 != null && win32.NativeErrorCode == 1060;
        }
        catch (Win32Exception ex) { result.ServiceObservationComplete = ex.NativeErrorCode == 1060; }
        catch { result.ServiceObservationComplete = false; }
        try
        {
            Process[] processes = Process.GetProcessesByName("sunshine");
            result.ExistingSunshineProcess = processes.Length != 0;
            foreach (Process process in processes) process.Dispose();
            result.ProcessObservationComplete = true;
        }
        catch { result.ProcessObservationComplete = false; }
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            scope.Connect();
            foreach (var query in new [] { new { Class = "MSFT_NetTCPConnection", Tcp = true },
                                           new { Class = "MSFT_NetUDPEndpoint", Tcp = false } })
            {
                using (var searcher = new ManagementObjectSearcher(scope,
                    new ObjectQuery("SELECT LocalPort" + (query.Tcp ? ", State" : "") +
                        " FROM " + query.Class + " WHERE " + Filter(family))))
                using (ManagementObjectCollection rows = searcher.Get())
                    foreach (ManagementBaseObject row in rows)
                    {
                        if (query.Tcp && Convert.ToInt32(row["State"]) != 2) continue;
                        int port = Convert.ToInt32(row["LocalPort"]);
                        if (query.Tcp) result.TcpListeners.Add(port);
                        else result.UdpListeners.Add(port);
                    }
            }
            result.PortObservationComplete = true;
        }
        catch { result.PortObservationComplete = false; }
        return result;
    }

    internal static IList<SunshineListener> ReadListeners(int ownedPid, out bool complete)
    { return ReadListeners(ownedPid, new SunshinePortFamily(47989), out complete); }

    internal static IList<SunshineListener> ReadListeners(int ownedPid, SunshinePortFamily family, out bool complete)
    {
        var listeners = new List<SunshineListener>();
        if (ownedPid <= 0 || family == null) { complete = false; return listeners; }
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            scope.Connect();
            foreach (var query in new [] { new { Class = "MSFT_NetTCPConnection", Tcp = true },
                                           new { Class = "MSFT_NetUDPEndpoint", Tcp = false } })
                using (var searcher = new ManagementObjectSearcher(scope,
                    new ObjectQuery("SELECT LocalAddress, LocalPort, OwningProcess" +
                        (query.Tcp ? ", State" : "") + " FROM " + query.Class +
                        " WHERE OwningProcess=" + ownedPid + " OR " + Filter(family))))
                using (ManagementObjectCollection rows = searcher.Get())
                    foreach (ManagementBaseObject row in rows)
                    {
                        if (query.Tcp && Convert.ToInt32(row["State"]) != 2) continue;
                        listeners.Add(new SunshineListener { Protocol = query.Tcp ? "TCP" : "UDP",
                            LocalAddress = Convert.ToString(row["LocalAddress"]),
                            Port = Convert.ToInt32(row["LocalPort"]),
                            Pid = Convert.ToInt32(row["OwningProcess"]) });
                    }
            complete = true;
        }
        catch { complete = false; listeners.Clear(); }
        return listeners;
    }
}

internal sealed class SunshineListener
{
    internal string Protocol, LocalAddress;
    internal int Port, Pid;
}

internal static class SunshineRuntimeGate
{
    internal static string Check(bool observationComplete, int ownedPid, IEnumerable<SunshineListener> listeners)
    {
        if (!observationComplete || listeners == null || ownedPid <= 0)
            return "Sunshine listener ownership could not be verified.";
        int ownedCount = 0;
        foreach (SunshineListener endpoint in listeners)
        {
            bool expectedTcp = endpoint.Protocol == "TCP" &&
                (endpoint.Port == 47984 || endpoint.Port == 47989 || endpoint.Port == 47990 || endpoint.Port == 48010);
            bool expectedUdp = endpoint.Protocol == "UDP" &&
                (endpoint.Port == 47998 || endpoint.Port == 47999 || endpoint.Port == 48000 || endpoint.Port == 48002);
            if (!expectedTcp && !expectedUdp)
            {
                if (endpoint.Pid == ownedPid) return "Owned Sunshine opened an unexpected listener.";
                continue;
            }
            if (endpoint.Pid != ownedPid) return "A Sunshine-family listener belongs to another process.";
            if (endpoint.LocalAddress != "127.0.0.1" && endpoint.LocalAddress != "::1")
                return "Sunshine opened a non-loopback listener without LAN approval.";
            ownedCount++;
        }
        return ownedCount == 0 ? "Sunshine has not opened a verifiable listener." : null;
    }

    internal static string CheckCandidate(bool observationComplete, int ownedPid,
        string bindAddress, SunshinePortFamily family, IEnumerable<SunshineListener> listeners)
    {
        if (!observationComplete || listeners == null || ownedPid <= 0 || family == null ||
            String.IsNullOrEmpty(bindAddress))
            return "Candidate Sunshine listener ownership could not be verified.";
        var observed = new HashSet<string>(StringComparer.Ordinal);
        foreach (SunshineListener endpoint in listeners)
        {
            bool inFamily = family.Contains(endpoint.Protocol, endpoint.Port);
            if (endpoint.Pid == ownedPid)
            {
                if (!inFamily) return "Owned Sunshine opened a listener outside its approved port family.";
                if (!String.Equals(endpoint.LocalAddress, bindAddress, StringComparison.Ordinal))
                    return "Owned Sunshine listener bound outside the selected LAN address.";
                if (!observed.Add(endpoint.Protocol + ":" + endpoint.Port))
                    return "Duplicate owned Sunshine listener observation.";
            }
            else if (inFamily) return "Candidate Sunshine-family listener belongs to another process.";
        }
        // At least one owned listener is required for readiness. The full
        // protocol family is checked during the live pairing/stream test.
        return observed.Count == 0 ? "Candidate Sunshine opened no verifiable listener." : null;
    }
}

internal static class SteamChildPolicy
{
    internal const string MinecraftDungeonsAppId = "1672970";
    internal static string Check(bool processObservationComplete, bool parentSteamRunning,
        bool unrelatedSteamRunning, bool childSteamRunning)
    {
        if (!processObservationComplete) return "Steam process ownership is unknown.";
        if (parentSteamRunning || unrelatedSteamRunning)
            return "An existing Steam instance may own the singleton or game session; no child launch is allowed.";
        if (childSteamRunning) return "The child already has Steam; reconcile its exact process identity before launch.";
        return null;
    }
}

internal enum SteamChildStage { NotStarted, BigPictureStarted, GameRequested, GameObserved, GameEnded, Ended, Conflict }

internal sealed class SteamChildRuntime
{
    private readonly IProductProcessHost host;
    private readonly ChildSessionIdentity child;
    private readonly string steamPath, steamDigest, gamePath, gameDigest;
    private ChildOwnedProcess steam, game;
    internal SteamChildStage Stage { get; private set; }
    internal string Failure { get; private set; }
    internal ProductProcessIdentity SteamIdentity { get { return steam == null ? null : steam.Identity; } }
    internal ProductProcessIdentity GameIdentity { get { return game == null ? null : game.Identity; } }

    internal void AssertHealthyForStreamingRecovery()
    {
        if ((Stage != SteamChildStage.BigPictureStarted && Stage != SteamChildStage.GameObserved) ||
            steam == null || !steam.VerifyRunning() ||
            (Stage == SteamChildStage.GameObserved && (game == null || !game.VerifyRunning())))
            throw new InvalidOperationException(
                "Steam or game ownership is unresolved; Sunshine-only recovery cannot change it.");
    }

    internal SteamChildRuntime(IProductProcessHost host, ChildSessionIdentity child,
        string steamPath, string steamDigest, string gamePath, string gameDigest)
    {
        this.host = host; this.child = child;
        this.steamPath = Path.GetFullPath(steamPath); this.steamDigest = steamDigest;
        this.gamePath = Path.GetFullPath(gamePath); this.gameDigest = gameDigest;
        Stage = SteamChildStage.NotStarted;
    }

    internal void StartBigPicture(bool observationComplete, bool parentSteam,
        bool unrelatedSteam, bool childSteam)
    {
        if (Stage != SteamChildStage.NotStarted)
            throw new InvalidOperationException("Steam has already been started or has an unresolved outcome.");
        string conflict = SteamChildPolicy.Check(observationComplete, parentSteam, unrelatedSteam, childSteam);
        if (conflict != null) throw new InvalidOperationException(conflict);
        steam = new ChildOwnedProcess(host, child, steamPath, steamDigest);
        try
        {
            steam.Start("-bigpicture");
            if (!steam.VerifyRunning()) throw new InvalidOperationException("The child Steam process is not running.");
            Stage = SteamChildStage.BigPictureStarted;
        }
        catch (Exception ex) { Failure = ex.Message; Stage = SteamChildStage.Conflict; throw; }
    }

    internal void RequestMinecraftDungeons(bool observationComplete, bool parentSteam,
        bool unrelatedSteam)
    {
        if (Stage != SteamChildStage.BigPictureStarted || steam == null || !steam.VerifyRunning())
            throw new InvalidOperationException("Verified child Steam is required before game launch.");
        if (!observationComplete || parentSteam || unrelatedSteam)
            throw new InvalidOperationException("Steam process ownership changed before the game request.");
        // Steam may hand this request to an existing singleton. A returned
        // steam.exe PID is not proof that the game started or belongs to child.
        Stage = SteamChildStage.GameRequested;
        try
        {
            ProductProcessIdentity request = host.Start(steamPath,
                "-applaunch " + SteamChildPolicy.MinecraftDungeonsAppId, Path.GetDirectoryName(steamPath));
            if (request == null || request.SessionId != (int)child.SessionId ||
                !String.Equals(Path.GetFullPath(request.ExecutablePath), steamPath, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(request.ExecutableSha256, steamDigest, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Steam launch request was not owned by the child session.");
        }
        catch (Exception ex) { Failure = ex.Message; Stage = SteamChildStage.Conflict; throw; }
    }

    internal void ObserveGame(ProductProcessIdentity observed)
    {
        if (Stage != SteamChildStage.GameRequested)
            throw new InvalidOperationException("No child game launch request is pending.");
        game = new ChildOwnedProcess(host, child, gamePath, gameDigest);
        try { game.Attach(observed); Stage = SteamChildStage.GameObserved; }
        catch (Exception ex) { game = null; Failure = ex.Message; Stage = SteamChildStage.Conflict; throw; }
    }

    internal void StopGame(int timeoutMs)
    {
        if (Stage != SteamChildStage.GameObserved || game == null)
            throw new InvalidOperationException("No exact owned child game was observed.");
        try { game.Stop(timeoutMs); Stage = SteamChildStage.GameEnded; }
        catch (Exception ex) { Failure = ex.Message; Stage = SteamChildStage.Conflict; throw; }
    }

    internal void StopSteam(int timeoutMs)
    {
        if (steam == null || (Stage != SteamChildStage.BigPictureStarted &&
            Stage != SteamChildStage.GameEnded))
            throw new InvalidOperationException("Steam cannot stop until the child game outcome is resolved.");
        try { steam.Stop(timeoutMs); Stage = SteamChildStage.Ended; }
        catch (Exception ex) { Failure = ex.Message; Stage = SteamChildStage.Conflict; throw; }
    }
}
