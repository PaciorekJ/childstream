using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.ServiceProcess;

internal enum CaptureBackend { DesktopDuplication, WindowsGraphicsCapture }

internal sealed class ChildProductOptions
{
    internal uint ParentSessionId;
    internal ChildSessionIdentity Child;
    internal string OwnedInstallationRoot, OwnedRoot, DisplayDeviceId, AudioEndpointId;
    internal bool DisplayActiveInChild, AudioEndpointVisibleInChild, ViGEmBusPresent;
    internal CaptureBackend Capture;
    internal int Port = 47989;
    internal string BindAddress = "127.0.0.1";
}

internal static class ChildProductConfiguration
{
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
        if (!option.AudioEndpointVisibleInChild)
            throw new InvalidDataException("The selected audio endpoint is not observed in the child session.");
        SafeValue(option.AudioEndpointId, "Child audio endpoint");
        if (option.BindAddress != "127.0.0.1")
            throw new InvalidDataException("Non-loopback streaming requires a separately validated LAN security posture.");
        if (option.Port != 47989)
            throw new InvalidDataException("Custom Sunshine port offsets and Moonlight compatibility are not validated.");
        string root = Path.GetFullPath(option.OwnedRoot).TrimEnd(Path.DirectorySeparatorChar);
        var config = new StringBuilder();
        Action<string, string> line = (key, value) => config.Append(key).Append(" = ").Append(value).Append('\n');
        line("sunshine_name", "ChildStream-child-" + option.Child.SessionId);
        line("address_family", "ipv4");
        line("bind_address", option.BindAddress);
        line("port", option.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        line("origin_web_ui_allowed", "pc");
        line("upnp", "disabled");
        line("install_steam_audio_drivers", "disabled");
        line("file_apps", SafePath(root, "apps.json"));
        line("credentials_file", SafePath(root, "sunshine_state.json"));
        line("file_state", SafePath(root, "sunshine_state.json"));
        line("log_path", SafePath(root, "sunshine.log"));
        line("pkey", SafePath(root, "sunshine.key"));
        line("cert", SafePath(root, "sunshine.cert"));
        line("output_name", "{" + displayGuid.ToString() + "}");
        line("dd_configuration_option", "verify_only");
        line("dd_resolution_option", "disabled");
        line("dd_refresh_rate_option", "disabled");
        line("capture", option.Capture == CaptureBackend.WindowsGraphicsCapture ? "wgc" : "ddx");
        line("encoder", "nvenc");
        line("audio_sink", option.AudioEndpointId);
        line("stream_audio", "enabled");
        line("controller", option.ViGEmBusPresent ? "enabled" : "disabled");
        line("gamepad_driver", "vigembus");
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
    { this.host = host; this.child = child; this.executable = Path.GetFullPath(executable); this.digest = digest; }

    private bool Same(ProductProcessIdentity actual)
    {
        return actual != null && actual.Pid == owned.Pid && actual.SessionId == (int)child.SessionId &&
            actual.StartTimeUtcTicks == owned.StartTimeUtcTicks &&
            String.Equals(Path.GetFullPath(actual.ExecutablePath), executable, StringComparison.OrdinalIgnoreCase) &&
            String.Equals(actual.ExecutableSha256, digest, StringComparison.OrdinalIgnoreCase);
    }

    internal void Start(string arguments)
    {
        if (owned != null) throw new InvalidOperationException("This child-owned process already has a start outcome.");
        if (host.CurrentSessionId != (int)child.SessionId || child.LogonTime <= 0)
            throw new InvalidOperationException("The process launcher is not running in the exact child session.");
        owned = host.Start(executable, arguments, Path.GetDirectoryName(executable));
        if (owned == null || !Same(owned))
        {
            Failure = "Started process identity or session did not match the approved child.";
            throw new InvalidOperationException(Failure);
        }
    }

    internal bool VerifyRunning()
    {
        if (owned == null) return false;
        try { return Same(host.Read(owned.Pid)); }
        catch { return false; }
    }

    internal void Stop(int gracefulTimeoutMs)
    {
        if (owned == null || gracefulTimeoutMs < 0 || gracefulTimeoutMs > 30000)
            throw new InvalidOperationException("No owned process or invalid shutdown timeout.");
        ProductProcessIdentity current = host.Read(owned.Pid);
        if (current == null) return; // Verified absent. Inaccessible remains an error.
        if (!Same(current)) throw new InvalidOperationException("Process identity changed; refusing to stop an unrelated process.");
        host.RequestClose(owned.Pid);
        if (host.WaitForExit(owned.Pid, gracefulTimeoutMs)) return;
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
}

internal static class WindowsSunshineCollisionReader
{
    // Read only. Each source has an independent completeness bit; an inaccessible
    // WMI provider cannot masquerade as an empty listener table.
    internal static SunshineCollisionSnapshot Read()
    {
        var result = new SunshineCollisionSnapshot();
        try
        {
            foreach (ServiceController service in ServiceController.GetServices())
            {
                using (service)
                    if (service.ServiceName.IndexOf("sunshine", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        service.DisplayName.IndexOf("sunshine", StringComparison.OrdinalIgnoreCase) >= 0)
                        result.ExistingSunshineService = true;
            }
            result.ServiceObservationComplete = true;
        }
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
                        " FROM " + query.Class)))
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

    internal static IList<SunshineListener> ReadListeners(out bool complete)
    {
        var listeners = new List<SunshineListener>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            scope.Connect();
            foreach (var query in new [] { new { Class = "MSFT_NetTCPConnection", Tcp = true },
                                           new { Class = "MSFT_NetUDPEndpoint", Tcp = false } })
                using (var searcher = new ManagementObjectSearcher(scope,
                    new ObjectQuery("SELECT LocalAddress, LocalPort, OwningProcess" +
                        (query.Tcp ? ", State" : "") + " FROM " + query.Class)))
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
