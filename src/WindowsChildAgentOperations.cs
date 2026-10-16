using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

internal sealed class WindowsChildAgentOperations : IChildAgentOperations
{
    private readonly ChildAgentRuntime runtime;
    internal WindowsChildAgentOperations(ChildAgentRequest request)
    {
        request.Validate();
        runtime = new ChildAgentRuntime(request.Child, request.ParentSessionId,
            new WindowsChildRuntimeEnvironment());
    }
    public string Execute(ChildAgentOperation operation, string payload)
    { return runtime.Execute(operation, payload); }
    public void Dispose() { runtime.Dispose(); }
}

internal sealed class WindowsChildRuntimeEnvironment : IChildRuntimeEnvironment
{
    private readonly WindowsProductProcessHost processes = new WindowsProductProcessHost();
    private readonly string root;
    private readonly string sunshine;
    internal WindowsChildRuntimeEnvironment()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!Path.IsPathRooted(local)) throw new InvalidOperationException("ChildStream user data location is unavailable.");
        root = Path.Combine(local, "ChildStream");
        sunshine = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "versions", SunshineReleasePin.Version, "sunshine.exe");
    }
    public IProductProcessHost Processes { get { return processes; } }
    public string SunshineExecutable
    {
        get
        {
            if (!File.Exists(sunshine)) throw new FileNotFoundException("ChildStream-owned portable Sunshine is not installed.", sunshine);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string trustedRoot = Path.Combine(programFiles, "ChildStream") + Path.DirectorySeparatorChar;
            if (!Path.GetFullPath(sunshine).StartsWith(trustedRoot, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Portable Sunshine binary is outside the protected ChildStream installation.");
            using (var stream = new FileStream(sunshine, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
            {
                string actual = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
                if (!String.Equals(actual, SunshineReleasePin.ExecutableSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("ChildStream portable Sunshine executable digest changed.");
            }
            return sunshine;
        }
    }
    public string DataRoot { get { return root; } }
    public string UserSid { get { return WindowsIdentity.GetCurrent().User.Value; } }
    public ProcessTokenObservation ReadToken(int pid) { return WindowsProcessToken.Read(pid); }
    public ChildAudioEndpointInventory ReadAudio(ChildSessionIdentity child)
    { return WindowsAudioEndpoints.ReadActiveRender((int)child.SessionId); }
    public SunshineCollisionSnapshot ReadCollision(SunshinePortFamily family)
    { return WindowsSunshineCollisionReader.Read(family); }
    public bool VerifyLanBoundary(string address, SunshinePortFamily family)
    {
        string installed = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar);
        string expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ChildStream");
        if (!String.Equals(installed, expected, StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            SetupInstallTrust.VerifyProtectedAcl(Directory.GetAccessControl(installed));
            string ownedSunshine = SetupInstallTrust.RequireOwnedSunshine();
            string journal = Path.Combine(installed, "lan-firewall.journal");
            SetupInstallTrust.VerifyProtectedAcl(File.GetAccessControl(journal));
            return new LanFirewallTransaction(new WindowsLanFirewallHost(), installed,
                ownedSunshine, family).Verify(address);
        }
        catch (Exception) { return false; }
    }
    public IList<SunshineListener> ReadListeners(int pid, SunshinePortFamily family, out bool complete)
    { return WindowsSunshineCollisionReader.ReadListeners(pid, family, out complete); }
    public IChildSunshineIdentity OpenIdentity() { return new SunshineIdentityStore(root); }
    public IChildSunshineTransport CreatePairingTransport(Uri endpoint, string certificateSha256,
        SunshineAdminCredential credential, IVerifiedChildSunshine owner)
    { return new PinnedSunshinePairingTransport(endpoint, certificateSha256,
        credential.UserName, credential.Password, owner); }
    private string SessionRoot(ChildSessionIdentity child)
    {
        string path = Path.Combine(root, "sessions", child.SessionId + "-" + child.LogonTime);
        InstallerPolicy.ValidateCanonicalFilePath(path, true);
        return path;
    }
    public string EnsureGenerationFile(ChildSessionIdentity child, string name, string content)
    {
        if (name != "apps.json" && name != "sunshine.conf" && name != "sunshine-discovery.conf")
            throw new InvalidOperationException("Child generation file is outside the fixed allowlist.");
        string path = Path.Combine(SessionRoot(child), name);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        byte[] desired = new UTF8Encoding(false).GetBytes(content);
        if (File.Exists(path))
        {
            byte[] existing = File.ReadAllBytes(path);
            if (existing.Length != desired.Length) throw new InvalidOperationException("Child generation configuration drifted.");
            for (int i = 0; i < desired.Length; i++)
                if (existing[i] != desired[i]) throw new InvalidOperationException("Child generation configuration drifted.");
            return path;
        }
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { stream.Write(desired, 0, desired.Length); stream.Flush(true); }
        return path;
    }
    private static string DiscoveryConfiguration(ChildSessionIdentity child, string session)
    {
        Action<StringBuilder, string, string> add = (buffer, key, value) => buffer.Append(key).Append(" = ").Append(value).Append('\n');
        var text = new StringBuilder();
        add(text, "sunshine_name", "ChildStream-discovery");
        add(text, "address_family", "ipv4");
        add(text, "bind_address", "127.0.0.1");
        add(text, "port", "48089");
        add(text, "origin_web_ui_allowed", "pc");
        add(text, "upnp", "disabled");
        add(text, "controller", "disabled");
        add(text, "stream_audio", "disabled");
        add(text, "install_steam_audio_drivers", "disabled");
        add(text, "dd_configuration_option", "disabled");
        add(text, "file_apps", Path.Combine(session, "apps.json"));
        add(text, "credentials_file", Path.Combine(session, "discovery-credentials.json"));
        add(text, "file_state", Path.Combine(session, "discovery-state.json"));
        add(text, "pkey", Path.Combine(session, "discovery.key"));
        add(text, "cert", Path.Combine(session, "discovery.cert"));
        add(text, "log_path", Path.Combine(session, "sunshine-discovery.log"));
        return text.ToString();
    }
    public string DiscoverDisplayLog(ChildSessionIdentity child)
    {
        SunshinePortFamily family = new SunshinePortFamily(48089);
        string conflict = SunshineStartupGate.CheckFamilyAvailable(ReadCollision(family), family);
        if (conflict != null) throw new InvalidOperationException(conflict);
        string session = SessionRoot(child);
        EnsureGenerationFile(child, "apps.json", ChildProductConfiguration.BuildApps());
        string config = EnsureGenerationFile(child, "sunshine-discovery.conf", DiscoveryConfiguration(child, session));
        string logPath = Path.Combine(session, "sunshine-discovery.log");
        DateTime started = DateTime.UtcNow;
        var discovery = new ChildOwnedProcess(processes, child, SunshineExecutable, SunshineReleasePin.ExecutableSha256);
        string intent = StateFile(child, "discovery.intent"), record = StateFile(child, "discovery.record");
        CreateDurable(intent, ChildText(child));
        try
        {
            discovery.Start("\"" + config + "\"");
            CreateDurable(record, RecordText(child, discovery.Identity));
            for (int i = 0; i < 100; i++)
            {
                if (!discovery.VerifyRunning()) throw new InvalidOperationException("Owned Sunshine discovery process exited.");
                if (File.Exists(logPath) && File.GetLastWriteTimeUtc(logPath) >= started)
                {
                    string log = File.ReadAllText(logPath);
                    try { SunshineDisplayCatalog.ParseOwnedLog(log); return log; }
                    catch (InvalidDataException) { }
                }
                Thread.Sleep(100);
            }
            throw new TimeoutException("Owned Sunshine did not report its child-session display catalog.");
        }
        finally
        {
            if (discovery.Identity != null)
            {
                discovery.Stop(5000); // Exact PID, generation, image and start time only.
                if (processes.Read(discovery.Identity.Pid) != null ||
                    File.ReadAllText(record) != RecordText(child, discovery.Identity) ||
                    File.ReadAllText(intent) != ChildText(child))
                    throw new InvalidOperationException("Sunshine display discovery stop could not be reconciled.");
                File.Delete(record); File.Delete(intent);
            }
        }
    }
    private static string RecordText(ChildSessionIdentity child, ProductProcessIdentity process)
    {
        return child.SessionId + "|" + child.LogonTime + "|" + process.Pid + "|" +
            process.StartTimeUtcTicks + "|" + process.ExecutableSha256;
    }
    public void RecordStartIntent(ChildSessionIdentity child)
    {
        string file = Path.Combine(SessionRoot(child), "start.intent");
        InstallerPolicy.ValidateCanonicalFilePath(file);
        byte[] bytes = Encoding.ASCII.GetBytes(child.SessionId + "|" + child.LogonTime);
        using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
    }
    public void RecordStarted(ChildSessionIdentity child, ProductProcessIdentity process)
    {
        string file = Path.Combine(SessionRoot(child), "started.record");
        InstallerPolicy.ValidateCanonicalFilePath(file);
        byte[] bytes = Encoding.ASCII.GetBytes(RecordText(child, process));
        using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
    }
    public void ResolveStopped(ChildSessionIdentity child, ProductProcessIdentity process)
    {
        string session = SessionRoot(child);
        string record = Path.Combine(session, "started.record"), intent = Path.Combine(session, "start.intent");
        if (processes.Read(process.Pid) != null ||
            File.ReadAllText(record) != RecordText(child, process) ||
            File.ReadAllText(intent) != child.SessionId + "|" + child.LogonTime)
            throw new InvalidOperationException("Owned Sunshine stop record or process state changed.");
        File.Delete(record); File.Delete(intent);
    }
    public SteamInstallation ReadSteamInstallation()
    { return WindowsSteamDiscovery.ReadInstallation(); }
    public SteamLaunchObservation ReadSteamObservation(ChildSessionIdentity child, uint parentSessionId)
    { return WindowsSteamDiscovery.ReadSteamProcesses(processes, child, parentSessionId); }
    public ProductProcessIdentity ReadGameProcess(ChildSessionIdentity child, SteamInstallation installation)
    { return WindowsSteamDiscovery.ReadExactGame(processes, child, installation); }
    private static string ChildText(ChildSessionIdentity child)
    { return child.SessionId + "|" + child.LogonTime; }
    private string StateFile(ChildSessionIdentity child, string name)
    {
        if (name != "steam.intent" && name != "steam.record" && name != "game.intent" &&
            name != "discovery.intent" && name != "discovery.record" &&
            name != "game.record" && name != "runtime.uncertain")
            throw new InvalidOperationException("Unrecognized child runtime state file.");
        string path = Path.Combine(SessionRoot(child), name);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        return path;
    }
    private static void CreateDurable(string path, string content)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
    }
    public void RecordSteamIntent(ChildSessionIdentity child)
    { CreateDurable(StateFile(child, "steam.intent"), ChildText(child)); }
    public void RecordSteamStarted(ChildSessionIdentity child, ProductProcessIdentity process)
    {
        if (File.ReadAllText(StateFile(child, "steam.intent")) != ChildText(child))
            throw new InvalidOperationException("Steam start intent changed.");
        CreateDurable(StateFile(child, "steam.record"), RecordText(child, process));
    }
    public void RecordGameRequest(ChildSessionIdentity child)
    {
        if (!File.Exists(StateFile(child, "steam.record")))
            throw new InvalidOperationException("Verified Steam start record is missing.");
        CreateDurable(StateFile(child, "game.intent"), ChildText(child));
    }
    public void RecordGameObserved(ChildSessionIdentity child, ProductProcessIdentity process)
    {
        if (File.ReadAllText(StateFile(child, "game.intent")) != ChildText(child))
            throw new InvalidOperationException("Game request intent changed.");
        CreateDurable(StateFile(child, "game.record"), RecordText(child, process));
    }
    public void ResolveSteamStopped(ChildSessionIdentity child, ProductProcessIdentity steam,
        ProductProcessIdentity game)
    {
        if (steam == null || processes.Read(steam.Pid) != null ||
            File.ReadAllText(StateFile(child, "steam.record")) != RecordText(child, steam) ||
            File.ReadAllText(StateFile(child, "steam.intent")) != ChildText(child))
            throw new InvalidOperationException("Exact stopped Steam identity could not be reconciled.");
        string gameIntent = StateFile(child, "game.intent"), gameRecord = StateFile(child, "game.record");
        if (File.Exists(gameIntent))
        {
            if (game == null || processes.Read(game.Pid) != null ||
                File.ReadAllText(gameIntent) != ChildText(child) ||
                File.ReadAllText(gameRecord) != RecordText(child, game))
                throw new InvalidOperationException("Game request outcome could not be reconciled.");
            File.Delete(gameRecord); File.Delete(gameIntent);
        }
        File.Delete(StateFile(child, "steam.record")); File.Delete(StateFile(child, "steam.intent"));
    }
    public void RecordRuntimeUncertainty(ChildSessionIdentity child, string reason)
    {
        if (reason != "SteamStartUnknown" && reason != "GameRequestUnknown" &&
            reason != "SteamStopUnknown" && reason != "AgentExitWithSteamUnknown")
            throw new InvalidOperationException("Unrecognized runtime uncertainty.");
        string path = StateFile(child, "runtime.uncertain");
        if (!File.Exists(path)) CreateDurable(path, ChildText(child) + "|" + reason);
    }
}
