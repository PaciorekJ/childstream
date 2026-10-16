using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

internal static class ProductIntegrationTests
{
    public sealed class FakeRdpAudioSettings
    {
        private int mode;
        public bool IgnoreWrites;
        public int AudioRedirectionMode { get { return mode; } set { if (!IgnoreWrites) mode = value; } }
    }
    public sealed class FakeRdpAdvancedSettings
    {
        private bool capture;
        public bool IgnoreWrites;
        public bool AudioCaptureRedirectionMode
        { get { return capture; } set { if (!IgnoreWrites) capture = value; } }
    }
    public sealed class FakeRdpControl
    {
        public FakeRdpAudioSettings SecuredSettings2 = new FakeRdpAudioSettings();
        public FakeRdpAdvancedSettings AdvancedSettings7 = new FakeRdpAdvancedSettings();
    }
    private static int assertions;
    private static readonly string SunshineDigest = new string('a', 64);
    private static readonly string SteamDigest = new string('b', 64);
    private static readonly string GameDigest = new string('c', 64);
    private static void Check(bool truth, string label)
    { assertions++; if (!truth) throw new Exception(label); }
    private static void Reject(Action action, string label)
    { bool rejected = false; try { action(); } catch (InvalidDataException) { rejected = true; }
      catch (InvalidOperationException) { rejected = true; }
      catch (FileNotFoundException) { rejected = true; }
      Check(rejected, label); }

    private sealed class FakeProcesses : IProductProcessHost
    {
        internal ProductProcessIdentity Current;
        internal bool CloseCalled, KillCalled, Exit;
        internal string LastArguments;
        public int CurrentSessionId { get; set; }
        internal long? SessionLogonTime = 123;
        public long? ReadSessionLogonTime(int sessionId) { return SessionLogonTime; }
        public ProductProcessIdentity Read(int pid) { return Current; }
        public ProductProcessIdentity Start(string path, string args, string dir)
        { LastArguments = args; return Current; }
        public bool RequestClose(int pid) { CloseCalled = true; return true; }
        public bool WaitForExit(int pid, int ms) { return Exit; }
        public void Kill(int pid) { KillCalled = true; Exit = true; }
    }

    private sealed class FakeBootstrap : IChildBootstrapHost
    {
        internal ChildSessionIdentity? Associated = new ChildSessionIdentity(2, 123);
        internal long? Generation = 123;
        internal ProductProcessIdentity Agent;
        internal bool Requested, Exited, WrongHello;
        public ChildSessionIdentity? ReadAssociatedChild() { return Associated; }
        public long? ReadLogonTime(uint id) { return Generation; }
        public void RequestAgentInSession(ChildAgentRequest request) { Requested = true; }
        public ChildAgentHello WaitForAgent(ChildAgentRequest request, int timeoutMs)
        { return new ChildAgentHello { Nonce = WrongHello ? "wrong" : request.Nonce,
            Pid = Agent.Pid, Child = request.Child }; }
        public ProductProcessIdentity ReadAgent(int pid) { return Agent; }
        public void RequestAgentExit(int pid) { Exited = true; Agent = null; }
    }

    private static MemoryStream Archive(params string[] paths)
    {
        var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, true))
            foreach (string path in paths)
            { using (var writer = new StreamWriter(zip.CreateEntry(path).Open(), Encoding.UTF8)) writer.Write("bytes"); }
        stream.Position = 0;
        return stream;
    }

    private static void Configuration(string root)
    {
        string installed = Path.Combine(root, "ChildStream");
        var audio = new ChildAudioEndpointInventory { SessionId = 2, Complete = true,
            DefaultRenderId = "{audio-endpoint}" };
        audio.ActiveRenderIds.Add("{audio-endpoint}");
        var option = new ChildProductOptions { ParentSessionId = 1, Child = new ChildSessionIdentity(2, 123),
            OwnedInstallationRoot = installed, OwnedRoot = Path.Combine(installed, "sessions", "2-123"),
            DisplayDeviceId = Guid.NewGuid().ToString(),
            AudioEndpointId = "{audio-endpoint}", DisplayActiveInChild = true,
            AudioInventory = audio, Capture = CaptureBackend.WindowsGraphicsCapture };
        string config = ChildProductConfiguration.BuildSunshine(option);
        Check(config.Contains("bind_address = 127.0.0.1") && config.Contains("upnp = disabled") &&
            config.Contains("origin_web_ui_allowed = pc"), "loopback-only posture");
        Check(config.Contains("capture = wgc") && config.Contains("encoder = nvenc") &&
            config.Contains("dd_configuration_option = verify_only"), "explicit capture without display mutation");
        Check(config.Contains("controller = disabled") &&
            config.Contains("gamepad_driver = vigembus") &&
            config.Contains("keyboard = enabled") && config.Contains("mouse = enabled") &&
            config.Contains("install_steam_audio_drivers = disabled"), "free input driver and no automatic driver install");
        Check(config.Contains("audio_sink = {audio-endpoint}") &&
            config.Contains("stream_audio = disabled") && !config.Contains("virtual_sink ="),
            "pinned Sunshine audio stays off until default-switching and parent effects are excluded");
        var rdpAudio = new FakeRdpControl();
        rdpAudio.AdvancedSettings7.AudioCaptureRedirectionMode = true;
        ChildRdpAudioPolicy.Configure(rdpAudio);
        Check(rdpAudio.SecuredSettings2.AudioRedirectionMode == 2 &&
            !rdpAudio.AdvancedSettings7.AudioCaptureRedirectionMode,
            "production RDP policy suppresses unsafe playback and parent microphone redirection");
        var ignoredRdp = new FakeRdpControl(); ignoredRdp.SecuredSettings2.IgnoreWrites = true;
        Reject(() => ChildRdpAudioPolicy.Configure(ignoredRdp),
            "RDP control refusing child-side playback blocks connection");
        var ignoredMic = new FakeRdpControl(); ignoredMic.AdvancedSettings7.AudioCaptureRedirectionMode = true;
        ignoredMic.AdvancedSettings7.IgnoreWrites = true;
        Reject(() => ChildRdpAudioPolicy.Configure(ignoredMic),
            "RDP control refusing parent microphone isolation blocks connection");
        string discovery = WindowsChildRuntimeEnvironment.DiscoveryConfiguration(option.Child,
            Path.Combine(installed, "sessions", "2-123"));
        Check(discovery.Contains("controller = disabled") &&
            discovery.Contains("gamepad_driver = vigembus") &&
            discovery.Contains("keyboard = disabled") && discovery.Contains("mouse = disabled") &&
            discovery.Contains("stream_audio = disabled"),
            "temporary display discovery cannot accept client input or audio");
        Check(config.Contains("credentials_file = " + Path.Combine(installed, "identity", "credentials.json")) &&
            config.Contains("file_state = " + Path.Combine(installed, "identity", "sunshine_state.json")) &&
            config.Contains("pkey = " + Path.Combine(installed, "identity", "sunshine.key")),
            "stable ChildStream-owned identity across child generations");
        option.ViGEmBusPresent = true;
        Check(ChildProductConfiguration.BuildSunshine(option).Contains("controller = disabled"),
            "global ViGEmBus presence cannot enable child controller injection");
        option.BindAddress = "192.0.2.1";
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "LAN requires independent posture");
        option.BindAddress = "127.0.0.1"; option.Port = 47990;
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "native-overlapping loopback port offset blocked");
        option.BindAddress = "192.168.50.10"; option.Port = 48089;
        option.LanCandidate = new SunshineLanCandidate { Child = option.Child,
            BindAddress = option.BindAddress, Port = option.Port };
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "unapproved LAN candidate cannot bind wildcard");
        option.LanCandidate.BoundaryVerified = true;
        string lan = ChildProductConfiguration.BuildSunshine(option);
        Check(lan.Contains("bind_address = 0.0.0.0") && lan.Contains("port = 48089") &&
            lan.Contains("origin_web_ui_allowed = pc") && lan.Contains("upnp = disabled") &&
            lan.Contains("controller = disabled"), "scoped LAN candidate configuration, no input injection");
        option.LanCandidate.Child = new ChildSessionIdentity(3, 123);
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "another child cannot reuse LAN candidate");
        option.LanCandidate.Child = option.Child; option.LanCandidate.Port = 47990; option.Port = 47990;
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "overlapping native port family rejected");
        option.LanCandidate.Port = 48089; option.Port = 48089;
        option.LanCandidate.BindAddress = "0.0.0.0"; option.BindAddress = "0.0.0.0";
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "wildcard LAN bind rejected");
        option.LanCandidate = null; option.BindAddress = "127.0.0.1"; option.Port = 48089;
        option.AudioEndpointId = "bad\ninjection = enabled";
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "config injection blocked");
        option.AudioEndpointId = "{audio-endpoint}"; audio.Complete = false;
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "incomplete child audio inventory blocked");
        audio.Complete = true; audio.DefaultRenderId = "{other-endpoint}";
        Reject(() => ChildProductConfiguration.BuildSunshine(option),
            "audio capture sink without the child render default is rejected");
        audio.DefaultRenderId = "{audio-endpoint}";
        audio.SessionId = 1;
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "parent audio inventory cannot qualify child");
        audio.SessionId = 2; option.DisplayActiveInChild = false;
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "parent or inactive display rejected");
        option.DisplayActiveInChild = true; option.Child = new ChildSessionIdentity(1, 123);
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "parent session cannot be child");
        option.Child = new ChildSessionIdentity(2, 123);
        option.OwnedRoot = Path.Combine(root, "native-sunshine-config");
        Reject(() => ChildProductConfiguration.BuildSunshine(option), "native config path rejected");
    }

    private static void SunshineRecoveryRecords(string root)
    {
        string data = Path.Combine(root, "recovery-records", "ChildStream");
        var child = new ChildSessionIdentity(2, 123);
        string session = Path.Combine(data, "sessions", "2-123");
        Directory.CreateDirectory(session);
        var processes = new FakeProcesses { CurrentSessionId = 2 };
        string executable = Path.Combine(root, "fake-owned", "sunshine.exe");
        var environment = new WindowsChildRuntimeEnvironment(data, executable, processes);
        var exact = new ProductProcessIdentity { Pid = 120, SessionId = 2,
            StartTimeUtcTicks = 54321, ExecutablePath = executable,
            ExecutableSha256 = SunshineReleasePin.ExecutableSha256 };
        string configText = "bind_address = 127.0.0.1\noutput_name = {first}\n";
        string config = environment.EnsureGenerationFile(child,
            ChildGenerationConfiguration.RunName(configText), configText);
        environment.RecordStartIntent(child); environment.RecordStarted(child, exact, config);
        Check(environment.HasUnresolvedStartIntent(child),
            "production record store exposes interrupted start intent after restart");
        var loaded = environment.ReadStarted(child);
        Check(loaded.Pid == exact.Pid && loaded.StartTimeUtcTicks == exact.StartTimeUtcTicks &&
            loaded.ExecutableSha256 == exact.ExecutableSha256,
            "production durable record store reloads exact Sunshine identity from temporary files");
        Check(File.ReadAllText(Path.Combine(session, "started.record")).Contains(Path.GetFileName(config)),
            "durable Sunshine process record binds the immutable run configuration");
        File.AppendAllText(config, "external edit");
        Reject(() => environment.ReadStarted(child),
            "foreign edit of a recorded run config invalidates recovery identity");
        Check(File.ReadAllText(config).EndsWith("external edit"),
            "foreign configuration drift remains untouched for review");
        File.WriteAllText(config, configText);
        processes.Current = new ProductProcessIdentity { Pid = exact.Pid, SessionId = 2,
            StartTimeUtcTicks = 88888, ExecutablePath = executable,
            ExecutableSha256 = SunshineReleasePin.ExecutableSha256 };
        Reject(() => environment.ResolveFailedStart(child, exact),
            "reused PID blocks failed-start record reconciliation");
        processes.Current = null;
        environment.ResolveFailedStart(child, loaded);
        Check(!File.Exists(Path.Combine(session, "start.intent")) &&
            !File.Exists(Path.Combine(session, "started.record")),
            "verified absent exact failed start removes only its own intent and record");
        Check(!environment.HasUnresolvedStartIntent(child), "reconciled start no longer blocks a new launch");
        string nextText = "bind_address = 0.0.0.0\noutput_name = {second}\n";
        string partialConfig = Path.Combine(session, ChildGenerationConfiguration.RunName(nextText));
        File.WriteAllText(partialConfig, "interrupted write");
        Reject(() => environment.EnsureGenerationFile(child,
            ChildGenerationConfiguration.RunName(nextText), nextText),
            "interrupted per-run file cannot be adopted as a completed config");
        Check(File.ReadAllText(partialConfig) == "interrupted write",
            "incomplete config admission preserves its bytes for reviewed cleanup");
        environment.RecordStartIntent(child);
        File.WriteAllText(Path.Combine(session, "started.record"), "partial");
        Reject(() => environment.ReadStarted(child),
            "partial durable process record cannot become recovery authority");
        Reject(() => environment.ResolveFailedStart(child, exact),
            "partial record is preserved rather than silently deleted");
    }

    private static void SteamRecoveryRecords(string root)
    {
        string data = Path.Combine(root, "steam-recovery-records", "ChildStream");
        var child = new ChildSessionIdentity(2, 123);
        string session = Path.Combine(data, "sessions", "2-123");
        Directory.CreateDirectory(session);
        var environment = new WindowsChildRuntimeEnvironment(data,
            Path.Combine(root, "fake-owned", "sunshine.exe"),
            new FakeProcesses { CurrentSessionId = 2 });
        var steam = new ProductProcessIdentity { Pid = 130, SessionId = 2,
            StartTimeUtcTicks = 3000, ExecutablePath = Path.Combine(root, "Steam", "steam.exe"),
            ExecutableSha256 = SteamDigest };
        var game = new ProductProcessIdentity { Pid = 140, SessionId = 2,
            StartTimeUtcTicks = 4000, ExecutablePath = Path.Combine(root, "Game", "Dungeons.exe"),
            ExecutableSha256 = GameDigest };
        environment.VerifySteamRecoveryState(child, SteamChildStage.NotStarted, null, null);
        Check(true, "production no-Steam recovery requires no detached durable state");
        environment.RecordSteamIntent(child);
        environment.RecordSteamStarted(child, steam);
        environment.VerifySteamRecoveryState(child, SteamChildStage.BigPictureStarted, steam, null);
        Check(true, "production record store admits exact healthy Steam without game intent");
        Reject(() => environment.VerifySteamRecoveryState(child, SteamChildStage.NotStarted, null, null),
            "detached durable Steam record blocks Sunshine-only recovery");
        string steamRecord = Path.Combine(session, "steam.record");
        string savedSteam = File.ReadAllText(steamRecord);
        File.Delete(steamRecord);
        Reject(() => environment.VerifySteamRecoveryState(child, SteamChildStage.BigPictureStarted, steam, null),
            "missing production Steam record blocks recovery");
        File.WriteAllText(steamRecord, savedSteam);
        environment.RecordGameRequest(child);
        Reject(() => environment.VerifySteamRecoveryState(child, SteamChildStage.BigPictureStarted, steam, null),
            "pending durable game intent is not treated as no game");
        environment.RecordGameObserved(child, game);
        environment.VerifySteamRecoveryState(child, SteamChildStage.GameObserved, steam, game);
        Check(true, "production record store admits exact observed game alongside Steam");
        string gameRecord = Path.Combine(session, "game.record");
        string savedGame = File.ReadAllText(gameRecord);
        File.WriteAllText(gameRecord, "partial");
        Reject(() => environment.VerifySteamRecoveryState(child, SteamChildStage.GameObserved, steam, game),
            "corrupt production game record blocks recovery");
        File.WriteAllText(gameRecord, savedGame);
        var reused = new ProductProcessIdentity { Pid = game.Pid, SessionId = game.SessionId,
            StartTimeUtcTicks = game.StartTimeUtcTicks + 1, ExecutablePath = game.ExecutablePath,
            ExecutableSha256 = game.ExecutableSha256 };
        Reject(() => environment.VerifySteamRecoveryState(child, SteamChildStage.GameObserved, steam, reused),
            "reused game process identity differs from durable exact record");
        environment.RecordRuntimeUncertainty(child, "GameRequestUnknown");
        Reject(() => environment.VerifySteamRecoveryState(child, SteamChildStage.GameObserved, steam, game),
            "durable game uncertainty cannot be erased by Sunshine recovery");
        File.Delete(Path.Combine(session, "runtime.uncertain"));
        environment.ResolveSteamStopped(child, steam, game);
        environment.VerifySteamRecoveryState(child, SteamChildStage.NotStarted, null, null);
        Check(true, "exact resolved Steam/game files no longer obstruct streaming-only recovery");
    }

    private static void Processes(string root)
    {
        string path = Path.Combine(root, "sunshine.exe");
        var fake = new FakeProcesses { CurrentSessionId = 2,
            Current = new ProductProcessIdentity { Pid = 42, SessionId = 2, StartTimeUtcTicks = 123,
                ExecutablePath = path, ExecutableSha256 = SunshineDigest } };
        Reject(() => new ChildOwnedProcess(fake, new ChildSessionIdentity(2, 123), path, "hash"),
            "non-digest process pin rejected");
        var owned = new ChildOwnedProcess(fake, new ChildSessionIdentity(2, 123), path, SunshineDigest);
        owned.Start("config");
        Check(owned.VerifyRunning(), "owned child process verified");
        fake.Current = new ProductProcessIdentity { Pid = 42, SessionId = 1, StartTimeUtcTicks = 123,
            ExecutablePath = path, ExecutableSha256 = SunshineDigest };
        Check(!owned.VerifyRunning(), "session drift detected");
        Reject(() => owned.Stop(100), "unrelated process preserved");
        Check(!fake.KillCalled && !fake.CloseCalled, "no stop attempted on wrong session");
        fake.Current.SessionId = 2; fake.Current.StartTimeUtcTicks = 124;
        Reject(() => owned.Stop(100), "PID reuse preserved");
        fake.Current.StartTimeUtcTicks = 123;
        fake.SessionLogonTime = 124;
        Reject(() => owned.Stop(100), "child session generation drift preserves process");
        Check(!fake.KillCalled && !fake.CloseCalled, "generation drift caused no stop");
        fake.SessionLogonTime = 123;
        owned.Stop(100);
        Check(fake.CloseCalled && fake.KillCalled, "owned process graceful then bounded termination");
        fake.CurrentSessionId = 1;
        Reject(() => new ChildOwnedProcess(fake, new ChildSessionIdentity(2, 123), path, SunshineDigest).Start(""),
            "parent cannot launch child-owned process");
        fake.CurrentSessionId = 2; fake.SessionLogonTime = null;
        Reject(() => new ChildOwnedProcess(fake, new ChildSessionIdentity(2, 123), path, SunshineDigest).Start(""),
            "unobserved child generation cannot launch process");
    }

    private static void Archives()
    {
        using (var stream = Archive("Sunshine/sunshine.exe", "Sunshine/assets/icon.png"))
            Check(PortableSunshineArchive.ValidateManifest(stream).Count == 2, "expected lite archive layout");
        using (var stream = Archive("Sunshine/../escape", "Sunshine/sunshine.exe"))
            Reject(() => PortableSunshineArchive.ValidateManifest(stream), "traversal rejected");
        using (var stream = Archive("Sunshine/sunshine.exe", "Sunshine/SUNSHINE.EXE"))
            Reject(() => PortableSunshineArchive.ValidateManifest(stream), "case-insensitive duplicate rejected");
        using (var stream = Archive("unexpected.exe"))
            Reject(() => PortableSunshineArchive.ValidateManifest(stream), "archive rename rejected");
        using (var stream = Archive("Sunshine/assets/icon.png"))
            Reject(() => PortableSunshineArchive.ValidateManifest(stream), "missing executable rejected");
        using (var stream = Archive("Sunshine/sunshine.exe", "Sunshine/CON.txt"))
            Reject(() => PortableSunshineArchive.ValidateManifest(stream), "Windows device path rejected");
        using (var stream = Archive("Sunshine/sunshine.exe", "Sunshine/trailing. "))
            Reject(() => PortableSunshineArchive.ValidateManifest(stream), "ambiguous Windows trailing path rejected");
    }

    private static void PinnedArchive(string path)
    {
        string owned = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PinnedChildStream");
        var package = SunshineReleasePin.Create(Path.Combine(owned, "versions", SunshineReleasePin.Version),
            Path.Combine(owned, "config"));
        package.Validate(owned);
        using (var file = package.Admit(path, new PinnedSunshineReleaseVerifier()))
        {
            Check(PortableSunshineArchive.ValidateManifest(file).Count > 1, "real pinned archive layout");
            using (var zip = new ZipArchive(file, ZipArchiveMode.Read, true))
            using (var executable = zip.GetEntry("Sunshine/sunshine.exe").Open())
            using (var sha = SHA256.Create())
                Check(BitConverter.ToString(sha.ComputeHash(executable)).Replace("-", "").Equals(
                    SunshineReleasePin.ExecutableSha256, StringComparison.OrdinalIgnoreCase),
                    "real pinned executable digest");
        }
    }

    private static void Extraction(string root)
    {
        string installed = Path.Combine(root, "ChildStream");
        string version = Path.Combine(installed, "versions", "vtest");
        string config = Path.Combine(installed, "config");
        using (var stream = Archive("Sunshine/sunshine.exe", "Sunshine/assets/icon.png"))
        {
            string archiveHash, executableHash;
            using (var sha = SHA256.Create())
                archiveHash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            stream.Position = 0;
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Read, true))
            using (var input = zip.GetEntry("Sunshine/sunshine.exe").Open())
            using (var sha = SHA256.Create())
                executableHash = BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant();
            stream.Position = 0;
            var package = new PortableSunshinePackage { Version = "vtest",
                SourceUrl = "https://github.com/LizardByte/Sunshine/releases/download/vtest/sunshine.zip",
                Sha256 = archiveHash, ExecutableSha256 = executableHash,
                PortableRoot = version, ConfigRoot = config };
            package.Validate(installed);
            package.VerifyBytes(stream);
            stream.Position = 0;
            PortableSunshineArchive.ExtractIntoNewRoot(stream, version, package, null);
            Check(File.Exists(Path.Combine(version, "sunshine.exe")), "validated archive extracted into new owned root");
            stream.Position = 0;
            Reject(() => PortableSunshineArchive.ExtractIntoNewRoot(stream, version, package, null),
                "existing extraction root preserved");
        }
    }

    private static void ExtractionRecovery(string root)
    {
        string installed = Path.Combine(root, "recovery", "ChildStream");
        string version = Path.Combine(installed, "versions", "vtest");
        using (var stream = Archive("Sunshine/sunshine.exe", "Sunshine/assets/icon.png"))
        {
            string archiveHash, executableHash;
            using (var sha = SHA256.Create())
                archiveHash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            stream.Position = 0;
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Read, true))
            using (var input = zip.GetEntry("Sunshine/sunshine.exe").Open())
            using (var sha = SHA256.Create())
                executableHash = BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant();
            stream.Position = 0;
            var package = new PortableSunshinePackage { Version = "vtest",
                SourceUrl = "https://github.com/LizardByte/Sunshine/releases/download/vtest/sunshine.zip",
                Sha256 = archiveHash, ExecutableSha256 = executableHash, PortableRoot = version,
                ConfigRoot = Path.Combine(installed, "config") };
            var plan = PortableExtractionTransaction.Plan(stream, package, installed);
            Reject(() => PortableExtractionTransaction.Apply(stream, package, installed, "wrong", null),
                "unapproved extraction cannot mutate");
            Check(!Directory.Exists(version), "unapproved extraction root absent");
            PortableExtractionTransaction.Apply(stream, package, installed, plan.Hash, null);
            Check(File.Exists(Path.Combine(version, "sunshine.exe")), "journaled portable executable installed");
            PortableExtractionTransaction.Apply(stream, package, installed, plan.Hash, null);
            File.WriteAllText(Path.Combine(version, "assets", "icon.png"), "drift");
            Reject(() => PortableExtractionTransaction.Recover(version), "changed portable file is preserved");
            Check(File.Exists(Path.Combine(version, "sunshine.exe")), "conflict precedes deletion");
            File.Delete(Path.Combine(version, "assets", "icon.png"));
            PortableExtractionTransaction.Recover(version);
            Check(!Directory.Exists(version), "partial extraction fully recovered");
            PortableExtractionTransaction.Recover(version);
            PortableExtractionTransaction.Apply(stream, package, installed, plan.Hash, null);
            Check(File.Exists(Path.Combine(version, "sunshine.exe")), "reinstall after verified rollback");
            PortableExtractionTransaction.Recover(version);
            Check(!Directory.Exists(version), "reinstalled version rolled back again");
        }
    }

    private static void Conflicts()
    {
        var state = new SunshineCollisionSnapshot { ServiceObservationComplete = true,
            ProcessObservationComplete = true, PortObservationComplete = true };
        Check(SunshineStartupGate.Check(state) == null, "complete empty collision snapshot passes");
        state.ExistingSunshineService = true;
        Check(SunshineStartupGate.Check(state) != null, "native service preserved");
        state.ExistingSunshineService = false; state.UdpListeners.Add(48000);
        Check(SunshineStartupGate.Check(state) != null, "stream port collision");
        state.UdpListeners.Clear(); state.ExistingSunshineProcess = true;
        Check(SunshineStartupGate.Check(state) != null, "existing Sunshine process preserved");
        state.ExistingSunshineProcess = false; state.PortObservationComplete = false;
        Check(SunshineStartupGate.Check(state) != null, "incomplete listener inventory fails closed");
        state.PortObservationComplete = true; state.ExistingSunshineService = true;
        var candidate = new SunshineLanCandidate { Child = new ChildSessionIdentity(2, 123),
            BindAddress = "192.168.50.10", Port = 48089 };
        SunshinePortFamily family = candidate.Validate();
        Check(family.Tcp[0] == 48084 && family.Tcp[3] == 48110 &&
            family.Udp[0] == 48098 && family.Udp[3] == 48102,
            "published Sunshine port offsets applied to candidate");
        Check(SunshineStartupGate.CheckCandidate(state, candidate) == null,
            "native service does not occupy a distinct candidate port family");
        state.UdpListeners.Add(48099);
        Check(SunshineStartupGate.CheckCandidate(state, candidate) != null,
            "occupied candidate UDP port rejected with native service preserved");
        state.UdpListeners.Clear(); state.PortObservationComplete = false;
        Check(SunshineStartupGate.CheckCandidate(state, candidate) != null,
            "unknown candidate listener inventory fails closed");
        state.PortObservationComplete = true;
        var endpoints = new [] { new SunshineListener { Pid = 77, Protocol = "TCP",
            Port = 47990, LocalAddress = "127.0.0.1" } };
        Check(SunshineRuntimeGate.Check(true, 77, endpoints) == null, "owned loopback listener accepted");
        endpoints[0].LocalAddress = "0.0.0.0";
        Check(SunshineRuntimeGate.Check(true, 77, endpoints) != null, "unexpected LAN listener blocked");
        endpoints[0].LocalAddress = "127.0.0.1"; endpoints[0].Pid = 88;
        Check(SunshineRuntimeGate.Check(true, 77, endpoints) != null, "unexpected listener owner blocked");
        endpoints[0].Pid = 77; endpoints[0].Port = 50000;
        Check(SunshineRuntimeGate.Check(true, 77, endpoints) != null, "unexpected Sunshine port blocked");
        Check(SunshineRuntimeGate.Check(false, 77, endpoints) != null, "incomplete runtime listener snapshot blocked");
        endpoints[0].Port = 48089; endpoints[0].LocalAddress = "192.168.50.10";
        Check(SunshineRuntimeGate.CheckCandidate(true, 77, candidate.BindAddress, family, endpoints) == null,
            "exact owned candidate listener accepted");
        endpoints[0].LocalAddress = "0.0.0.0";
        Check(SunshineRuntimeGate.CheckCandidate(true, 77, candidate.BindAddress, family, endpoints) != null,
            "wildcard candidate bind rejected");
        endpoints[0].LocalAddress = candidate.BindAddress; endpoints[0].Pid = 88;
        Check(SunshineRuntimeGate.CheckCandidate(true, 77, candidate.BindAddress, family, endpoints) != null,
            "another process cannot own candidate family");
        Check(SteamChildPolicy.Check(true, true, false, false) != null, "parent Steam conflict");
        Check(SteamChildPolicy.Check(false, false, false, false) != null, "Steam unknown fails closed");
        Check(SteamChildPolicy.Check(true, false, false, false) == null, "known empty Steam state");
    }

    private static void OwnedFileTransaction(string root)
    {
        root = Path.Combine(root, "owned-files", "ChildStream");
        Directory.CreateDirectory(root);
        string file = Path.Combine(root, "installed", "candidate.txt");
        string journal = Path.Combine(root, "candidate.journal");
        const string owner = "childstream-product-test";
        var host = new WindowsOwnedInstallerHost(root, journal);
        var engine = new InstallerEngine(host, new FileJournalStore(journal), new InstallerPolicy(root),
            new FileTransactionOwnership(Path.Combine(root, "candidate.lock")));
        var operation = new InstallOperation { Target = new ResourceTarget(ResourceKind.OwnedFile, file),
            Desired = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "FileBytes",
                Data = Encoding.UTF8.GetBytes("candidate"), Owner = owner },
            Privilege = InstallPrivilege.CurrentUser, OwnershipEvidence = owner,
            Verification = "Exact owned bytes", Reversal = "Remove only exact owned file" };
        var plan = engine.Plan(new [] { operation });
        Check(engine.Apply(plan, plan.Hash).Phase == JournalPhase.Complete, "real owned file created transactionally");
        Check(File.ReadAllText(file) == "candidate", "installed bytes on disk");
        Check(engine.Apply(plan, plan.Hash).Phase == JournalPhase.Complete, "real owned file idempotent");
        File.WriteAllText(file, "outside-change");
        Reject(() => engine.RecoverOrUninstall(), "external file drift blocks deletion");
        Check(File.ReadAllText(file) == "outside-change", "drifted file preserved");
        File.WriteAllText(file, "candidate");
        Check(engine.RecoverOrUninstall().Phase == JournalPhase.RolledBack, "exact owned file rolled back");
        Check(!File.Exists(file), "rollback removed only the owned file");
        Check(engine.RecoverOrUninstall().Phase == JournalPhase.RolledBack, "rollback idempotent");
        string unrelated = Path.Combine(root, "installed", "unrelated.txt");
        File.WriteAllText(unrelated, "preserve");
        Check(File.ReadAllText(unrelated) == "preserve", "unrelated sibling preserved");
    }

    private static void ProductInstallation(string fixture)
    {
        string root = Path.Combine(fixture, "bootstrap", "ChildStream");
        string journal = Path.Combine(root, "install.journal");
        var host = new WindowsOwnedInstallerHost(root, journal);
        var engine = new InstallerEngine(host, new FileJournalStore(journal), new InstallerPolicy(root),
            new FileTransactionOwnership(Path.Combine(root, "install.lock")));
        var payload = new ProductInstallPayload();
        foreach (string name in ProductInstallPayload.InstalledFiles)
            payload.Files.Add(name, Encoding.UTF8.GetBytes("reviewed:" + name));
        using (var archive = Archive("Sunshine/sunshine.exe", "Sunshine/assets/icon.png"))
        using (var sha = SHA256.Create())
        {
            string archiveHash = ProductInstallPayload.Hex(sha.ComputeHash(archive));
            archive.Position = 0;
            string exeHash;
            using (var zip = new ZipArchive(archive, ZipArchiveMode.Read, true))
            using (var input = zip.GetEntry("Sunshine/sunshine.exe").Open())
                exeHash = ProductInstallPayload.Hex(sha.ComputeHash(input));
            archive.Position = 0;
            var package = new PortableSunshinePackage { Version = SunshineReleasePin.Version,
                SourceUrl = SunshineReleasePin.AssetUrl, Sha256 = archiveHash, ExecutableSha256 = exeHash,
                PortableRoot = Path.Combine(root, "versions", SunshineReleasePin.Version),
                ConfigRoot = Path.Combine(root, "identity") };
            var install = new ProductInstallCoordinator(engine, root, InstallPrivilege.CurrentUser, package);
            var plan = install.Plan(payload, archive);
            Check(!Directory.Exists(root), "read-only install plan creates no lock, journal or installation root");
            Reject(() => install.Apply(plan, payload, archive, "wrong"), "unapproved combined plan cannot install");
            Check(!File.Exists(Path.Combine(root, "ChildStream.exe")), "unapproved bootstrap made no file");
            install.Apply(plan, payload, archive, plan.Hash);
            Check(File.Exists(Path.Combine(root, "ChildStream.exe")) &&
                File.Exists(Path.Combine(root, "versions", SunshineReleasePin.Version, "sunshine.exe")),
                "combined owned binary and portable runtime installed");
            install.Apply(plan, payload, archive, plan.Hash);
            var committed = install.PlanCommitted(payload, archive, new FileJournalStore(journal).Load());
            Check(committed.Hash == plan.Hash, "reviewed repair retains exact committed plan");
            install.Apply(committed, payload, archive, committed.Hash);
            string missingOwned = Path.Combine(root, "ChildStreamSetup.exe");
            File.Delete(missingOwned);
            Reject(() => install.Apply(committed, payload, archive, committed.Hash),
                "verify-only repair refuses to call a missing owned file intact");
            install.RecoverOrUninstall();
            Check(!File.Exists(Path.Combine(root, "ChildStream.exe")) &&
                !Directory.Exists(Path.Combine(root, "versions", SunshineReleasePin.Version)),
                "reviewed recovery reverses exact remaining owned files after one owned file vanished");
            archive.Position = 0;
            var renewed = install.Plan(payload, archive);
            install.Apply(renewed, payload, archive, renewed.Hash);
            Check(File.Exists(missingOwned) && File.Exists(Path.Combine(root, "ChildStream.exe")),
                "new reviewed plan reinstalls missing owned payload without overwriting foreign bytes");
            string foreign = Path.Combine(root, "native-preserve.txt");
            File.WriteAllText(foreign, "untouched");
            string portable = Path.Combine(root, "versions", SunshineReleasePin.Version, "sunshine.exe");
            File.WriteAllText(portable, "foreign drift");
            Reject(() => install.RecoverOrUninstall(), "portable drift blocks all file deletion");
            Check(File.Exists(Path.Combine(root, "ChildStream.exe")), "small files preserved until portable recovery");
            archive.Position = 0;
            using (var zip = new ZipArchive(archive, ZipArchiveMode.Read, true))
            using (var input = zip.GetEntry("Sunshine/sunshine.exe").Open())
            using (var output = new MemoryStream())
            { input.CopyTo(output); File.WriteAllBytes(portable, output.ToArray()); }
            install.RecoverOrUninstall();
            Check(!File.Exists(Path.Combine(root, "ChildStream.exe")) &&
                !Directory.Exists(Path.Combine(root, "versions", SunshineReleasePin.Version)) &&
                File.ReadAllText(foreign) == "untouched", "exact rollback preserves unrelated sibling");
            install.RecoverOrUninstall();
            Check(File.ReadAllText(foreign) == "untouched", "repeated rollback idempotent");
        }
        string candidate = Path.Combine(fixture, "candidate-fixture.zip");
        using (var output = new FileStream(candidate, FileMode.CreateNew, FileAccess.Write))
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create))
            foreach (string name in ProductInstallPayload.InstalledFiles)
            using (var writer = new StreamWriter(zip.CreateEntry(name).Open())) writer.Write("reviewed:" + name);
        string digest;
        using (var sha = SHA256.Create())
        using (var input = File.OpenRead(candidate)) digest = ProductInstallPayload.Hex(sha.ComputeHash(input));
        Reject(() => ProductInstallPayload.ReadCandidate(candidate, new string('0', 64)),
            "candidate self-description cannot replace reviewed outer digest");
        Check(ProductInstallPayload.ReadCandidate(candidate, digest).Files.Count == 5,
            "exact reviewed candidate payload admitted");
        string reacquired = Path.Combine(fixture, "reacquired", "candidate.zip");
        Directory.CreateDirectory(Path.Combine(fixture, "reacquired", "bin"));
        File.Copy(candidate, reacquired);
        File.WriteAllText(Path.Combine(fixture, "reacquired", "bin", "ChildStreamBootstrap.exe"),
            "reviewed:bin/ChildStreamBootstrap.exe");
        File.Delete(candidate);
        Check(ProductInstallPayload.ReadCandidate(reacquired, digest).Files.Count == 5 &&
            WindowsProductInstallWorkflow.SelectBootstrapPath(root, reacquired, root, true) ==
                Path.Combine(fixture, "reacquired", "bin", "ChildStreamBootstrap.exe"),
            "installed-app maintenance accepts a reacquired identical candidate and external bootstrap after original download is gone");
        File.Delete(Path.Combine(fixture, "reacquired", "bin", "ChildStreamBootstrap.exe"));
        Reject(() => WindowsProductInstallWorkflow.SelectBootstrapPath(root, reacquired, root, true),
            "installed bootstrap cannot be mistaken for safe external self-uninstall helper");
    }

    private static void Acceptance()
    {
        var child = new ChildSessionIdentity(2, 123);
        var missing = ProductAcceptance.Evaluate(child, null);
        Check(!ProductAcceptance.Complete(missing), "unmeasured hardware cannot pass acceptance");
        var evidence = new PhysicalProductEvidence {
            IndependentParentAndChildInput = true, ChildDisplayActive = true,
            ParentDisplayUnchanged = true, ParentDisplayId = "parent", ChildDisplayId = "child",
            SunshineCaptureDisplayId = "parent", SunshineSessionId = 2, EncoderObserved = "software",
            MoonlightWidth = 1920, MoonlightHeight = 1080, MoonlightFps = 60,
            SustainedStreamStable = true, ParentForegroundGamepadWorks = false,
            ParentUnaffectedByGamepad = true, TwoControllersDistinct = true,
            ChildAudioOnTv = true, ParentAudioOnPc = true, AudioIsolated = true,
            SteamBigPictureInChild = true, MinecraftDungeonsPlayedInChild = true,
            ExactChildTeardown = true, OriginalSettingsRestored = true };
        var rows = ProductAcceptance.Evaluate(child, evidence);
        Check(!ProductAcceptance.Complete(rows), "parent capture, software encoder and focus failure reject");
        evidence.SunshineCaptureDisplayId = "child"; evidence.EncoderObserved = "nvenc";
        evidence.ParentForegroundGamepadWorks = true;
        Check(ProductAcceptance.Complete(ProductAcceptance.Evaluate(child, evidence)),
            "fully populated physical-evidence model satisfies deterministic gates only");
    }

    private static void Steam(string root)
    {
        string steamPath = Path.Combine(root, "steam.exe");
        string gamePath = Path.Combine(root, "game.exe");
        var fake = new FakeProcesses { CurrentSessionId = 2,
            Current = new ProductProcessIdentity { Pid = 21, SessionId = 2,
                StartTimeUtcTicks = 10, ExecutablePath = steamPath, ExecutableSha256 = SteamDigest } };
        var runtime = new SteamChildRuntime(fake, new ChildSessionIdentity(2, 123),
            steamPath, SteamDigest, gamePath, GameDigest);
        Reject(() => runtime.StartBigPicture(true, true, false, false), "parent Steam preserved");
        runtime.StartBigPicture(true, false, false, false);
        Check(runtime.Stage == SteamChildStage.BigPictureStarted && fake.LastArguments == "-bigpicture",
            "Steam Big Picture starts only in observed child");
        Reject(() => runtime.RequestMinecraftDungeons(false, false, false), "unknown Steam ownership blocks game request");
        runtime.RequestMinecraftDungeons(true, false, false);
        Check(runtime.Stage == SteamChildStage.GameRequested &&
            fake.LastArguments == "-applaunch 1672970", "game launch request uses exact app ID");
        Reject(() => runtime.StopGame(100), "request is not game process evidence");
        fake.Current = new ProductProcessIdentity { Pid = 31, SessionId = 1,
            StartTimeUtcTicks = 11, ExecutablePath = gamePath, ExecutableSha256 = GameDigest };
        Reject(() => runtime.ObserveGame(fake.Current), "parent game cannot be attached");
        Check(runtime.Stage == SteamChildStage.Conflict, "wrong-session game ends in conflict");
        fake.Current = new ProductProcessIdentity { Pid = 22, SessionId = 2,
            StartTimeUtcTicks = 12, ExecutablePath = steamPath, ExecutableSha256 = SteamDigest };
        runtime = new SteamChildRuntime(fake, new ChildSessionIdentity(2, 123),
            steamPath, SteamDigest, gamePath, GameDigest);
        runtime.StartBigPicture(true, false, false, false);
        runtime.RequestMinecraftDungeons(true, false, false);
        fake.Current = new ProductProcessIdentity { Pid = 32, SessionId = 2,
            StartTimeUtcTicks = 13, ExecutablePath = gamePath, ExecutableSha256 = GameDigest };
        runtime.ObserveGame(fake.Current);
        Check(runtime.Stage == SteamChildStage.GameObserved, "exact child game observed");
        Reject(() => runtime.StopSteam(100), "Steam cannot stop before running game");
        runtime.StopGame(100);
        Check(fake.CloseCalled && fake.KillCalled && runtime.Stage == SteamChildStage.GameEnded,
            "only observed child game stopped");
        fake.Current = new ProductProcessIdentity { Pid = 22, SessionId = 2,
            StartTimeUtcTicks = 12, ExecutablePath = steamPath, ExecutableSha256 = SteamDigest };
        runtime.StopSteam(100);
        Check(runtime.Stage == SteamChildStage.Ended, "verified child Steam stopped after game");
    }

    private static void ChildBootstrap(string root)
    {
        string path = Path.Combine(root, "ChildStream.exe");
        var child = new ChildSessionIdentity(2, 123);
        var request = new ChildAgentRequest { ParentSessionId = 1, Child = child,
            PipeName = "ChildStream-" + new string('a', 32), Nonce = new string('d', 64),
            ParentPid = 17, ParentExecutableSha256 = SunshineDigest, RequesterSid = "S-1-5-21-100" };
        Check(ChildAgentRequest.Decode(request.Encode()).Child.Equals(child), "agent request round trip");
        var fake = new FakeBootstrap { Agent = new ProductProcessIdentity { Pid = 42, SessionId = 2,
            StartTimeUtcTicks = 12, ExecutablePath = path, ExecutableSha256 = SunshineDigest } };
        var controller = new ChildAgentController(fake, 1, child, path, SunshineDigest);
        controller.Start(request);
        Check(fake.Requested && controller.Stage == ChildAgentStage.Ready && controller.Reconcile(),
            "exact child agent handshake and process accepted");
        controller.Stop();
        Check(fake.Exited && controller.Stage == ChildAgentStage.Ended, "exact agent exit verified");
        fake = new FakeBootstrap { Agent = new ProductProcessIdentity { Pid = 42, SessionId = 2,
            StartTimeUtcTicks = 12, ExecutablePath = path, ExecutableSha256 = SunshineDigest } };
        controller = new ChildAgentController(fake, 1, child, path, SunshineDigest);
        controller.Start(request);
        fake.Generation = 124;
        Reject(() => controller.Stop(), "generation drift blocks agent shutdown");
        Check(!fake.Exited && controller.Stage == ChildAgentStage.Uncertain,
            "generation drift preserved agent for reviewed recovery");
        fake = new FakeBootstrap { Generation = null, Agent = new ProductProcessIdentity { Pid = 42,
            SessionId = 2, StartTimeUtcTicks = 12, ExecutablePath = path,
            ExecutableSha256 = SunshineDigest } };
        controller = new ChildAgentController(fake, 1, child, path, SunshineDigest);
        Reject(() => controller.Start(request), "unknown child generation prevents launch request");
        Check(!fake.Requested, "no scheduler action after unknown generation");
        fake.Generation = 123; fake.WrongHello = true;
        Reject(() => controller.Start(request), "wrong agent handshake rejected");
        Check(controller.Stage == ChildAgentStage.Uncertain, "ambiguous task start remains uncertain");
        Reject(() => controller.Start(request), "uncertain task start cannot be repeated");
        request.PipeName = "unowned-pipe";
        Reject(() => request.Encode(), "unowned pipe name rejected");
    }

    internal static int Main(string[] args)
    {
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "product-fixtures-" + Guid.NewGuid().ToString("N"));
        try
        {
            Configuration(root); Processes(root); Archives(); Extraction(root); ExtractionRecovery(root);
            Conflicts(); OwnedFileTransaction(root); ProductInstallation(root);
            SunshineRecoveryRecords(root); SteamRecoveryRecords(root);
            Acceptance(); Steam(root); ChildBootstrap(root);
            if (args.Length == 1) PinnedArchive(args[0]);
            Console.WriteLine("Product integration offline assertions passed: " + assertions);
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
