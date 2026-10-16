using System;
using System.Collections.Generic;
using System.IO;

static class IntegratedRuntimeTests
{
    private sealed class ManualMonitor : IRuntimeMonitor
    {
        internal Action Tick;
        internal int Starts, Stops;
        public void Start(Action tick) { Tick = tick; Starts++; }
        public void Stop() { Tick = null; Stops++; }
        public void Dispose() { Stop(); }
        internal void Fire() { Action action = Tick; if (action != null) action(); }
    }
    private const string Digest = SunshineReleasePin.ExecutableSha256;
    private sealed class ProcessHost : IProductProcessHost
    {
        internal ProductProcessIdentity Current;
        internal ProductProcessIdentity SteamCurrent, GameCurrent;
        internal int Starts, Stops, UnrelatedTouched;
        internal int SteamStarts, SteamStops, GameRequests, GameStops;
        internal bool DelayGame;
        internal string Path, SteamPath, GamePath;
        internal long Generation = 123;
        public int CurrentSessionId { get { return 2; } }
        public long? ReadSessionLogonTime(int sessionId) { return sessionId == 2 ? (long?)Generation : null; }
        public ProductProcessIdentity Read(int pid)
        { return Current != null && Current.Pid == pid ? Current :
            SteamCurrent != null && SteamCurrent.Pid == pid ? SteamCurrent :
            GameCurrent != null && GameCurrent.Pid == pid ? GameCurrent : null; }
        public ProductProcessIdentity Start(string executable, string arguments, string workingDirectory)
        {
            if (executable == SteamPath)
            {
                if (arguments == "-bigpicture" && SteamCurrent == null)
                { SteamStarts++; SteamCurrent = new ProductProcessIdentity { Pid = 130, SessionId = 2,
                    StartTimeUtcTicks = 3000, ExecutablePath = SteamPath, ExecutableSha256 = Digest }; return SteamCurrent; }
                if (arguments == "-applaunch " + SteamChildPolicy.MinecraftDungeonsAppId && SteamCurrent != null)
                { GameRequests++; if (!DelayGame) PublishGame();
                  return new ProductProcessIdentity { Pid = 131, SessionId = 2,
                    StartTimeUtcTicks = 3010, ExecutablePath = SteamPath, ExecutableSha256 = Digest }; }
            }
            if (executable != Path || Current != null) throw new Exception("Unexpected or duplicate process launch.");
            Starts++; Current = new ProductProcessIdentity { Pid = 120, SessionId = 2,
                StartTimeUtcTicks = 1000 + Starts, ExecutablePath = Path, ExecutableSha256 = Digest };
            return Current;
        }
        internal void PublishGame()
        { GameCurrent = new ProductProcessIdentity { Pid = 140, SessionId = 2,
            StartTimeUtcTicks = 4000, ExecutablePath = GamePath, ExecutableSha256 = Digest }; }
        public bool RequestClose(int pid)
        { if (pid != 120 && pid != 130 && pid != 140) UnrelatedTouched++; return pid == 120 || pid == 130 || pid == 140; }
        public bool WaitForExit(int pid, int milliseconds)
        {
            if (pid == 120) { Current = null; Stops++; return true; }
            if (pid == 130) { SteamCurrent = null; SteamStops++; return true; }
            if (pid == 140) { GameCurrent = null; GameStops++; return true; }
            UnrelatedTouched++; return false;
        }
        public void Kill(int pid) { UnrelatedTouched++; throw new Exception("No guessed process kill allowed."); }
    }
    private sealed class Identity : IChildSunshineIdentity
    {
        internal bool Credentials;
        internal string StablePassword = "a-stable-test-only-password-that-is-long";
        internal string Certificate = new string('a', 64);
        internal int MissingReads, PartialReads, Reads;
        internal bool ChangeAfterFirstRead;
        internal Action<int> DuringRead;
        public string DirectoryPath { get { return "fixture-identity"; } }
        public string CertificatePath { get { return "fixture-cert"; } }
        public string CredentialFilePath { get { return "fixture-creds"; } }
        public bool HasSunshineCredentials { get { return Credentials; } }
        public SunshineAdminCredential GetOrCreateCredentials()
        { return new SunshineAdminCredential { UserName = "ChildStream", Password = StablePassword }; }
        public string ReadCertificateSha256()
        {
            Reads++;
            if (DuringRead != null) DuringRead(Reads);
            if (MissingReads-- > 0) throw new FileNotFoundException("First-start certificate not written yet.");
            if (PartialReads-- > 0) throw new InvalidDataException("First-start certificate is incomplete.");
            return ChangeAfterFirstRead && Reads > 1 ? new string('b', 64) : Certificate;
        }
        public void Dispose() { }
    }
    private sealed class Pairing : IChildSunshineTransport
    {
        internal readonly Identity Identity;
        internal bool Refuse;
        internal int Posts;
        internal int Bootstraps;
        internal IVerifiedChildSunshine Owner;
        internal Pairing(Identity identity) { Identity = identity; }
        public bool BootstrapFirstCredentials() { Owner.AssertStillOwned(); Bootstraps++; Identity.Credentials = true; return true; }
        public string Send(string method, string path, string body)
        {
            Owner.AssertStillOwned();
            if (path != "/api/pin") throw new Exception("Unexpected pairing API.");
            if (method == "GET") return "{\"pairings\":[{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"name\":\"Fire TV\",\"address\":\"192.168.1.50\"}]}";
            Posts++; return Refuse ? "{\"status\":false}" : "{\"status\":true}";
        }
    }
    private sealed class Environment : IChildRuntimeEnvironment
    {
        internal readonly ProcessHost Process = new ProcessHost();
        internal readonly Identity Identity = new Identity();
        internal readonly Pairing Pairing;
        internal readonly string Root;
        internal int Intents, Records, Resolved, Discoveries;
        internal int SteamIntents, SteamRecords, GameIntents, GameRecords, SteamResolved, UncertainRecords;
        internal bool WrongListener, Elevated, ParentSteam, LanApproved, LanRequested;
        internal int ListenerDelay, ListenerReads;
        internal bool MultipleDevices;
        internal bool FailGameRecord;
        internal string SunshineConfiguration;
        internal string GameIntentPath { get { return Path.Combine(Root, "game.intent"); } }
        internal string GameRecordPath { get { return Path.Combine(Root, "game.record"); } }
        internal Environment(string root)
        { Root = Path.Combine(root, "ChildStream"); Process.Path = Path.Combine(root, "Sunshine", "sunshine.exe");
          Process.SteamPath = Path.Combine(root, "Steam", "steam.exe");
          Process.GamePath = Path.Combine(root, "Game", "Dungeons-Win64-Shipping.exe"); Pairing = new Pairing(Identity);
          Directory.CreateDirectory(Root); }
        public IProductProcessHost Processes { get { return Process; } }
        public string SunshineExecutable { get { return Process.Path; } }
        public string DataRoot { get { return Root; } }
        public string UserSid { get { return "S-1-5-21-100"; } }
        public ProcessTokenObservation ReadToken(int pid)
        { return new ProcessTokenObservation { Sid = UserSid, Elevation = Elevated ? RuntimeTokenStatus.Elevated : RuntimeTokenStatus.Limited }; }
        public string DiscoverDisplayLog(ChildSessionIdentity child)
        { Discoveries++; return "Info: Currently available display devices:\n[{\"device_id\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\",\"display_name\":\"DISPLAY2\",\"info\":{\"primary\":true}}" +
            (MultipleDevices ? ",{\"device_id\":\"{12100db6-5a9d-40c4-9c10-c3b1f606a632}\",\"display_name\":\"DISPLAY3\",\"info\":{}}" : "") + "]"; }
        public ChildAudioEndpointInventory ReadAudio(ChildSessionIdentity child)
        { var result = new ChildAudioEndpointInventory { SessionId = (int)child.SessionId, Complete = true };
          result.ActiveRenderIds.Add("{child-audio}"); if (MultipleDevices) result.ActiveRenderIds.Add("{child-audio-2}");
          return result; }
        public SunshineCollisionSnapshot ReadCollision(SunshinePortFamily family)
        { return new SunshineCollisionSnapshot { ServiceObservationComplete = true, ProcessObservationComplete = true, PortObservationComplete = true }; }
        public bool VerifyLanBoundary(string address, SunshinePortFamily family)
        { LanRequested = true; return LanApproved && address == "192.168.50.10" && family.BasePort == 48089; }
        public IList<SunshineListener> ReadListeners(int pid, SunshinePortFamily family, out bool complete)
        { complete = true; ListenerReads++;
          if (ListenerReads <= ListenerDelay) return new SunshineListener[0];
          return new [] { new SunshineListener { Protocol = "TCP", Port = family.BasePort + 1,
            Pid = WrongListener ? 999 : pid, LocalAddress = LanRequested ? "0.0.0.0" : "127.0.0.1" } }; }
        public IChildSunshineIdentity OpenIdentity() { return Identity; }
        public IChildSunshineTransport CreatePairingTransport(Uri endpoint, string certificateSha256,
            SunshineAdminCredential credential, IVerifiedChildSunshine owner)
        { if (credential.Password != Identity.StablePassword || certificateSha256 != new string('a',64) ||
              endpoint.Host != "127.0.0.1") throw new Exception("Identity or loopback admin endpoint changed.");
          Pairing.Owner = owner; return Pairing; }
        public string EnsureGenerationFile(ChildSessionIdentity child, string name, string content)
        { if (!name.EndsWith(".conf") && name != "apps.json") throw new Exception("Unexpected config file.");
          if (name == "sunshine.conf") SunshineConfiguration = content;
          return Path.Combine(Root, "sessions", child.SessionId + "-" + child.LogonTime, name); }
        public void RecordStartIntent(ChildSessionIdentity child) { Intents++; }
        public void RecordStarted(ChildSessionIdentity child, ProductProcessIdentity process) { Records++; LastStarted = process; }
        public bool HasUnresolvedStartIntent(ChildSessionIdentity child) { return Intents > Resolved; }
        public void ResolveStopped(ChildSessionIdentity child, ProductProcessIdentity process) { Resolved++; }
        public ProductProcessIdentity ReadStarted(ChildSessionIdentity child)
        { return Records > Resolved ? LastStarted : null; }
        internal ProductProcessIdentity LastStarted;
        public void ResolveFailedStart(ChildSessionIdentity child, ProductProcessIdentity process)
        { if (Process.Read(process.Pid) != null || process != LastStarted)
              throw new InvalidOperationException("Recovery must reconcile the exact absent process.");
          Resolved++; }
        public SteamInstallation ReadSteamInstallation()
        { return new SteamInstallation { SteamPath = Process.SteamPath, SteamSha256 = Digest,
            GamePath = Process.GamePath, GameSha256 = Digest }; }
        public SteamLaunchObservation ReadSteamObservation(ChildSessionIdentity child, uint parentSessionId)
        { return new SteamLaunchObservation { Complete = true, ParentSteam = ParentSteam,
            ChildSteam = Process.SteamCurrent != null }; }
        public ProductProcessIdentity ReadGameProcess(ChildSessionIdentity child, SteamInstallation installation)
        { return Process.GameCurrent; }
        public void RecordSteamIntent(ChildSessionIdentity child) { SteamIntents++; }
        public void RecordSteamStarted(ChildSessionIdentity child, ProductProcessIdentity process)
        { if (process == null || process.Pid != 130) throw new Exception("Wrong Steam record"); SteamRecords++; }
        public void RecordGameRequest(ChildSessionIdentity child)
        { GameIntents++; using (var file = new FileStream(GameIntentPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
          { byte[] bytes = System.Text.Encoding.ASCII.GetBytes(child.SessionId + "|" + child.LogonTime);
            file.Write(bytes, 0, bytes.Length); file.Flush(true); } }
        public void RecordGameObserved(ChildSessionIdentity child, ProductProcessIdentity process)
        {
            if (process == null || process.Pid != 140 || !File.Exists(GameIntentPath)) throw new Exception("Wrong game record");
            using (var file = new FileStream(GameRecordPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { byte[] bytes = System.Text.Encoding.ASCII.GetBytes(child.SessionId + "|" + child.LogonTime + "|" +
                process.Pid + "|" + process.StartTimeUtcTicks); file.Write(bytes, 0, bytes.Length); file.Flush(true); }
            if (FailGameRecord) throw new IOException("Injected interrupted record publication.");
            GameRecords++;
        }
        public void ResolveSteamStopped(ChildSessionIdentity child, ProductProcessIdentity steam,
            ProductProcessIdentity game)
        { if (steam == null || steam.Pid != 130 || game == null || game.Pid != 140 ||
              File.ReadAllText(GameRecordPath) != child.SessionId + "|" + child.LogonTime + "|" +
                game.Pid + "|" + game.StartTimeUtcTicks) throw new Exception("Wrong stopped record");
          File.Delete(GameRecordPath); File.Delete(GameIntentPath); SteamResolved++; }
        public void RecordRuntimeUncertainty(ChildSessionIdentity child, string reason) { UncertainRecords++; }
    }
    private sealed class Bootstrap : IChildBootstrapHost, IChildAgentCommandHost
    {
        internal readonly ChildAgentRuntime Runtime;
        internal readonly ChildSessionIdentity Child;
        internal ProductProcessIdentity Agent;
        internal int Commands, Exits;
        internal Bootstrap(ChildAgentRuntime runtime, ChildSessionIdentity child, string agentPath)
        { Runtime = runtime; Child = child; Agent = new ProductProcessIdentity { Pid = 99, SessionId = 2,
            StartTimeUtcTicks = 999, ExecutablePath = agentPath, ExecutableSha256 = Digest }; }
        public ChildSessionIdentity? ReadAssociatedChild() { return Child; }
        public long? ReadLogonTime(uint sessionId) { return Child.LogonTime; }
        public void RequestAgentInSession(ChildAgentRequest request) { }
        public ChildAgentHello WaitForAgent(ChildAgentRequest request, int timeoutMs)
        { return new ChildAgentHello { Nonce = request.Nonce, Pid = 99, Child = Child }; }
        public ProductProcessIdentity ReadAgent(int pid) { return Agent; }
        public void RequestAgentExit(int pid) { if (pid != 99) throw new Exception("Wrong agent exit."); Agent = null; Exits++; }
        public string Exchange(ChildAgentOperation operation, string payload, int timeoutMs)
        {
            Commands++;
            try { return Runtime.Execute(operation, payload); }
            catch (Exception ex) { throw new ChildAgentCommandRejectedException(ex.Message); }
        }
    }
    private static int checks;
    private static void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
    private static void Reject(Action operation, string message)
    { bool rejected = false; try { operation(); } catch { rejected = true; } Check(rejected, message); }
    public static int Main()
    {
        string root = Path.Combine(Path.GetTempPath(), "ChildStreamIntegrated-" + Guid.NewGuid().ToString("N"));
        var child = new ChildSessionIdentity(2, 123);
        var environment = new Environment(root);
        var runtime = new ChildAgentRuntime(child, 1, environment);
        string agentPath = Path.Combine(root, "ChildStream.exe");
        var bootstrap = new Bootstrap(runtime, child, agentPath);
        var controller = new ChildAgentController(bootstrap, 1, child, agentPath, Digest);
        var request = new ChildAgentRequest { ParentSessionId = 1, Child = child,
            PipeName = "ChildStream-" + new string('a', 32), Nonce = new string('b', 64),
            ParentPid = 17, ParentExecutableSha256 = Digest, RequesterSid = "S-1-5-21-100" };
        controller.Start(request);
        Check(controller.Stage == ChildAgentStage.Ready, "agent verified before operational command");
        string status = controller.Execute(ChildAgentOperation.StartSunshine, "");
        Check(status.Contains("SunshineReady") && environment.Process.Starts == 1 &&
            environment.Intents == 1 && environment.Records == 1, "controller-to-agent-to-owned runtime started once");
        controller.Execute(ChildAgentOperation.StartSunshine, "");
        Check(environment.Process.Starts == 1, "reconnect cannot duplicate Sunshine");
        var flow = new MoonlightPairingCoordinator(new VerifiedAgentSunshine(controller, child),
            new AgentSunshinePairingApi(controller));
        var pending = flow.Refresh();
        Check(pending.Count == 1 && pending[0].Name == "Fire TV", "UI pairing sees exact child request");
        Check(flow.Approve(pending[0].Id, "1234", true), "selected PIN traverses controller and child pairing transport");
        environment.Pairing.Refuse = true;
        pending = flow.Refresh();
        Check(!flow.Approve(pending[0].Id, "1234", true), "refused pairing remains a truthful failure");
        Check(environment.Pairing.Posts == 2, "two selected pairing attempts, no implicit pairing");
        environment.WrongListener = true;
        Reject(() => flow.Refresh(), "foreign listener blocks pairing");
        environment.WrongListener = false;
        environment.Identity.Certificate = new string('b', 64);
        Reject(() => flow.Refresh(), "changed owned certificate blocks later pairing");
        environment.Identity.Certificate = new string('a', 64);
        environment.Elevated = true;
        Reject(() => flow.Refresh(), "elevated child Sunshine token blocks pairing");
        environment.Elevated = false;
        environment.ParentSteam = true;
        Reject(() => controller.Execute(ChildAgentOperation.StartSteam, ""),
            "parent Steam singleton blocks child launch");
        Check(environment.Process.SteamStarts == 0, "parent Steam untouched by rejected child request");
        environment.ParentSteam = false;
        Check(controller.Execute(ChildAgentOperation.StartSteam, "").Contains("BigPictureStarted") &&
            environment.Process.SteamStarts == 1, "authenticated command starts exact child Steam");
        Check(controller.Execute(ChildAgentOperation.RequestGame, "").Contains("GameObserved") &&
            environment.Process.GameRequests == 1, "fixed app request and exact child game observed");
        controller.Execute(ChildAgentOperation.StopSteam, "");
        Check(environment.Process.SteamStops == 1 && environment.Process.GameStops == 1 &&
            environment.Process.UnrelatedTouched == 0 && environment.SteamIntents == 1 &&
            environment.SteamRecords == 1 && environment.GameIntents == 1 &&
            environment.GameRecords == 1 && environment.SteamResolved == 1,
            "child-only Steam/game teardown with durable intent and exact reconciliation");
        controller.Execute(ChildAgentOperation.StopSunshine, "");
        Check(environment.Process.Stops == 1 && environment.Resolved == 1 && environment.Process.UnrelatedTouched == 0,
            "exact-owned shutdown only");
        Reject(() => flow.Refresh(), "pairing unavailable after owned stop");
        controller.Stop();
        Check(bootstrap.Exits == 1, "exact agent exit after runtime stop");
        runtime.Dispose();
        environment.Process.Generation = 124;
        var nextChild = new ChildSessionIdentity(2, 124);
        using (var nextRuntime = new ChildAgentRuntime(nextChild, 1, environment))
        {
            string nextStatus = nextRuntime.Execute(ChildAgentOperation.StartSunshine, "");
            Check(nextStatus.Contains("SunshineReady") && environment.Pairing.Bootstraps == 1 &&
                environment.Process.Starts == 2, "new child generation reuses owned pairing identity without rebootstrap");
            environment.Process.Current = null; // Owned process exited before explicit reconciliation.
            nextRuntime.Execute(ChildAgentOperation.StopSunshine, "");
            Check(environment.Resolved == 2 && environment.Process.UnrelatedTouched == 0,
                "verified-absent owned process record reconciles without PID guessing");
        }
        var cold = new Environment(root + "-cold");
        cold.Identity.MissingReads = 1; cold.Identity.PartialReads = 1;
        using (var first = new ChildAgentRuntime(child, 1, cold))
        {
            Check(first.Execute(ChildAgentOperation.StartSunshine, "").Contains("SunshineReady") &&
                cold.Identity.Reads >= 3, "first-start missing and partial certificate waits for complete owned identity");
            first.Execute(ChildAgentOperation.StopSunshine, "");
        }
        var warmDelayed = new Environment(root + "-warm-delayed") { ListenerDelay = 3 };
        using (var worker = new ChildAgentRuntime(child, 1, warmDelayed))
        {
            Check(worker.Execute(ChildAgentOperation.StartSunshine, "").Contains("SunshineReady") &&
                warmDelayed.ListenerReads >= 4,
                "existing certificate waits for its own delayed pairing listener");
            worker.Execute(ChildAgentOperation.StopSunshine, "");
        }
        var warmNever = new Environment(root + "-warm-never") { ListenerDelay = 100 };
        using (var worker = new ChildAgentRuntime(child, 1, warmNever))
        {
            Reject(() => worker.Execute(ChildAgentOperation.StartSunshine, ""),
                "existing unchanged certificate cannot hide a listener that never appears");
            Check(worker.Execute(ChildAgentOperation.Status, "").Contains("Uncertain") &&
                warmNever.ListenerReads >= 50,
                "warm missing listener reaches a bounded uncertain state");
            Check(worker.Execute(ChildAgentOperation.RecoverSunshine, "").Contains("NoSunshine") &&
                warmNever.Process.Stops == 1,
                "warm listener timeout has exact-owned recovery");
        }
        var replaced = new Environment(root + "-replaced");
        replaced.Identity.ChangeAfterFirstRead = true;
        using (var first = new ChildAgentRuntime(child, 1, replaced))
        {
            Reject(() => first.Execute(ChildAgentOperation.StartSunshine, ""),
                "existing certificate replacement is rejected before pairing");
            Check(first.Execute(ChildAgentOperation.Status, "").Contains("Uncertain"),
                "failed startup remains observable without allowing a second launch");
            Reject(() => first.Execute(ChildAgentOperation.StartSunshine, ""),
                "failed startup cannot duplicate the owned process");
            Check(first.Execute(ChildAgentOperation.RecoverSunshine, "").Contains("NoSunshine") &&
                replaced.Process.Stops == 1 && replaced.Resolved == 1,
                "exact failed-start process can be stopped and reconciled through the agent");
            replaced.Identity.ChangeAfterFirstRead = false;
            Check(first.Execute(ChildAgentOperation.StartSunshine, "").Contains("SunshineReady"),
                "reconciled failed start can be retried in the same child generation");
            first.Execute(ChildAgentOperation.StopSunshine, "");
        }
        var exited = new Environment(root + "-exited");
        exited.Identity.MissingReads = 5;
        exited.Identity.DuringRead = read => { if (read == 2) exited.Process.Current = null; };
        using (var first = new ChildAgentRuntime(child, 1, exited))
            Reject(() => first.Execute(ChildAgentOperation.StartSunshine, ""),
                "owned process exit during first-start certificate wait is rejected");
        var resumed = new Environment(root + "-resumed");
        resumed.Intents = 1; resumed.Records = 1;
        resumed.Process.Current = new ProductProcessIdentity { Pid = 120, SessionId = 2,
            StartTimeUtcTicks = 5000, ExecutablePath = resumed.Process.Path,
            ExecutableSha256 = Digest };
        resumed.LastStarted = resumed.Process.Current;
        using (var worker = new ChildAgentRuntime(child, 1, resumed))
        {
            Check(worker.Execute(ChildAgentOperation.Status, "").Contains("Uncertain"),
                "new agent exposes previously interrupted exact start instead of reporting no runtime");
            Reject(() => worker.Execute(ChildAgentOperation.StartSunshine, ""),
                "new agent never duplicates an interrupted prior process");
            Check(worker.Execute(ChildAgentOperation.RecoverSunshine, "").Contains("NoSunshine") &&
                resumed.Process.Stops == 1 && resumed.Resolved == 1,
                "new agent attaches only the durable exact process for reviewed recovery");
        }
        var never = new Environment(root + "-never");
        never.Identity.MissingReads = 100;
        using (var first = new ChildAgentRuntime(child, 1, never))
            Reject(() => first.Execute(ChildAgentOperation.StartSunshine, ""),
                "first-start identity never appearing reaches a bounded failure");
        var lan = new Environment(root + "-lan");
        var monitor = new ManualMonitor();
        using (var worker = new ChildAgentRuntime(child, 1, lan, monitor))
        {
            string lanSelection = "{\"display\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\"," +
                "\"audio\":\"{child-audio}\",\"address\":\"192.168.50.10\"}";
            Reject(() => worker.Execute(ChildAgentOperation.StartSunshineLan, lanSelection),
                "LAN Sunshine cannot start before scoped firewall admission");
            Check(lan.Process.Starts == 0, "unapproved LAN path does not launch a process");
            lan.LanApproved = true;
            string observed = worker.Execute(ChildAgentOperation.StartSunshineLan, lanSelection);
            Check(observed.Contains("192.168.50.10:48089") && observed.Contains("ScopedRulesVerified") &&
                lan.Process.Starts == 1 && monitor.Starts == 1,
                "real child runtime uses admitted LAN address and starts agent-side monitor");
            lan.LanApproved = false;
            monitor.Fire(); // No UI command or poll triggers this transition.
            Check(worker.Execute(ChildAgentOperation.Status, "").Contains("SunshineWithdrawn") &&
                lan.Process.Stops == 1 && lan.Resolved == 1,
                "idle agent withdraws exact owned LAN Sunshine when boundary is lost");
            Reject(() => worker.Execute(ChildAgentOperation.PairingGet, ""),
                "LAN rule drift blocks authenticated pairing operations");
            Check(lan.Process.UnrelatedTouched == 0 && monitor.Tick == null,
                "boundary withdrawal stops monitoring and never touches unrelated processes");
        }
        var reusedLan = new Environment(root + "-reused-lan") { LanApproved = true };
        var reusedMonitor = new ManualMonitor();
        using (var worker = new ChildAgentRuntime(child, 1, reusedLan, reusedMonitor))
        {
            string chosen = "{\"display\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\"," +
                "\"audio\":\"{child-audio}\",\"address\":\"192.168.50.10\"}";
            worker.Execute(ChildAgentOperation.StartSunshineLan, chosen);
            ProductProcessIdentity old = reusedLan.Process.Current;
            reusedLan.Process.Current = new ProductProcessIdentity { Pid = old.Pid, SessionId = old.SessionId,
                StartTimeUtcTicks = old.StartTimeUtcTicks + 1, ExecutablePath = old.ExecutablePath,
                ExecutableSha256 = old.ExecutableSha256 };
            reusedLan.LanApproved = false;
            reusedMonitor.Fire();
            Check(worker.Execute(ChildAgentOperation.Status, "").Contains("Uncertain") &&
                reusedLan.Process.Stops == 0 && reusedLan.Resolved == 0 &&
                reusedLan.UncertainRecords == 1,
                "idle boundary loss with PID reuse latches uncertainty and preserves records");
            Reject(() => worker.Execute(ChildAgentOperation.RecoverSunshine, ""),
                "recovery cannot stop a reused Sunshine PID");
            Check(reusedLan.Process.UnrelatedTouched == 0,
                "boundary monitor never closes an unrelated reused process");
        }
        var transition = new Environment(root + "-transition");
        using (var worker = new ChildAgentRuntime(child, 1, transition, new ManualMonitor()))
        {
            var host = new Bootstrap(worker, child, agentPath);
            var app = new ChildAgentController(host, 1, child, agentPath, Digest);
            app.Start(request);
            var journey = new ChildStreamingJourney(app, child);
            Check(journey.Start("", false).ManualAddress == "127.0.0.1:48089",
                "normal application establishes local child-owned pairing runtime");
            Check(journey.Start("", false).ManualAddress == "127.0.0.1:48089" &&
                transition.Process.Starts == 1,
                "repeat local action reuses the exact verified runtime without a duplicate process");
            transition.LanApproved = true;
            string chosen = "{\"display\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\"," +
                "\"audio\":\"{child-audio}\",\"address\":\"192.168.50.10\"}";
            Check(journey.Start(chosen, true).ManualAddress == "192.168.50.10:48089" &&
                transition.Process.Starts == 2 && transition.Process.Stops == 1 &&
                transition.Identity.Credentials,
                "app switches exact owned local process to approved LAN without recreating child or pairing identity");
            Check(journey.Start("", true).ManualAddress == "192.168.50.10:48089" &&
                transition.Process.Starts == 2,
                "repeat approved LAN action reuses the exact verified runtime");
            Reject(() => journey.Start(chosen, true),
                "running LAN stream cannot silently ignore a new device selection");
            journey.Stop();
            Check(transition.Process.Stops == 2 && transition.Process.UnrelatedTouched == 0,
                "normal application stops only its exact second Sunshine process");
            app.Stop();
        }
        var multiple = new Environment(root + "-multiple") { MultipleDevices = true };
        using (var worker = new ChildAgentRuntime(child, 1, multiple))
        {
            ChildCapabilityCatalog catalog = ChildCapabilityCatalog.Parse(
                worker.Execute(ChildAgentOperation.Capabilities, ""));
            Check(catalog.Displays.Count == 2 && catalog.Audio.Count == 2,
                "normal child agent exposes multiple child-observed choices");
            Reject(() => worker.Execute(ChildAgentOperation.StartSunshine, ""),
                "multiple child devices cannot be chosen implicitly");
            string selected = catalog.SelectionPayload("{12100db6-5a9d-40c4-9c10-c3b1f606a632}",
                "{child-audio-2}", null);
            worker.Execute(ChildAgentOperation.StartSunshine, selected);
            Check(multiple.SunshineConfiguration.Contains("audio_sink = {child-audio-2}") &&
                multiple.SunshineConfiguration.Contains("output_name = {12100db6-5a9d-40c4-9c10-c3b1f606a632}"),
                "selected IDs reach the real Sunshine config builder");
            worker.Execute(ChildAgentOperation.StopSunshine, "");
        }
        var delayed = new Environment(root + "-delayed"); delayed.Process.DelayGame = true;
        using (var worker = new ChildAgentRuntime(child, 1, delayed))
        {
            worker.Execute(ChildAgentOperation.StartSunshine, "");
            worker.Execute(ChildAgentOperation.StartSteam, "");
            Check(worker.Execute(ChildAgentOperation.RequestGame, "").Contains("GameRequested") &&
                File.Exists(delayed.GameIntentPath) && !File.Exists(delayed.GameRecordPath),
                "delayed game remains pending with durable request intent");
            delayed.Process.PublishGame();
            Check(worker.Execute(ChildAgentOperation.Status, "").Contains("GameObserved") &&
                File.Exists(delayed.GameRecordPath), "late exact game observation is durably recorded on status");
            worker.Execute(ChildAgentOperation.StopSteam, "");
            Check(!File.Exists(delayed.GameRecordPath) && !File.Exists(delayed.GameIntentPath) &&
                delayed.Process.GameStops == 1 && delayed.Process.UnrelatedTouched == 0,
                "delayed game exact stop reconciles real temporary record files");
            worker.Execute(ChildAgentOperation.StopSunshine, "");
        }
        var vanished = new Environment(root + "-vanished"); vanished.Process.DelayGame = true;
        using (var worker = new ChildAgentRuntime(child, 1, vanished))
        {
            worker.Execute(ChildAgentOperation.StartSunshine, ""); worker.Execute(ChildAgentOperation.StartSteam, "");
            worker.Execute(ChildAgentOperation.RequestGame, "");
            vanished.Process.PublishGame(); vanished.Process.GameCurrent = null;
            Reject(() => worker.Execute(ChildAgentOperation.StopSteam, ""),
                "game that exited before observation cannot be guessed or stopped");
            Check(!File.Exists(vanished.GameRecordPath) && vanished.Process.GameStops == 0,
                "unobserved launch preserves intent for reviewed recovery");
        }
        var reused = new Environment(root + "-reused"); reused.Process.DelayGame = true;
        using (var worker = new ChildAgentRuntime(child, 1, reused))
        {
            worker.Execute(ChildAgentOperation.StartSunshine, ""); worker.Execute(ChildAgentOperation.StartSteam, "");
            worker.Execute(ChildAgentOperation.RequestGame, ""); reused.Process.PublishGame();
            reused.Process.GameCurrent.SessionId = 3;
            Reject(() => worker.Execute(ChildAgentOperation.Status, ""),
                "wrong-session reused game PID cannot become a durable owned record");
            Check(!File.Exists(reused.GameRecordPath) && reused.Process.GameStops == 0,
                "identity drift preserves the unresolved request");
        }
        var interrupted = new Environment(root + "-interrupted"); interrupted.Process.DelayGame = true;
        using (var worker = new ChildAgentRuntime(child, 1, interrupted))
        {
            worker.Execute(ChildAgentOperation.StartSunshine, ""); worker.Execute(ChildAgentOperation.StartSteam, "");
            worker.Execute(ChildAgentOperation.RequestGame, ""); interrupted.Process.PublishGame();
            interrupted.FailGameRecord = true;
            Reject(() => worker.Execute(ChildAgentOperation.Status, ""),
                "interrupted game record makes runtime uncertain");
            Reject(() => worker.Execute(ChildAgentOperation.StopSteam, ""),
                "interrupted durable record blocks destructive stop");
            Check(File.Exists(interrupted.GameRecordPath) && interrupted.Process.GameStops == 0,
                "interrupted record evidence is preserved for review");
        }
        string temporary = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) +
            Path.DirectorySeparatorChar + "ChildStreamIntegrated-";
        foreach (string fixture in new [] { root, root + "-cold", root + "-replaced", root + "-exited",
            root + "-never", root + "-warm-delayed", root + "-warm-never", root + "-resumed", root + "-lan", root + "-reused-lan", root + "-transition", root + "-multiple", root + "-delayed", root + "-vanished", root + "-reused", root + "-interrupted" })
        { if (!Path.GetFullPath(fixture).StartsWith(temporary, StringComparison.OrdinalIgnoreCase))
              throw new InvalidOperationException("Fixture cleanup escaped ChildStream temp root.");
          if (Directory.Exists(fixture)) Directory.Delete(fixture, true); }
        Console.WriteLine("Integrated controller/agent/Sunshine/pairing assertions passed: " + checks);
        return 0;
    }
}
