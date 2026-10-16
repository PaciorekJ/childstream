using System;
using System.Collections.Generic;
using System.IO;

static class IntegratedRuntimeTests
{
    private const string Digest = SunshineReleasePin.ExecutableSha256;
    private sealed class ProcessHost : IProductProcessHost
    {
        internal ProductProcessIdentity Current;
        internal ProductProcessIdentity SteamCurrent, GameCurrent;
        internal int Starts, Stops, UnrelatedTouched;
        internal int SteamStarts, SteamStops, GameRequests, GameStops;
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
                { GameRequests++; GameCurrent = new ProductProcessIdentity { Pid = 140, SessionId = 2,
                    StartTimeUtcTicks = 4000, ExecutablePath = GamePath, ExecutableSha256 = Digest };
                  return new ProductProcessIdentity { Pid = 131, SessionId = 2,
                    StartTimeUtcTicks = 3010, ExecutablePath = SteamPath, ExecutableSha256 = Digest }; }
            }
            if (executable != Path || Current != null) throw new Exception("Unexpected or duplicate process launch.");
            Starts++; Current = new ProductProcessIdentity { Pid = 120, SessionId = 2,
                StartTimeUtcTicks = 1000 + Starts, ExecutablePath = Path, ExecutableSha256 = Digest };
            return Current;
        }
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
        public string DirectoryPath { get { return "fixture-identity"; } }
        public string CertificatePath { get { return "fixture-cert"; } }
        public string CredentialFilePath { get { return "fixture-creds"; } }
        public bool HasSunshineCredentials { get { return Credentials; } }
        public SunshineAdminCredential GetOrCreateCredentials()
        { return new SunshineAdminCredential { UserName = "ChildStream", Password = StablePassword }; }
        public string ReadCertificateSha256() { return Certificate; }
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
        internal bool WrongListener, Elevated, ParentSteam;
        internal Environment(string root)
        { Root = Path.Combine(root, "ChildStream"); Process.Path = Path.Combine(root, "Sunshine", "sunshine.exe");
          Process.SteamPath = Path.Combine(root, "Steam", "steam.exe");
          Process.GamePath = Path.Combine(root, "Game", "Dungeons-Win64-Shipping.exe"); Pairing = new Pairing(Identity); }
        public IProductProcessHost Processes { get { return Process; } }
        public string SunshineExecutable { get { return Process.Path; } }
        public string DataRoot { get { return Root; } }
        public string UserSid { get { return "S-1-5-21-100"; } }
        public ProcessTokenObservation ReadToken(int pid)
        { return new ProcessTokenObservation { Sid = UserSid, Elevation = Elevated ? RuntimeTokenStatus.Elevated : RuntimeTokenStatus.Limited }; }
        public string DiscoverDisplayLog(ChildSessionIdentity child)
        { Discoveries++; return "Info: Currently available display devices:\n[{\"device_id\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\",\"display_name\":\"DISPLAY2\",\"info\":{\"primary\":true}}]"; }
        public ChildAudioEndpointInventory ReadAudio(ChildSessionIdentity child)
        { var result = new ChildAudioEndpointInventory { SessionId = (int)child.SessionId, Complete = true }; result.ActiveRenderIds.Add("{child-audio}"); return result; }
        public SunshineCollisionSnapshot ReadCollision(SunshinePortFamily family)
        { return new SunshineCollisionSnapshot { ServiceObservationComplete = true, ProcessObservationComplete = true, PortObservationComplete = true }; }
        public IList<SunshineListener> ReadListeners(int pid, SunshinePortFamily family, out bool complete)
        { complete = true; return new [] { new SunshineListener { Protocol = "TCP", Port = family.BasePort + 1,
            Pid = WrongListener ? 999 : pid, LocalAddress = "127.0.0.1" } }; }
        public IChildSunshineIdentity OpenIdentity() { return Identity; }
        public IChildSunshineTransport CreatePairingTransport(Uri endpoint, string certificateSha256,
            SunshineAdminCredential credential, IVerifiedChildSunshine owner)
        { if (credential.Password != Identity.StablePassword || certificateSha256 != new string('a',64)) throw new Exception("Identity changed."); Pairing.Owner = owner; return Pairing; }
        public string EnsureGenerationFile(ChildSessionIdentity child, string name, string content)
        { if (!name.EndsWith(".conf") && name != "apps.json") throw new Exception("Unexpected config file."); return Path.Combine(Root, "sessions", child.SessionId + "-" + child.LogonTime, name); }
        public void RecordStartIntent(ChildSessionIdentity child) { Intents++; }
        public void RecordStarted(ChildSessionIdentity child, ProductProcessIdentity process) { Records++; }
        public void ResolveStopped(ChildSessionIdentity child, ProductProcessIdentity process) { Resolved++; }
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
        public void RecordGameRequest(ChildSessionIdentity child) { GameIntents++; }
        public void RecordGameObserved(ChildSessionIdentity child, ProductProcessIdentity process)
        { if (process == null || process.Pid != 140) throw new Exception("Wrong game record"); GameRecords++; }
        public void ResolveSteamStopped(ChildSessionIdentity child, ProductProcessIdentity steam,
            ProductProcessIdentity game)
        { if (steam == null || steam.Pid != 130 || game == null || game.Pid != 140) throw new Exception("Wrong stopped record"); SteamResolved++; }
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
        Console.WriteLine("Integrated controller/agent/Sunshine/pairing assertions passed: " + checks);
        return 0;
    }
}
