using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal interface IChildRuntimeEnvironment
{
    IProductProcessHost Processes { get; }
    string SunshineExecutable { get; }
    string DataRoot { get; }
    string UserSid { get; }
    ProcessTokenObservation ReadToken(int pid);
    string DiscoverDisplayLog(ChildSessionIdentity child);
    ChildAudioEndpointInventory ReadAudio(ChildSessionIdentity child);
    SunshineCollisionSnapshot ReadCollision(SunshinePortFamily family);
    bool VerifyLanBoundary(string address, SunshinePortFamily family);
    IList<SunshineListener> ReadListeners(int pid, SunshinePortFamily family, out bool complete);
    IChildSunshineIdentity OpenIdentity();
    IChildSunshineTransport CreatePairingTransport(Uri endpoint, string certificateSha256,
        SunshineAdminCredential credential, IVerifiedChildSunshine owner);
    string EnsureGenerationFile(ChildSessionIdentity child, string name, string content);
    void RecordStartIntent(ChildSessionIdentity child);
    void RecordStarted(ChildSessionIdentity child, ProductProcessIdentity process);
    bool HasUnresolvedStartIntent(ChildSessionIdentity child);
    void ResolveStopped(ChildSessionIdentity child, ProductProcessIdentity process);
    ProductProcessIdentity ReadStarted(ChildSessionIdentity child);
    void ResolveFailedStart(ChildSessionIdentity child, ProductProcessIdentity process);
    SteamInstallation ReadSteamInstallation();
    SteamLaunchObservation ReadSteamObservation(ChildSessionIdentity child, uint parentSessionId);
    ProductProcessIdentity ReadGameProcess(ChildSessionIdentity child, SteamInstallation installation);
    void RecordSteamIntent(ChildSessionIdentity child);
    void RecordSteamStarted(ChildSessionIdentity child, ProductProcessIdentity process);
    void RecordGameRequest(ChildSessionIdentity child);
    void RecordGameObserved(ChildSessionIdentity child, ProductProcessIdentity process);
    void ResolveSteamStopped(ChildSessionIdentity child, ProductProcessIdentity steam,
        ProductProcessIdentity game);
    void RecordRuntimeUncertainty(ChildSessionIdentity child, string reason);
}

internal sealed class SteamInstallation
{
    internal string SteamPath, SteamSha256, GamePath, GameSha256;
}
internal sealed class SteamLaunchObservation
{
    internal bool Complete, ParentSteam, UnrelatedSteam, ChildSteam;
}

internal sealed class SunshineNotReadyException : InvalidOperationException
{
    internal SunshineNotReadyException(string message) : base(message) { }
}

internal interface IRuntimeMonitor : IDisposable
{
    void Start(Action tick);
    void Stop();
}

internal sealed class PeriodicRuntimeMonitor : IRuntimeMonitor
{
    private Timer timer;
    public void Start(Action tick)
    {
        if (timer != null) throw new InvalidOperationException("Runtime monitor already started.");
        timer = new Timer(state => tick(), null, 1000, 1000);
    }
    public void Stop()
    {
        Timer old = timer; timer = null;
        if (old != null) old.Dispose();
    }
    public void Dispose() { Stop(); }
}

internal sealed class VerifiedChildSunshineRuntime : IVerifiedChildSunshine
{
    private readonly IChildRuntimeEnvironment environment;
    private readonly ChildSessionIdentity child;
    private readonly ProductProcessIdentity expected;
    private readonly IChildSunshineIdentity identity;
    private readonly SunshinePortFamily family;
    private readonly string certificateSha256;
    private readonly string lanAddress;
    internal VerifiedChildSunshineRuntime(IChildRuntimeEnvironment environment, ChildSessionIdentity child,
        ProductProcessIdentity expected, IChildSunshineIdentity identity, SunshinePortFamily family,
        string certificateSha256, string lanAddress)
    { this.environment = environment; this.child = child; this.expected = expected;
      this.identity = identity; this.family = family; this.certificateSha256 = certificateSha256;
      this.lanAddress = lanAddress; }
    public string HostName { get { AssertStillOwned(); return "ChildStream"; } }
    public string ManualAddress { get { AssertStillOwned(); return (lanAddress ?? "127.0.0.1") + ":" + family.BasePort; } }
    public void AssertStillOwned()
    {
        AssertProcessAndListener();
        if (lanAddress != null && !environment.VerifyLanBoundary(lanAddress, family))
            throw new InvalidOperationException("Approved LAN firewall or network boundary changed.");
        if (String.IsNullOrEmpty(certificateSha256) ||
            !String.Equals(identity.ReadCertificateSha256(), certificateSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ChildStream Sunshine certificate identity changed.");
    }
    internal void AssertProcessAndListener()
    {
        var process = environment.Processes.Read(expected.Pid);
        var token = environment.ReadToken(expected.Pid);
        if (process == null || process.Pid != expected.Pid ||
            process.StartTimeUtcTicks != expected.StartTimeUtcTicks ||
            process.SessionId != (int)child.SessionId ||
            !String.Equals(process.ExecutablePath, expected.ExecutablePath, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(process.ExecutableSha256, expected.ExecutableSha256, StringComparison.OrdinalIgnoreCase) ||
            environment.Processes.CurrentSessionId != (int)child.SessionId ||
            environment.Processes.ReadSessionLogonTime((int)child.SessionId) != child.LogonTime ||
            token == null || token.Elevation != RuntimeTokenStatus.Limited || token.Sid != environment.UserSid)
            throw new InvalidOperationException("ChildStream Sunshine process, token or child generation changed.");
        bool complete;
        IList<SunshineListener> listeners = environment.ReadListeners(expected.Pid, family, out complete);
        string expectedBind = lanAddress == null ? "127.0.0.1" : "0.0.0.0";
        string problem = SunshineRuntimeGate.CheckCandidate(complete, expected.Pid, expectedBind, family, listeners);
        if (problem == "Candidate Sunshine opened no verifiable listener.")
            throw new SunshineNotReadyException(problem);
        if (problem != null) throw new InvalidOperationException(problem);
        bool webUi = false;
        foreach (var endpoint in listeners)
            if (endpoint.Protocol == "TCP" && endpoint.Port == family.BasePort + 1 &&
                endpoint.Pid == expected.Pid && endpoint.LocalAddress == expectedBind) webUi = true;
        if (!webUi) throw new SunshineNotReadyException("ChildStream HTTPS pairing listener has not appeared yet.");
    }
}

internal sealed class ChildAgentRuntime : IChildAgentOperations
{
    private readonly ChildSessionIdentity child;
    private readonly uint parentSessionId;
    private readonly IChildRuntimeEnvironment environment;
    private readonly SunshinePortFamily family = new SunshinePortFamily(48089);
    private readonly object gate = new object();
    private readonly IRuntimeMonitor monitor;
    private bool monitoringLan, boundaryWithdrawn;
    private string lanAddress;
    private ChildOwnedProcess sunshine;
    private ProductProcessIdentity sunshineIdentity;
    private IChildSunshineIdentity identity;
    private IChildSunshineTransport pairing;
    private VerifiedChildSunshineRuntime owner;
    private bool uncertain;
    private SteamChildRuntime steam;
    private SteamInstallation steamInstallation;
    internal ChildAgentRuntime(ChildSessionIdentity child, uint parentSessionId,
        IChildRuntimeEnvironment environment, IRuntimeMonitor monitor = null)
    {
        if (child.SessionId == 0 || child.LogonTime <= 0 || parentSessionId == 0 ||
            parentSessionId == child.SessionId || environment == null)
            throw new InvalidDataException("Exact child and production environment are required.");
        this.child = child; this.parentSessionId = parentSessionId; this.environment = environment;
        this.monitor = monitor ?? new PeriodicRuntimeMonitor();
    }
    private void RequireChild()
    {
        if (environment.Processes.CurrentSessionId != (int)child.SessionId ||
            environment.Processes.ReadSessionLogonTime((int)child.SessionId) != child.LogonTime)
            throw new InvalidOperationException("Runtime left the exact child logon generation.");
    }
    public string Execute(ChildAgentOperation operation, string payload)
    { lock (gate) { return ExecuteLocked(operation, payload); } }
    private string ExecuteLocked(ChildAgentOperation operation, string payload)
    {
        RequireChild();
        if (monitoringLan) SuperviseLanLocked();
        if (sunshineIdentity == null && environment.HasUnresolvedStartIntent(child)) uncertain = true;
        if (uncertain && operation != ChildAgentOperation.Status &&
            operation != ChildAgentOperation.RecoverSunshine)
            throw new InvalidOperationException("Runtime ownership is uncertain; exact owned recovery is required.");
        if (payload == null) payload = "";
        switch (operation)
        {
            case ChildAgentOperation.Status:
                if (payload.Length != 0) throw new InvalidDataException("Status has no payload.");
                return Status();
            case ChildAgentOperation.StartSunshine:
                return StartSunshine(null, ParseSelection(payload, false));
            case ChildAgentOperation.StartSunshineLan:
                var selectedLan = ParseSelection(payload, true);
                return StartSunshine(selectedLan.Address, selectedLan);
            case ChildAgentOperation.Capabilities:
                if (payload.Length != 0) throw new InvalidDataException("Capability discovery has no payload.");
                return Capabilities();
            case ChildAgentOperation.StopSunshine:
                if (payload.Length != 0) throw new InvalidDataException("Sunshine stop has no payload.");
                StopSunshine(); return Status();
            case ChildAgentOperation.RecoverSunshine:
                if (payload.Length != 0) throw new InvalidDataException("Recovery has no payload.");
                RecoverSunshine(); return Status();
            case ChildAgentOperation.PairingGet:
                if (payload.Length != 0 || pairing == null) throw new InvalidOperationException("Verified Sunshine is required for pairing refresh.");
                owner.AssertStillOwned(); return pairing.Send("GET", "/api/pin", null);
            case ChildAgentOperation.PairingPost:
                if (pairing == null || payload.Length > 4096) throw new InvalidOperationException("Verified Sunshine is required for PIN approval.");
                var selected = new JavaScriptSerializer().DeserializeObject(payload) as IDictionary<string, object>;
                object id, pin, name;
                if (selected == null || selected.Count != 3 || !selected.TryGetValue("pairing_id", out id) ||
                    !selected.TryGetValue("pin", out pin) || !selected.TryGetValue("name", out name))
                    throw new InvalidDataException("PIN approval request is malformed.");
                string canonical = SunshinePairingProtocol.BuildPinRequest(id as string, pin as string, name as string);
                owner.AssertStillOwned(); return pairing.Send("POST", "/api/pin", canonical);
            case ChildAgentOperation.StartSteam:
                if (payload.Length != 0) throw new InvalidDataException("Steam start has no caller-selected path or arguments.");
                StartSteam(); return Status();
            case ChildAgentOperation.RequestGame:
                if (payload.Length != 0) throw new InvalidDataException("Only the fixed Minecraft Dungeons app request is supported.");
                RequestGame(); return Status();
            case ChildAgentOperation.StopSteam:
                if (payload.Length != 0) throw new InvalidDataException("Steam stop has no payload.");
                StopSteam(); return Status();
            default: throw new InvalidOperationException("This child operation is not available without verified ownership.");
        }
    }
    private sealed class SelectedCapabilities
    { internal string Address, Display, Audio; }
    private static SelectedCapabilities ParseSelection(string payload, bool lan)
    {
        if (payload == null || payload.Length > 1024 || (lan && payload.Length == 0))
            throw new InvalidDataException("Child capability selection is malformed.");
        if (payload.Length == 0) return new SelectedCapabilities();
        var values = new JavaScriptSerializer().DeserializeObject(payload) as IDictionary<string, object>;
        object display, audio, address = null;
        if (values == null || values.Count != (lan ? 3 : 2) ||
            !values.TryGetValue("display", out display) || !values.TryGetValue("audio", out audio) ||
            (lan && !values.TryGetValue("address", out address)) ||
            !(display is string) || !(audio is string) ||
            ((string)display).Length > 64 || ((string)audio).Length > 256 ||
            (lan && !(address is string)))
            throw new InvalidDataException("Child capability selection has unexpected fields.");
        return new SelectedCapabilities { Display = (string)display, Audio = (string)audio,
            Address = lan ? (string)address : null };
    }
    private string Capabilities()
    {
        string log = environment.DiscoverDisplayLog(child);
        var displays = new List<object>();
        foreach (SunshineDisplayObservation display in SunshineDisplayCatalog.ParseOwnedLog(log))
            if (display.Active) displays.Add(new { id = display.Id, name = display.Name });
        ChildAudioEndpointInventory audio = environment.ReadAudio(child);
        if (audio == null || !audio.Complete || audio.SessionId != child.SessionId)
            throw new InvalidOperationException("Child audio endpoint inventory is incomplete.");
        var endpoints = new List<string>(audio.ActiveRenderIds);
        endpoints.Sort(StringComparer.Ordinal);
        return new JavaScriptSerializer().Serialize(new { displays = displays, audio = endpoints });
    }
    private string Status()
    {
        if (sunshineIdentity == null && environment.HasUnresolvedStartIntent(child)) uncertain = true;
        if (!uncertain) ObservePendingGame();
        string state = uncertain ? "Uncertain" : sunshineIdentity == null ?
            (boundaryWithdrawn ? "SunshineWithdrawn" : "NoSunshine") :
            sunshine != null && sunshine.VerifyRunning() ? "SunshineReady" : "SunshineLost";
        if (state == "SunshineReady")
            try { owner.AssertStillOwned(); }
            catch (InvalidOperationException) { state = "SunshineBoundaryLost"; }
        return new JavaScriptSerializer().Serialize(new Dictionary<string, object> {
            { "stage", state }, { "childSession", child.SessionId }, { "childLogon", child.LogonTime },
            { "host", "ChildStream" }, { "manualAddress", state == "SunshineReady" ?
                (lanAddress ?? "127.0.0.1") + ":" + family.BasePort : "" },
            { "lanPosture", boundaryWithdrawn ? "Withdrawn" : lanAddress == null ? "LocalOnly" :
                state == "SunshineReady" ? "ScopedRulesVerified" : "ChangedOrUnavailable" },
            { "steamStage", steam == null ? "NotStarted" : steam.Stage.ToString() }
        });
    }
    private void StartSteam()
    {
        if (steam != null) throw new InvalidOperationException("Steam already has an owned or uncertain start outcome.");
        if (sunshineIdentity == null || owner == null) throw new InvalidOperationException("Verified child streaming runtime is required.");
        owner.AssertStillOwned();
        SteamInstallation installed = environment.ReadSteamInstallation();
        SteamLaunchObservation observed = environment.ReadSteamObservation(child, parentSessionId);
        if (installed == null || String.IsNullOrEmpty(installed.SteamPath) ||
            String.IsNullOrEmpty(installed.GamePath) || observed == null)
            throw new InvalidOperationException("Steam and Minecraft Dungeons installation could not be verified.");
        string conflict = SteamChildPolicy.Check(observed.Complete, observed.ParentSteam,
            observed.UnrelatedSteam, observed.ChildSteam);
        if (conflict != null) throw new InvalidOperationException(conflict);
        steamInstallation = installed;
        steam = new SteamChildRuntime(environment.Processes, child, installed.SteamPath,
            installed.SteamSha256, installed.GamePath, installed.GameSha256);
        environment.RecordSteamIntent(child);
        try
        {
            steam.StartBigPicture(observed.Complete, observed.ParentSteam, observed.UnrelatedSteam, observed.ChildSteam);
            environment.RecordSteamStarted(child, steam.SteamIdentity);
        }
        catch { uncertain = true; environment.RecordRuntimeUncertainty(child, "SteamStartUnknown"); throw; }
    }
    private void RequestGame()
    {
        if (steam == null || steam.Stage != SteamChildStage.BigPictureStarted)
            throw new InvalidOperationException("Verified child Steam Big Picture is required.");
        SteamLaunchObservation observed = environment.ReadSteamObservation(child, parentSessionId);
        if (observed == null) throw new InvalidOperationException("Steam ownership observation is unavailable.");
        environment.RecordGameRequest(child);
        try
        {
            steam.RequestMinecraftDungeons(observed.Complete, observed.ParentSteam, observed.UnrelatedSteam);
            ObservePendingGame();
        }
        catch { uncertain = true; environment.RecordRuntimeUncertainty(child, "GameRequestUnknown"); throw; }
    }
    private bool ObservePendingGame()
    {
        if (steam == null || steam.Stage != SteamChildStage.GameRequested) return false;
        ProductProcessIdentity game = environment.ReadGameProcess(child, steamInstallation);
        if (game == null) return false;
        try
        {
            steam.ObserveGame(game); // Exact path, image, session and generation check.
            environment.RecordGameObserved(child, game); // Durable before any stop.
            return true;
        }
        catch { uncertain = true; environment.RecordRuntimeUncertainty(child, "GameRequestUnknown"); throw; }
    }
    private void StopSteam()
    {
        if (steam == null) throw new InvalidOperationException("No exact owned Steam process exists.");
        try
        {
            if (steam.Stage == SteamChildStage.GameRequested && !ObservePendingGame())
                throw new InvalidOperationException("Game launch outcome is still uncertain; Steam is not stopped.");
            ProductProcessIdentity steamProcess = steam.SteamIdentity, gameProcess = steam.GameIdentity;
            if (steam.Stage == SteamChildStage.GameObserved) steam.StopGame(5000);
            steam.StopSteam(5000);
            environment.ResolveSteamStopped(child, steamProcess, gameProcess);
            steam = null; steamInstallation = null;
        }
        catch { uncertain = true; environment.RecordRuntimeUncertainty(child, "SteamStopUnknown"); throw; }
    }
    private string StartSunshine(string requestedLanAddress, SelectedCapabilities selected)
    {
        if (sunshineIdentity != null)
        {
            if (!String.Equals(lanAddress, requestedLanAddress, StringComparison.Ordinal))
                throw new InvalidOperationException("The running Sunshine instance has a different network posture.");
            owner.AssertStillOwned(); return Status();
        } // Reconnect never duplicates the owned process.
        if (requestedLanAddress != null)
        {
            new SunshineLanCandidate { Child = child, BindAddress = requestedLanAddress,
                Port = family.BasePort }.Validate();
            if (!environment.VerifyLanBoundary(requestedLanAddress, family))
                throw new InvalidOperationException("Exact ChildStream LAN rules and physical network are not verified.");
        }
        SunshineCollisionSnapshot collision = environment.ReadCollision(family);
        string conflict = SunshineStartupGate.CheckFamilyAvailable(collision, family);
        if (conflict != null) throw new InvalidOperationException(conflict);
        string log = environment.DiscoverDisplayLog(child);
        SunshineDisplayObservation display = null;
        if (selected.Display == null) display = SunshineDisplayCatalog.RequireUniqueActive(log);
        else
        {
            foreach (SunshineDisplayObservation candidate in SunshineDisplayCatalog.ParseOwnedLog(log))
                if (candidate.Active && String.Equals(candidate.Id, selected.Display,
                    StringComparison.OrdinalIgnoreCase)) display = candidate;
            if (display == null) throw new InvalidOperationException("Selected child display is absent or inactive.");
        }
        ChildAudioEndpointInventory audio = environment.ReadAudio(child);
        if (audio == null || !audio.Complete || audio.SessionId != child.SessionId)
            throw new InvalidOperationException("Child audio endpoint inventory is incomplete.");
        string audioId = selected.Audio;
        if (audioId == null)
        {
            if (audio.ActiveRenderIds.Count != 1)
                throw new InvalidOperationException("Multiple or no child audio endpoints require explicit selection.");
            foreach (string value in audio.ActiveRenderIds) audioId = value;
        }
        if (!audio.ActiveRenderIds.Contains(audioId))
            throw new InvalidOperationException("Selected child audio endpoint is not active in this child session.");
        identity = environment.OpenIdentity();
        bool startIntentRecorded = false;
        try
        {
            SunshineAdminCredential credential = identity.GetOrCreateCredentials();
            string establishedCertificate = null;
            try { establishedCertificate = identity.ReadCertificateSha256(); }
            catch (FileNotFoundException) { } // Only an absent first-start file may appear later.
            var options = new ChildProductOptions { ParentSessionId = parentSessionId,
                Child = child, OwnedInstallationRoot = environment.DataRoot,
                OwnedRoot = Path.Combine(environment.DataRoot, "sessions", child.SessionId + "-" + child.LogonTime),
                DisplayDeviceId = display.Id, DisplayActiveInChild = display.Active,
                AudioEndpointId = audioId, AudioInventory = audio,
                Capture = CaptureBackend.DesktopDuplication, Port = family.BasePort,
                BindAddress = requestedLanAddress ?? "127.0.0.1",
                LanCandidate = requestedLanAddress == null ? null : new SunshineLanCandidate {
                    Child = child, BindAddress = requestedLanAddress, Port = family.BasePort,
                    BoundaryVerified = true } };
            environment.EnsureGenerationFile(child, "apps.json", ChildProductConfiguration.BuildApps());
            string config = environment.EnsureGenerationFile(child,
                requestedLanAddress == null ? "sunshine.conf" : "sunshine-lan.conf",
                ChildProductConfiguration.BuildSunshine(options));
            environment.RecordStartIntent(child);
            startIntentRecorded = true;
            sunshine = new ChildOwnedProcess(environment.Processes, child,
                environment.SunshineExecutable, SunshineReleasePin.ExecutableSha256);
            sunshine.Start("\"" + config + "\"");
            sunshineIdentity = sunshine.Identity;
            environment.RecordStarted(child, sunshineIdentity);
            var pendingOwner = new VerifiedChildSunshineRuntime(environment, child,
                sunshineIdentity, identity, family, establishedCertificate, requestedLanAddress);
            string readyCertificate = null;
            for (int i = 0; i < 50; i++)
            {
                if (!sunshine.VerifyRunning()) throw new InvalidOperationException("Owned Sunshine exited before certificate readiness.");
                try
                {
                    pendingOwner.AssertProcessAndListener();
                    readyCertificate = identity.ReadCertificateSha256();
                    if (establishedCertificate != null && !String.Equals(readyCertificate,
                        establishedCertificate, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Existing owned Sunshine certificate changed on startup.");
                    break;
                }
                catch (SunshineNotReadyException) { }
                catch (FileNotFoundException) { if (establishedCertificate != null) throw; }
                catch (InvalidDataException) { if (establishedCertificate != null) throw; }
                Thread.Sleep(100);
            }
            if (readyCertificate == null)
                throw new InvalidOperationException("Owned Sunshine did not expose a complete certificate and pairing listener.");
            owner = new VerifiedChildSunshineRuntime(environment, child, sunshineIdentity,
                identity, family, readyCertificate, requestedLanAddress);
            owner.AssertStillOwned();
            pairing = environment.CreatePairingTransport(new Uri("https://127.0.0.1:" + (family.BasePort + 1) + "/"),
                readyCertificate, credential, owner);
            if (!identity.HasSunshineCredentials)
            {
                if (!pairing.BootstrapFirstCredentials()) throw new InvalidOperationException("Owned Sunshine credential bootstrap was refused.");
            }
            pairing.Send("GET", "/api/pin", null); // Authenticated readiness, never native Sunshine.
            lanAddress = requestedLanAddress;
            boundaryWithdrawn = false;
            if (requestedLanAddress != null)
            {
                monitoringLan = true;
                monitor.Start(SuperviseLan);
            }
            return Status();
        }
        catch
        {
            uncertain = startIntentRecorded;
            if (!startIntentRecorded) { identity.Dispose(); identity = null; }
            throw;
        }
    }
    private void StopSunshine()
    {
        if (sunshine == null || sunshineIdentity == null) throw new InvalidOperationException("No exact owned Sunshine process exists.");
        try
        {
            // Exact process identity is sufficient to stop an owned process even
            // if the LAN boundary has drifted and pairing/status are blocked.
            sunshine.Stop(5000);
            environment.ResolveStopped(child, sunshineIdentity);
            monitoringLan = false; monitor.Stop();
            sunshine = null; sunshineIdentity = null; pairing = null; owner = null; lanAddress = null;
            identity.Dispose(); identity = null;
        }
        catch { uncertain = true; throw; }
    }
    private void SuperviseLan()
    {
        lock (gate)
        {
            try { if (monitoringLan) SuperviseLanLocked(); }
            catch { /* The durable uncertainty and command status retain the failure. */ }
        }
    }
    private void SuperviseLanLocked()
    {
        if (!monitoringLan || sunshine == null || owner == null) return;
        try { owner.AssertStillOwned(); return; }
        catch
        {
            // Invalidate pairing before attempting an exact-owned stop. A
            // changed PID, generation or token can never be killed by name.
            pairing = null; owner = null; monitoringLan = false; monitor.Stop();
            try
            {
                sunshine.Stop(5000);
                environment.ResolveStopped(child, sunshineIdentity);
                sunshine = null; sunshineIdentity = null; lanAddress = null;
                if (identity != null) { identity.Dispose(); identity = null; }
                boundaryWithdrawn = true;
            }
            catch
            {
                uncertain = true;
                environment.RecordRuntimeUncertainty(child, "LanWithdrawalUnknown");
            }
        }
    }
    private void RecoverSunshine()
    {
        if (steam != null)
            throw new InvalidOperationException("Steam or game state requires separate reviewed recovery.");
        ProductProcessIdentity exact = sunshineIdentity ?? environment.ReadStarted(child);
        if (exact == null)
            throw new InvalidOperationException("No durable exact Sunshine identity exists; an intent-only start needs reviewed process enumeration.");
        ChildOwnedProcess controlled = sunshine;
        if (controlled == null)
        {
            controlled = new ChildOwnedProcess(environment.Processes, child,
                environment.SunshineExecutable, SunshineReleasePin.ExecutableSha256);
            ProductProcessIdentity current = environment.Processes.Read(exact.Pid);
            if (current != null) controlled.Attach(exact);
        }
        // Stop validates PID, creation time, session, path and digest before a
        // close request. An absent PID is handled by the durable record check.
        if (environment.Processes.Read(exact.Pid) != null) controlled.Stop(5000);
        environment.ResolveFailedStart(child, exact);
        monitoringLan = false; monitor.Stop();
        sunshine = null; sunshineIdentity = null; pairing = null; owner = null; lanAddress = null;
        if (identity != null) { identity.Dispose(); identity = null; }
        uncertain = false;
    }
    public void Dispose()
    {
        lock (gate) DisposeLocked();
    }
    private void DisposeLocked()
    {
        monitoringLan = false; monitor.Dispose();
        if (steam != null)
            try { StopSteam(); }
            catch { try { environment.RecordRuntimeUncertainty(child, "AgentExitWithSteamUnknown"); } catch { } }
        if (sunshine != null)
            try
            {
                sunshine.Stop(5000);
                environment.ResolveStopped(child, sunshineIdentity);
                sunshine = null; sunshineIdentity = null;
            }
            catch { } // Never kill by name or if exact ownership has drifted.
        if (identity != null) identity.Dispose();
    }
}
