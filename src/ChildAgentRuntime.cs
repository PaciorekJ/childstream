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
    IList<SunshineListener> ReadListeners(int pid, SunshinePortFamily family, out bool complete);
    IChildSunshineIdentity OpenIdentity();
    IChildSunshineTransport CreatePairingTransport(Uri endpoint, string certificateSha256,
        SunshineAdminCredential credential, IVerifiedChildSunshine owner);
    string EnsureGenerationFile(ChildSessionIdentity child, string name, string content);
    void RecordStartIntent(ChildSessionIdentity child);
    void RecordStarted(ChildSessionIdentity child, ProductProcessIdentity process);
    void ResolveStopped(ChildSessionIdentity child, ProductProcessIdentity process);
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

internal sealed class VerifiedChildSunshineRuntime : IVerifiedChildSunshine
{
    private readonly IChildRuntimeEnvironment environment;
    private readonly ChildSessionIdentity child;
    private readonly ProductProcessIdentity expected;
    private readonly IChildSunshineIdentity identity;
    private readonly SunshinePortFamily family;
    private readonly string certificateSha256;
    internal VerifiedChildSunshineRuntime(IChildRuntimeEnvironment environment, ChildSessionIdentity child,
        ProductProcessIdentity expected, IChildSunshineIdentity identity, SunshinePortFamily family)
    { this.environment = environment; this.child = child; this.expected = expected;
      this.identity = identity; this.family = family;
      certificateSha256 = identity.ReadCertificateSha256(); }
    public string HostName { get { AssertStillOwned(); return "ChildStream"; } }
    public string ManualAddress { get { AssertStillOwned(); return "127.0.0.1:" + family.BasePort; } }
    public void AssertStillOwned()
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
        string problem = SunshineRuntimeGate.CheckCandidate(complete, expected.Pid, "127.0.0.1", family, listeners);
        if (problem != null) throw new InvalidOperationException(problem);
        bool webUi = false;
        foreach (var endpoint in listeners)
            if (endpoint.Protocol == "TCP" && endpoint.Port == family.BasePort + 1 &&
                endpoint.Pid == expected.Pid && endpoint.LocalAddress == "127.0.0.1") webUi = true;
        if (!webUi) throw new InvalidOperationException("ChildStream HTTPS pairing listener is not owned by this process.");
        if (!String.Equals(identity.ReadCertificateSha256(), certificateSha256,
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ChildStream Sunshine certificate identity changed.");
    }
}

internal sealed class ChildAgentRuntime : IChildAgentOperations
{
    private readonly ChildSessionIdentity child;
    private readonly uint parentSessionId;
    private readonly IChildRuntimeEnvironment environment;
    private readonly SunshinePortFamily family = new SunshinePortFamily(48089);
    private ChildOwnedProcess sunshine;
    private ProductProcessIdentity sunshineIdentity;
    private IChildSunshineIdentity identity;
    private IChildSunshineTransport pairing;
    private VerifiedChildSunshineRuntime owner;
    private bool uncertain;
    private SteamChildRuntime steam;
    private SteamInstallation steamInstallation;
    internal ChildAgentRuntime(ChildSessionIdentity child, uint parentSessionId, IChildRuntimeEnvironment environment)
    {
        if (child.SessionId == 0 || child.LogonTime <= 0 || parentSessionId == 0 ||
            parentSessionId == child.SessionId || environment == null)
            throw new InvalidDataException("Exact child and production environment are required.");
        this.child = child; this.parentSessionId = parentSessionId; this.environment = environment;
    }
    private void RequireChild()
    {
        if (environment.Processes.CurrentSessionId != (int)child.SessionId ||
            environment.Processes.ReadSessionLogonTime((int)child.SessionId) != child.LogonTime)
            throw new InvalidOperationException("Runtime left the exact child logon generation.");
    }
    public string Execute(ChildAgentOperation operation, string payload)
    {
        RequireChild();
        if (uncertain) throw new InvalidOperationException("Runtime ownership is uncertain; reviewed recovery is required.");
        if (payload == null) payload = "";
        switch (operation)
        {
            case ChildAgentOperation.Status:
                if (payload.Length != 0) throw new InvalidDataException("Status has no payload.");
                return Status();
            case ChildAgentOperation.StartSunshine:
                if (payload.Length != 0) throw new InvalidDataException("Sunshine start has no caller-selected executable or configuration.");
                return StartSunshine();
            case ChildAgentOperation.StopSunshine:
                if (payload.Length != 0) throw new InvalidDataException("Sunshine stop has no payload.");
                StopSunshine(); return Status();
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
    private string Status()
    {
        string state = uncertain ? "Uncertain" : sunshineIdentity == null ? "NoSunshine" :
            sunshine != null && sunshine.VerifyRunning() ? "SunshineReady" : "SunshineLost";
        return new JavaScriptSerializer().Serialize(new Dictionary<string, object> {
            { "stage", state }, { "childSession", child.SessionId }, { "childLogon", child.LogonTime },
            { "host", "ChildStream" }, { "manualAddress", state == "SunshineReady" ? "127.0.0.1:48089" : "" },
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
            ProductProcessIdentity game = environment.ReadGameProcess(child, steamInstallation);
            if (game != null)
            { steam.ObserveGame(game); environment.RecordGameObserved(child, game); }
        }
        catch { uncertain = true; environment.RecordRuntimeUncertainty(child, "GameRequestUnknown"); throw; }
    }
    private void StopSteam()
    {
        if (steam == null) throw new InvalidOperationException("No exact owned Steam process exists.");
        if (steam.Stage == SteamChildStage.GameRequested)
        {
            ProductProcessIdentity game = environment.ReadGameProcess(child, steamInstallation);
            if (game == null) throw new InvalidOperationException("Game launch outcome is still uncertain; Steam is not stopped.");
            steam.ObserveGame(game);
        }
        ProductProcessIdentity steamProcess = steam.SteamIdentity, gameProcess = steam.GameIdentity;
        try
        {
            if (steam.Stage == SteamChildStage.GameObserved) steam.StopGame(5000);
            steam.StopSteam(5000);
            environment.ResolveSteamStopped(child, steamProcess, gameProcess);
            steam = null; steamInstallation = null;
        }
        catch { uncertain = true; environment.RecordRuntimeUncertainty(child, "SteamStopUnknown"); throw; }
    }
    private string StartSunshine()
    {
        if (sunshineIdentity != null)
        { owner.AssertStillOwned(); return Status(); } // Reconnect never duplicates the owned process.
        SunshineCollisionSnapshot collision = environment.ReadCollision(family);
        string conflict = SunshineStartupGate.CheckFamilyAvailable(collision, family);
        if (conflict != null) throw new InvalidOperationException(conflict);
        string log = environment.DiscoverDisplayLog(child);
        SunshineDisplayObservation display = SunshineDisplayCatalog.RequireUniqueActive(log);
        ChildAudioEndpointInventory audio = environment.ReadAudio(child);
        if (audio == null || !audio.Complete || audio.SessionId != child.SessionId || audio.ActiveRenderIds.Count != 1)
            throw new InvalidOperationException("Exactly one active child audio endpoint must be observed before automatic start.");
        string audioId = null; foreach (string value in audio.ActiveRenderIds) audioId = value;
        identity = environment.OpenIdentity();
        bool startIntentRecorded = false;
        try
        {
            SunshineAdminCredential credential = identity.GetOrCreateCredentials();
            var options = new ChildProductOptions { ParentSessionId = parentSessionId,
                Child = child, OwnedInstallationRoot = environment.DataRoot,
                OwnedRoot = Path.Combine(environment.DataRoot, "sessions", child.SessionId + "-" + child.LogonTime),
                DisplayDeviceId = display.Id, DisplayActiveInChild = display.Active,
                AudioEndpointId = audioId, AudioInventory = audio,
                Capture = CaptureBackend.DesktopDuplication, Port = family.BasePort,
                BindAddress = "127.0.0.1" };
            environment.EnsureGenerationFile(child, "apps.json", ChildProductConfiguration.BuildApps());
            string config = environment.EnsureGenerationFile(child, "sunshine.conf", ChildProductConfiguration.BuildSunshine(options));
            environment.RecordStartIntent(child);
            startIntentRecorded = true;
            sunshine = new ChildOwnedProcess(environment.Processes, child,
                environment.SunshineExecutable, SunshineReleasePin.ExecutableSha256);
            sunshine.Start("\"" + config + "\"");
            sunshineIdentity = sunshine.Identity;
            environment.RecordStarted(child, sunshineIdentity);
            owner = new VerifiedChildSunshineRuntime(environment, child, sunshineIdentity, identity, family);
            bool ready = false;
            for (int i = 0; i < 30; i++)
            {
                try { owner.AssertStillOwned(); ready = true; break; }
                catch { Thread.Sleep(100); }
            }
            if (!ready) throw new InvalidOperationException("Owned Sunshine did not expose its verified pairing listener and certificate.");
            pairing = environment.CreatePairingTransport(new Uri("https://127.0.0.1:" + (family.BasePort + 1) + "/"),
                identity.ReadCertificateSha256(), credential, owner);
            if (!identity.HasSunshineCredentials)
            {
                if (!pairing.BootstrapFirstCredentials()) throw new InvalidOperationException("Owned Sunshine credential bootstrap was refused.");
            }
            pairing.Send("GET", "/api/pin", null); // Authenticated readiness, never native Sunshine.
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
            if (sunshine.VerifyRunning()) owner.AssertStillOwned();
            sunshine.Stop(5000);
            environment.ResolveStopped(child, sunshineIdentity);
            sunshine = null; sunshineIdentity = null; pairing = null; owner = null;
            identity.Dispose(); identity = null;
        }
        catch { uncertain = true; throw; }
    }
    public void Dispose()
    {
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
