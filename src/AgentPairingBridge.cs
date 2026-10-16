using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

internal sealed class AgentSunshinePairingApi : ISunshinePairingApi
{
    private readonly ChildAgentController controller;
    internal AgentSunshinePairingApi(ChildAgentController controller)
    { if (controller == null) throw new ArgumentNullException("controller"); this.controller = controller; }
    public string GetPendingJson() { return controller.Execute(ChildAgentOperation.PairingGet, ""); }
    public string SubmitPinJson(string requestJson)
    { return controller.Execute(ChildAgentOperation.PairingPost, requestJson); }
}

internal sealed class VerifiedAgentSunshine : IVerifiedChildSunshine
{
    private readonly ChildAgentController controller;
    private readonly ChildSessionIdentity child;
    internal VerifiedAgentSunshine(ChildAgentController controller, ChildSessionIdentity child)
    { if (controller == null) throw new ArgumentNullException("controller"); this.controller = controller; this.child = child; }
    private IDictionary<string, object> Status()
    {
        if (!controller.Reconcile()) throw new InvalidOperationException("Exact child agent is no longer verified.");
        string json = controller.Execute(ChildAgentOperation.Status, "");
        var status = new JavaScriptSerializer().DeserializeObject(json) as IDictionary<string, object>;
        object stage, session, logon, host, manual;
        if (status == null || !status.TryGetValue("stage", out stage) ||
            !status.TryGetValue("childSession", out session) || !status.TryGetValue("childLogon", out logon) ||
            !status.TryGetValue("host", out host) || !status.TryGetValue("manualAddress", out manual) ||
            !String.Equals(stage as string, "SunshineReady", StringComparison.Ordinal) ||
            Convert.ToUInt32(session) != child.SessionId || Convert.ToInt64(logon) != child.LogonTime ||
            !String.Equals(host as string, "ChildStream", StringComparison.Ordinal) ||
            String.IsNullOrWhiteSpace(manual as string))
            throw new InvalidDataException("Child agent has no verified ChildStream Sunshine runtime.");
        return status;
    }
    public string HostName { get { return (string)Status()["host"]; } }
    public string ManualAddress { get { return (string)Status()["manualAddress"]; } }
    public void AssertStillOwned() { Status(); }
}

// The normal parent application uses one controller for local readiness,
// approved LAN transition and recovery. It never changes a machine-wide rule.
internal sealed class ChildStreamingJourney
{
    private readonly ChildAgentController controller;
    private readonly ChildSessionIdentity child;
    internal ChildStreamingJourney(ChildAgentController controller, ChildSessionIdentity child)
    { if (controller == null) throw new ArgumentNullException("controller");
      this.controller = controller; this.child = child; }
    internal IDictionary<string, object> ReadStatus()
    {
        if (!controller.Reconcile()) throw new InvalidOperationException("Exact child agent is no longer verified.");
        var state = new JavaScriptSerializer().DeserializeObject(
            controller.Execute(ChildAgentOperation.Status, "")) as IDictionary<string, object>;
        object session, logon, stage, posture;
        if (state == null || !state.TryGetValue("childSession", out session) ||
            !state.TryGetValue("childLogon", out logon) ||
            !state.TryGetValue("stage", out stage) || !state.TryGetValue("lanPosture", out posture) ||
            Convert.ToUInt32(session) != child.SessionId || Convert.ToInt64(logon) != child.LogonTime ||
            !(stage is string) || !(posture is string))
            throw new InvalidDataException("Exact child streaming status is incomplete.");
        return state;
    }
    internal IVerifiedChildSunshine Start(string selectionJson, bool approvedLan)
    {
        IDictionary<string, object> status = ReadStatus();
        string stage = (string)status["stage"], posture = (string)status["lanPosture"];
        if (stage == "Uncertain" || stage == "SunshineLost" || stage == "SunshineBoundaryLost")
            throw new InvalidOperationException("Owned runtime state requires reviewed recovery before another start.");
        if (stage == "SunshineReady" &&
            ((approvedLan && posture == "ScopedRulesVerified") ||
             (!approvedLan && posture == "LocalOnly")))
        {
            if (!String.IsNullOrEmpty(selectionJson))
                throw new InvalidOperationException("Stop the owned stream before selecting different child devices.");
            var existing = new VerifiedAgentSunshine(controller, child);
            existing.AssertStillOwned();
            return existing;
        }
        if (stage == "SunshineReady" && approvedLan && posture == "LocalOnly")
            throw new InvalidOperationException("An explicit approved stop is required before changing network posture.");
        else if (stage == "SunshineReady" &&
            ((approvedLan && posture != "ScopedRulesVerified") ||
             (!approvedLan && posture != "LocalOnly")))
            throw new InvalidOperationException("A different running network posture requires an explicit stop.");
        controller.Execute(approvedLan ? ChildAgentOperation.StartSunshineLan :
            ChildAgentOperation.StartSunshine, selectionJson);
        var verified = new VerifiedAgentSunshine(controller, child);
        verified.AssertStillOwned();
        return verified;
    }
    internal string RecoverFailedStart()
    {
        string stage = (string)ReadStatus()["stage"];
        if (stage != "Uncertain" && stage != "SunshineLost" && stage != "SunshineBoundaryLost")
            throw new InvalidOperationException("No lost or uncertain owned Sunshine requires recovery.");
        return controller.Execute(ChildAgentOperation.RecoverSunshine, "");
    }
    internal string Stop()
    {
        if ((string)ReadStatus()["stage"] != "SunshineReady")
            throw new InvalidOperationException("No verified owned Sunshine process is available to stop.");
        return controller.Execute(ChildAgentOperation.StopSunshine, "");
    }
}

internal sealed class ChildStreamingPreparation
{
    internal ChildCapabilityCatalog Catalog;
    internal string Stage, Posture, Address;
}

// The same presenter is called by the real WinForms actions and the connected
// fixture. Discovery is read-only with respect to the owned runtime; consent
// to interrupt is required only after the user has selected child devices.
internal sealed class ChildStreamingPresenter
{
    private readonly ChildAgentController controller;
    private readonly ChildStreamingJourney journey;
    internal ChildStreamingPresenter(ChildAgentController controller, ChildSessionIdentity child)
    { this.controller = controller; journey = new ChildStreamingJourney(controller, child); }
    internal IDictionary<string, object> Observe() { return journey.ReadStatus(); }
    internal ChildStreamingPreparation Prepare(string address)
    {
        var status = Observe();
        string stage = (string)status["stage"];
        if (stage != "NoSunshine" && stage != "SunshineWithdrawn" && stage != "SunshineReady")
            throw new InvalidOperationException("Reconcile the current owned runtime before device selection.");
        if (stage == "SunshineReady" && (string)status["lanPosture"] != "LocalOnly" && address == null)
            throw new InvalidOperationException("Stop approved LAN streaming before local diagnostics.");
        string choices = controller.Execute(ChildAgentOperation.Capabilities, "");
        return new ChildStreamingPreparation { Catalog = ChildCapabilityCatalog.Parse(choices),
            Stage = stage, Posture = (string)status["lanPosture"], Address = address };
    }
    internal IVerifiedChildSunshine Commit(ChildStreamingPreparation prepared,
        string display, string audio, bool approvedInterruption)
    {
        if (prepared == null || prepared.Catalog == null)
            throw new InvalidDataException("A verified child device preparation is required.");
        var now = Observe();
        if ((string)now["stage"] != prepared.Stage || (string)now["lanPosture"] != prepared.Posture)
            throw new InvalidOperationException("Child runtime changed during device selection; prepare again.");
        string payload = prepared.Catalog.SelectionPayload(display, audio, prepared.Address);
        if (prepared.Stage == "SunshineReady")
        {
            if (!approvedInterruption)
                throw new InvalidOperationException("Interrupting the owned stream requires explicit approval.");
            journey.Stop(); // Exact owned process only; child, game and pairing identity remain.
        }
        return journey.Start(payload, prepared.Address != null);
    }
    internal string Stop() { return journey.Stop(); }
    internal string Recover() { return journey.RecoverFailedStart(); }
    internal string OpenGameAudioRoute()
    {
        var state = Observe();
        if ((string)state["steamStage"] != "GameObserved" || (string)state["stage"] != "SunshineReady")
            throw new InvalidOperationException("The exact child game and owned Sunshine must be running before setting its route.");
        return controller.Execute(ChildAgentOperation.OpenGameAudioRoute, "");
    }
}
