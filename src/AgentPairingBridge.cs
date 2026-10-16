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
    private IDictionary<string, object> ReadStatus()
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
        {
            controller.Execute(ChildAgentOperation.StopSunshine, "");
            if ((string)ReadStatus()["stage"] != "NoSunshine")
                throw new InvalidOperationException("Local Sunshine stop was not reconciled before LAN start.");
        }
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
        if ((string)ReadStatus()["stage"] != "Uncertain")
            throw new InvalidOperationException("No uncertain ChildStream startup requires recovery.");
        return controller.Execute(ChildAgentOperation.RecoverSunshine, "");
    }
    internal string Stop()
    {
        if ((string)ReadStatus()["stage"] != "SunshineReady")
            throw new InvalidOperationException("No verified owned Sunshine process is available to stop.");
        return controller.Execute(ChildAgentOperation.StopSunshine, "");
    }
}
