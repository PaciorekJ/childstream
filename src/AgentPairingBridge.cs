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
