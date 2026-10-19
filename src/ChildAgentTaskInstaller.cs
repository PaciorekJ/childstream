using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;

// This is a per-user, interactive-token task. It needs no stored password and
// performs no feature, service, firewall, or driver change. Installation is an
// explicit ordinary-user action, never part of the Sunshine reconnect path.
internal interface IChildAgentTaskStore
{
    bool Exists(string taskName);
    ChildAgentTaskDefinition Read(string taskName);
    void Create(string taskName, ChildAgentTaskDefinition definition);
    void Delete(string taskName);
}

internal sealed class ChildAgentTaskDefinition
{
    internal string PrincipalSid, Executable, ExecutableSha256, Arguments;
    internal bool Enabled, DemandOnly, InteractiveToken, LimitedRunLevel;
    internal int RunningInstances;
}

internal static class ChildAgentTaskPolicy
{
    internal static string Name(string sid)
    {
        new SecurityIdentifier(sid); // Reject malformed caller-selected identities.
        return "ChildStream-" + sid + "-ChildAgent";
    }
    internal static string Sid(string account)
    {
        SecurityIdentifier sid;
        if (String.IsNullOrEmpty(account)) throw new InvalidOperationException("Task principal is absent.");
        try { sid = new SecurityIdentifier(account); }
        catch (ArgumentException) { sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier)); }
        return sid.Value;
    }
    internal static void RequireExact(ChildAgentTaskDefinition actual, ChildAgentTaskDefinition expected)
    {
        if (actual == null || expected == null || !actual.Enabled || !actual.DemandOnly ||
            !actual.InteractiveToken || !actual.LimitedRunLevel ||
            actual.PrincipalSid != expected.PrincipalSid ||
            !String.Equals(actual.Executable, expected.Executable, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(actual.ExecutableSha256, expected.ExecutableSha256, StringComparison.OrdinalIgnoreCase) ||
            actual.Arguments != expected.Arguments)
            throw new InvalidOperationException("The ChildStream task is missing or its exact ownership/definition changed.");
    }
}

internal sealed class ChildAgentTaskInstaller
{
    private readonly IChildAgentTaskStore store;
    private readonly ChildAgentTaskDefinition expected;
    internal ChildAgentTaskInstaller(IChildAgentTaskStore store, ChildAgentTaskDefinition expected)
    { this.store = store; this.expected = expected; }
    internal void EnsureRegistered(bool explicitConsent)
    {
        if (!explicitConsent) throw new InvalidOperationException("Explicit task setup approval is required.");
        string name = ChildAgentTaskPolicy.Name(expected.PrincipalSid);
        if (store.Exists(name)) { ChildAgentTaskPolicy.RequireExact(store.Read(name), expected); return; }
        store.Create(name, expected);
        ChildAgentTaskPolicy.RequireExact(store.Read(name), expected);
    }
    internal bool IsRegisteredExactly()
    {
        string name = ChildAgentTaskPolicy.Name(expected.PrincipalSid);
        if (!store.Exists(name)) return false;
        ChildAgentTaskPolicy.RequireExact(store.Read(name), expected);
        return true;
    }
    internal void Remove(bool explicitConsent)
    {
        if (!explicitConsent) throw new InvalidOperationException("Explicit task removal approval is required.");
        string name = ChildAgentTaskPolicy.Name(expected.PrincipalSid);
        if (!store.Exists(name)) return;
        ChildAgentTaskDefinition actual = store.Read(name);
        ChildAgentTaskPolicy.RequireExact(actual, expected);
        if (actual.RunningInstances != 0)
            throw new InvalidOperationException("The exact child agent is still running; task removal is blocked.");
        store.Delete(name);
        if (store.Exists(name)) throw new InvalidOperationException("Task removal could not be verified.");
    }
}

internal sealed class WindowsChildAgentTaskStore : IChildAgentTaskStore
{
    private readonly string userSid;
    internal WindowsChildAgentTaskStore(string userSid) { userSid = new SecurityIdentifier(userSid).Value; this.userSid = userSid; }
    private dynamic Root()
    {
        Type type = Type.GetTypeFromProgID("Schedule.Service");
        if (type == null) throw new InvalidOperationException("Task Scheduler is unavailable.");
        dynamic service = Activator.CreateInstance(type);
        service.Connect();
        return service.GetFolder("\\");
    }
    private void RequireName(string name)
    { if (name != ChildAgentTaskPolicy.Name(userSid)) throw new InvalidOperationException("Foreign task path rejected."); }
    public bool Exists(string name)
    {
        RequireName(name);
        try { dynamic task = Root().GetTask(name); return task != null; }
        catch (System.Runtime.InteropServices.COMException ex)
        {
            if ((uint)ex.ErrorCode == 0x80070002 || (uint)ex.ErrorCode == 0x8004130F) return false;
            throw;
        }
    }
    public ChildAgentTaskDefinition Read(string name)
    {
        RequireName(name);
        dynamic task = Root().GetTask(name);
        dynamic definition = task.Definition;
        if ((int)definition.Actions.Count != 1) throw new InvalidOperationException("Task action count changed.");
        dynamic action = definition.Actions.Item(1);
        if ((int)action.Type != 0) throw new InvalidOperationException("Task action type changed.");
        string executable = Path.GetFullPath((string)action.Path);
        string sha;
        using (var stream = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var hash = SHA256.Create())
            sha = BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "");
        return new ChildAgentTaskDefinition {
            PrincipalSid = ChildAgentTaskPolicy.Sid((string)definition.Principal.UserId),
            Executable = executable, ExecutableSha256 = sha,
            Arguments = (string)action.Arguments,
            Enabled = (bool)task.Enabled && (bool)definition.Settings.Enabled,
            DemandOnly = (int)definition.Triggers.Count == 0 && (bool)definition.Settings.AllowDemandStart,
            InteractiveToken = (int)definition.Principal.LogonType == 3,
            LimitedRunLevel = (int)definition.Principal.RunLevel == 0,
            RunningInstances = (int)task.GetInstances(0).Count
        };
    }
    public void Create(string name, ChildAgentTaskDefinition expected)
    {
        RequireName(name);
        if (Exists(name)) throw new InvalidOperationException("ChildStream task appeared during setup.");
        if (expected.PrincipalSid != userSid || expected.Arguments != "-child-agent $(Arg0)" ||
            !expected.Enabled || !expected.DemandOnly || !expected.InteractiveToken || !expected.LimitedRunLevel)
            throw new InvalidOperationException("Only the fixed limited child-agent task can be registered.");
        if (!String.Equals(Path.GetFullPath(expected.Executable), expected.Executable, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Task executable path must be canonical.");
        dynamic root = Root();
        Type type = Type.GetTypeFromProgID("Schedule.Service");
        dynamic service = Activator.CreateInstance(type); service.Connect();
        dynamic definition = service.NewTask(0);
        definition.RegistrationInfo.Description = "ChildStream exact-session, demand-only limited child agent";
        definition.Principal.UserId = userSid;
        definition.Principal.LogonType = 3;
        definition.Principal.RunLevel = 0;
        definition.Settings.Enabled = true;
        definition.Settings.AllowDemandStart = true;
        definition.Settings.StartWhenAvailable = false;
        definition.Settings.MultipleInstances = 2; // Ignore new; controller also verifies exact peer.
        definition.Settings.ExecutionTimeLimit = "PT8H";
        dynamic action = definition.Actions.Create(0);
        action.Path = expected.Executable;
        action.Arguments = expected.Arguments;
        string acl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + userSid + ")";
        root.RegisterTaskDefinition(name, definition, 2, userSid, null, 3, acl);
    }
    public void Delete(string name)
    { RequireName(name); Root().DeleteTask(name, 0); }
}

internal static class WindowsChildAgentTaskSetup
{
    internal static ChildAgentTaskInstaller ForCurrentLimitedUser()
    {
        if (new WindowsRuntimeTokenReader().Read() != RuntimeTokenStatus.Limited)
            throw new UnauthorizedAccessException("Child agent task setup requires the ordinary unelevated user token.");
        string executable = Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName);
        string installed = SetupInstallTrust.RequireOwnedPath("ChildStream.exe");
        if (!String.Equals(executable, installed, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Install ChildStream in its protected Program Files directory before task setup.");
        string digest;
        using (var stream = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var sha = SHA256.Create())
            digest = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
        string sid = WindowsIdentity.GetCurrent().User.Value;
        var expected = new ChildAgentTaskDefinition { PrincipalSid = sid, Executable = executable,
            ExecutableSha256 = digest, Arguments = "-child-agent $(Arg0)",
            Enabled = true, DemandOnly = true, InteractiveToken = true, LimitedRunLevel = true };
        return new ChildAgentTaskInstaller(new WindowsChildAgentTaskStore(sid), expected);
    }
}
