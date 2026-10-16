using System;
using System.Drawing;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;

internal static class SetupBoundaryTests
{
    private sealed class Host : IFeasibilityHost
    {
        internal ProbeSnapshot State = Good();
        internal int Writes;
        internal bool FailAfterWrite;
        public bool HasAdministratorPrivilege { get { return true; } }
        public ProbeSnapshot Capture() { return Clone(State); }
        public ProbeSnapshot CaptureBoundary(bool confirmed) { return Clone(State); }
        public bool CompareExchangeChildFeature(bool expected, bool desired)
        {
            if (State.FeatureEnabled != expected) return false;
            Writes++; State.FeatureEnabled = desired;
            if (FailAfterWrite) throw new IOException("Injected uncertain native write");
            return true;
        }
        public ProbeConnectionResult ConnectWithoutPassword(Action observe, Action<ChildSessionIdentity> child)
        { throw new Exception("Setup must never connect a child."); }
        public bool LogoffExact(ChildSessionIdentity child)
        { throw new Exception("Setup must never sign out a child."); }
    }
    private sealed class Store : IProbeStore
    {
        internal ProbeJournal Journal;
        public ProbeJournal Load() { return Journal; }
        public void Save(ProbeJournal journal) { Journal = journal; }
        public ProbeJournal ResolveInterruptedReplacement() { return Journal; }
    }
    private sealed class Lock : ITransactionOwnership
    {
        public IDisposable Acquire() { return new MemoryStream(); }
    }
    private sealed class TaskStore : IChildAgentTaskStore
    {
        internal ChildAgentTaskDefinition Definition;
        internal int Created, Deleted;
        public bool Exists(string name) { return Definition != null; }
        public ChildAgentTaskDefinition Read(string name) { return Definition; }
        public void Create(string name, ChildAgentTaskDefinition definition)
        { Created++; Definition = new ChildAgentTaskDefinition {
            PrincipalSid = definition.PrincipalSid, Executable = definition.Executable,
            ExecutableSha256 = definition.ExecutableSha256, Arguments = definition.Arguments,
            Enabled = definition.Enabled, DemandOnly = definition.DemandOnly,
            InteractiveToken = definition.InteractiveToken, LimitedRunLevel = definition.LimitedRunLevel }; }
        public void Delete(string name) { Deleted++; Definition = null; }
    }
    private sealed class Workflow : ISetupWorkflow
    {
        public string Execute(SetupRequest request) { return "Plan " + new string('a',64) + "; feature=False"; }
        public void RegisterOwnAgentTask() { }
        public void RemoveOwnAgentTask() { }
    }
    private static ProbeSnapshot Good()
    {
        return new ProbeSnapshot { FeatureAccess = ResourceAccess.Accessible, FeatureEnabled = false,
            ChildAccess = ResourceAccess.Absent, ChildApiErrorCode = 0,
            IndependentNoUnexpectedSessions = true, SessionInventoryFingerprint = "sessions",
            ParentSessionId = 2, ConsoleSessionId = 2, ParentProtocolType = 0, ParentLogonTime = 100,
            AccountBinding = "requester-hash", Edition = "Professional", WindowsBuild = 26100,
            LocalRdpPostureAccepted = true, RdpPolicyDenied = true, TermServiceStopped = true,
            RdpListenersAbsent = true, FirewallObservationComplete = true,
            RdpRegistryFingerprint = "rdp", ListenerFingerprint = "listener",
            FirewallFingerprint = "firewall", DisplayFingerprint = "display", NativeResourceFingerprint = "native" };
    }
    private static ProbeSnapshot Clone(ProbeSnapshot x)
    {
        return new ProbeSnapshot { FormatVersion = x.FormatVersion, NetworkPosture = x.NetworkPosture,
            FeatureAccess = x.FeatureAccess, FeatureEnabled = x.FeatureEnabled,
            ChildAccess = x.ChildAccess, ChildApiErrorCode = x.ChildApiErrorCode,
            IndependentNoUnexpectedSessions = x.IndependentNoUnexpectedSessions,
            SessionInventoryFingerprint = x.SessionInventoryFingerprint,
            ParentSessionId = x.ParentSessionId, ConsoleSessionId = x.ConsoleSessionId,
            ParentProtocolType = x.ParentProtocolType, ParentLogonTime = x.ParentLogonTime,
            AccountBinding = x.AccountBinding, Edition = x.Edition, WindowsBuild = x.WindowsBuild,
            LocalRdpPostureAccepted = x.LocalRdpPostureAccepted, RdpPolicyDenied = x.RdpPolicyDenied,
            TermServiceStopped = x.TermServiceStopped, RdpListenersAbsent = x.RdpListenersAbsent,
            FirewallObservationComplete = x.FirewallObservationComplete,
            RdpRegistryFingerprint = x.RdpRegistryFingerprint, ListenerFingerprint = x.ListenerFingerprint,
            FirewallFingerprint = x.FirewallFingerprint, DisplayFingerprint = x.DisplayFingerprint,
            NativeResourceFingerprint = x.NativeResourceFingerprint };
    }
    private static int checks;
    private static void Check(bool yes, string name) { checks++; if (!yes) throw new Exception(name); }
    private static void Reject(Action action, string name)
    { bool rejected = false; try { action(); } catch { rejected = true; } Check(rejected, name); }
    private static SetupRequest Request(SetupOperation operation, string hash)
    { return new SetupRequest { Operation = operation, ApprovedPlanHash = hash }; }
    [STAThread]
    public static int Main(string[] args)
    {
        var host = new Host(); var store = new Store();
        var transaction = new SetupTransaction(new FeasibilityProbe(host, store, new Lock()), store);
        host.State.LocalRdpPostureAccepted = false; // Protected connected host fixture.
        Reject(() => transaction.Execute(Request(SetupOperation.PlanConnected, ""), true),
            "connected-network firewall gate rejects planning");
        Check(host.Writes == 0 && store.Journal == null, "protected host has zero native writes/journal");
        host.State.LocalRdpPostureAccepted = true;
        string plan = transaction.Execute(Request(SetupOperation.PlanConnected, ""), true);
        string hash = plan.Substring(5, 64);
        Check(plan.Contains("feature=False") && hash.Length == 64, "read-only plan reaches native adapter fixture");
        Reject(() => transaction.Execute(Request(SetupOperation.BeginConnected, new string('b',64)), true),
            "forged plan hash rejected");
        Reject(() => transaction.Execute(Request(SetupOperation.BeginConnected, hash), false),
            "approval required before journal creation");
        Check(store.Journal == null && host.Writes == 0, "rejected approvals have no mutation");
        transaction.Execute(Request(SetupOperation.BeginConnected, hash), true);
        Check(store.Journal.Stage == ProbeStage.Captured, "approved exact plan journal is durable before native call");
        Check(transaction.Execute(Request(SetupOperation.ReadJournal, ""), true).Contains(hash),
            "requester journal can be read separately");
        host.State.AccountBinding = "different-requester";
        Reject(() => transaction.Execute(Request(SetupOperation.PrepareFeature, hash), true),
            "requester-account drift blocks feature write");
        Check(host.Writes == 0, "account drift causes zero native writes");
        host.State.AccountBinding = "requester-hash";
        transaction.Execute(Request(SetupOperation.PrepareFeature, hash), true);
        Check(host.Writes == 1 && host.State.FeatureEnabled && store.Journal.Stage == ProbeStage.AwaitFreshParent,
            "approved fixture reaches feature adapter with pre/post journal");
        transaction.Execute(Request(SetupOperation.RestoreOriginal, hash), true);
        Check(host.Writes == 2 && !host.State.FeatureEnabled && store.Journal.Stage == ProbeStage.Restored,
            "exact original feature restored and verified");
        var interruptedHost = new Host { FailAfterWrite = true };
        var interruptedStore = new Store();
        var interrupted = new SetupTransaction(new FeasibilityProbe(interruptedHost, interruptedStore,
            new Lock()), interruptedStore);
        string interruptedHash = interrupted.Execute(Request(SetupOperation.PlanConnected, ""), true).Substring(5,64);
        interrupted.Execute(Request(SetupOperation.BeginConnected, interruptedHash), true);
        Reject(() => interrupted.Execute(Request(SetupOperation.PrepareFeature, interruptedHash), true),
            "injected crash after native API remains uncertain");
        Check(interruptedHost.Writes == 1 && interruptedStore.Journal.Stage == ProbeStage.PreparedEnable,
            "write intent persisted before uncertain native result");
        interruptedHost.FailAfterWrite = false;
        Reject(() => interrupted.Execute(Request(SetupOperation.RestoreOriginal, interruptedHash), true),
            "ambiguous feature outcome requires reviewed recovery acknowledgement");
        Check(interruptedHost.Writes == 1, "ambiguous restore does not silently write");
        interrupted.Execute(Request(SetupOperation.ReviewedRestore, interruptedHash), true);
        Check(interruptedHost.Writes == 2 && !interruptedHost.State.FeatureEnabled &&
            interruptedStore.Journal.Stage == ProbeStage.Restored,
            "separately reviewed uncertain enable can restore exact original");
        var taskStore = new TaskStore();
        string sid = "S-1-5-21-100-200-300-1001";
        var expected = new ChildAgentTaskDefinition { PrincipalSid = sid, Executable = @"C:\Program Files\ChildStream\ChildStream.exe",
            ExecutableSha256 = new string('a',64), Arguments = "-child-agent $(Arg0)",
            Enabled = true, DemandOnly = true, InteractiveToken = true, LimitedRunLevel = true };
        var installer = new ChildAgentTaskInstaller(taskStore, expected);
        Reject(() => installer.EnsureRegistered(false), "ordinary task registration requires approval");
        installer.EnsureRegistered(true); installer.EnsureRegistered(true);
        Check(taskStore.Created == 1, "demand-only task registration reconciles exactly");
        Check(installer.IsRegisteredExactly(), "exact task is read-only approval for unknown feature attempt");
        taskStore.Definition.RunningInstances = 1;
        Reject(() => installer.Remove(true), "running agent cannot be unregistered");
        taskStore.Definition.RunningInstances = 0;
        taskStore.Definition.Arguments = "-evil";
        Reject(() => installer.IsRegisteredExactly(), "changed task cannot approve unknown feature attempt");
        Reject(() => installer.Remove(true), "foreign task action cannot be removed");
        taskStore.Definition.Arguments = expected.Arguments;
        installer.Remove(true); Check(taskStore.Deleted == 1, "exact stopped task removed");
        using (var bytes = new MemoryStream())
        {
            SetupWire.SendRequest(bytes, Request(SetupOperation.BeginConnected, hash));
            bytes.Position = 0;
            Check(SetupWire.ReadRequest(bytes).ApprovedPlanHash == hash, "bounded typed setup wire round trip");
        }
        Reject(() => Request((SetupOperation)255, "").Validate(), "arbitrary helper operation rejected");
        var requester = new ProductProcessIdentity { Pid = 71, SessionId = 2,
            StartTimeUtcTicks = 901, ExecutablePath = @"C:\Program Files\ChildStream\ChildStream.exe",
            ExecutableSha256 = hash };
        var requesterToken = new ProcessTokenObservation { Sid = sid, Elevation = RuntimeTokenStatus.Limited };
        SetupPeerPolicy.RequireRequester(requester, requesterToken, 71, 2, sid,
            requester.ExecutablePath, hash);
        SetupPeerPolicy.RequireElevatedConsole(RuntimeTokenStatus.Elevated, true, 2, 2, 2);
        var otherAdmin = new ProcessTokenObservation { Sid = "S-1-5-21-100-200-300-2002",
            Elevation = RuntimeTokenStatus.Elevated };
        var helper = new ProductProcessIdentity { Pid = 72, SessionId = 2, StartTimeUtcTicks = 902,
            ExecutablePath = @"C:\Program Files\ChildStream\ChildStreamSetup.exe",
            ExecutableSha256 = hash };
        SetupPeerPolicy.RequireAuthenticatedHelper(helper, otherAdmin, 72, 2, helper.ExecutablePath, hash);
        Check(otherAdmin.Sid != requesterToken.Sid, "over-the-shoulder Administrator stays distinct from requester");
        requesterToken.Sid = otherAdmin.Sid;
        Reject(() => SetupPeerPolicy.RequireRequester(requester, requesterToken, 71, 2, sid,
            requester.ExecutablePath, hash), "wrong requesting SID rejected");
        requesterToken.Sid = sid; requesterToken.Elevation = RuntimeTokenStatus.Elevated;
        Reject(() => SetupPeerPolicy.RequireRequester(requester, requesterToken, 71, 2, sid,
            requester.ExecutablePath, hash), "elevated requester rejected");
        requesterToken.Elevation = RuntimeTokenStatus.Limited;
        Reject(() => SetupPeerPolicy.RequireRequester(requester, requesterToken, 71, 2, sid,
            @"C:\Program Files\ChildStream\foreign.exe", hash), "substituted application path rejected");
        Reject(() => SetupPeerPolicy.RequireRequester(requester, requesterToken, 71, 3, sid,
            requester.ExecutablePath, hash), "wrong requester session rejected");
        Reject(() => SetupPeerPolicy.RequireElevatedConsole(RuntimeTokenStatus.Elevated, false, 2, 2, 2),
            "elevated non-Administrator helper rejected");
        Reject(() => SetupPeerPolicy.RequireAuthenticatedHelper(helper,
            new ProcessTokenObservation { Sid = sid, Elevation = RuntimeTokenStatus.Limited },
            72, 2, helper.ExecutablePath, hash), "limited helper rejected");
        Reject(() => SetupPeerPolicy.RequireAuthenticatedHelper(helper, otherAdmin, 72, 2,
            @"C:\Program Files\ChildStream\foreign.exe", hash), "substituted helper path rejected");
        var protectedAcl = new FileSecurity();
        protectedAcl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        protectedAcl.SetAccessRuleProtection(true, false);
        protectedAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-544"),
            FileSystemRights.FullControl, AccessControlType.Allow));
        protectedAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"),
            FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        SetupInstallTrust.VerifyProtectedAcl(protectedAcl);
        Check(true, "standard-user read/execute ACE is safe for protected code");
        foreach (FileSystemRights right in new [] { FileSystemRights.WriteData, FileSystemRights.AppendData,
            FileSystemRights.WriteAttributes, FileSystemRights.WriteExtendedAttributes,
            FileSystemRights.Delete, FileSystemRights.DeleteSubdirectoriesAndFiles,
            FileSystemRights.ChangePermissions, FileSystemRights.TakeOwnership })
        {
            var writable = new FileSecurity();
            writable.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
            writable.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"),
                right, AccessControlType.Allow));
            Reject(() => SetupInstallTrust.VerifyProtectedAcl(writable),
                "untrusted mutation right rejected: " + right);
        }
        var wrongOwner = new FileSecurity();
        wrongOwner.SetOwner(new SecurityIdentifier("S-1-5-32-545"));
        Reject(() => SetupInstallTrust.VerifyProtectedAcl(wrongOwner), "untrusted code owner rejected");
        using (var malformed = new MemoryStream(new byte[] { (byte)SetupOperation.PrepareFeature, 255 }))
            Reject(() => SetupWire.ReadRequest(malformed), "oversized setup request rejected before allocation");
        if (args.Length == 1)
        {
            Application.EnableVisualStyles(); Directory.CreateDirectory(args[0]);
            using (var form = new SetupDialog(new Workflow(), true))
            using (var image = new Bitmap(form.Width, form.Height))
            {
                form.StartPosition = FormStartPosition.Manual; form.Location = new Point(-2000, -2000);
                form.Show(); Application.DoEvents();
                form.DrawToBitmap(image, new Rectangle(0, 0, image.Width, image.Height));
                image.Save(Path.Combine(args[0], "setup-simulated.png")); form.Hide();
            }
        }
        Console.WriteLine("Scoped setup/transaction/task assertions passed: " + checks);
        return 0;
    }
}
