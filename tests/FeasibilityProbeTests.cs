using System;
using System.IO;

internal static class FeasibilityProbeTests
{
    private static int assertions;
    private sealed class FakeHost : IFeasibilityHost
    {
        internal ProbeSnapshot State = Base();
        internal bool Admin = true, FailBeforeFeature, FailAfterFeature, FailRestore, FailConnectAfterChild,
            FailLogoffAfterChild, CredentialPrompt;
        internal int FeatureWrites, Connections, Logoffs;
        internal ChildSessionIdentity TestChild = new ChildSessionIdentity(31, 200);
        public bool HasAdministratorPrivilege { get { return Admin; } }
        public ProbeSnapshot Capture() { return Clone(State); }
        public bool CompareExchangeChildFeature(bool expected, bool desired)
        {
            if (State.FeatureEnabled != expected) return false;
            if (FailBeforeFeature || (FailRestore && !desired)) throw new IOException("Before feature write");
            FeatureWrites++; State.FeatureEnabled = desired;
            if (FailAfterFeature) throw new IOException("After feature write");
            return true;
        }
        public ProbeConnectionResult ConnectWithoutPassword()
        {
            Connections++; State.ChildAccess = ResourceAccess.Accessible; State.AssociatedChild = TestChild;
            if (FailConnectAfterChild) throw new IOException("After connection");
            return new ProbeConnectionResult { Outcome = CredentialPrompt ? ProbeConnectOutcome.CredentialPrompt : ProbeConnectOutcome.AutomaticLogon,
                Identity = TestChild, ErrorCode = CredentialPrompt ? 1326 : 0 };
        }
        public bool LogoffExact(ChildSessionIdentity expected)
        {
            Logoffs++;
            if (!State.AssociatedChild.HasValue || !State.AssociatedChild.Value.Equals(expected)) return false;
            State.ChildAccess = ResourceAccess.Absent; State.AssociatedChild = null;
            if (FailLogoffAfterChild) throw new IOException("After logoff");
            return true;
        }
    }

    private static ProbeSnapshot Base()
    {
        return new ProbeSnapshot { FeatureAccess = ResourceAccess.Accessible, FeatureEnabled = false,
            ChildAccess = ResourceAccess.Absent, ParentSessionId = 2, ConsoleSessionId = 2, ParentLogonTime = 100,
            AccountBinding = "sid-hash", Edition = "Professional", WindowsBuild = 26100, NetworkRdpClosed = true,
            RdpRegistryFingerprint = "registry-1", ListenerFingerprint = "listener-1", FirewallFingerprint = "firewall-1",
            DisplayFingerprint = "display-1", NativeResourceFingerprint = "native-1" };
    }
    private static ProbeSnapshot Clone(ProbeSnapshot x)
    {
        return new ProbeSnapshot { FeatureAccess = x.FeatureAccess, FeatureEnabled = x.FeatureEnabled,
            ChildAccess = x.ChildAccess, ParentSessionId = x.ParentSessionId, ConsoleSessionId = x.ConsoleSessionId,
            ParentLogonTime = x.ParentLogonTime, AccountBinding = x.AccountBinding, Edition = x.Edition,
            WindowsBuild = x.WindowsBuild, NetworkRdpClosed = x.NetworkRdpClosed,
            RdpRegistryFingerprint = x.RdpRegistryFingerprint, ListenerFingerprint = x.ListenerFingerprint,
            FirewallFingerprint = x.FirewallFingerprint, DisplayFingerprint = x.DisplayFingerprint,
            NativeResourceFingerprint = x.NativeResourceFingerprint, AssociatedChild = x.AssociatedChild };
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly string Root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "probe-" + Guid.NewGuid().ToString("N"));
        internal readonly FakeHost Host = new FakeHost();
        internal readonly IProbeStore Store;
        internal readonly FeasibilityProbe Probe;
        internal Fixture()
        {
            Directory.CreateDirectory(Root);
            Store = new FileProbeStore(Path.Combine(Root, "probe.journal"));
            Probe = new FeasibilityProbe(Host, Store, new FileTransactionOwnership(Path.Combine(Root, "probe.lock")));
        }
        internal ProbeJournal Begin()
        {
            ProbePlan plan = Probe.Plan(); return Probe.Begin(plan, plan.Hash, true);
        }
        internal ProbeJournal Ready()
        {
            Begin(); Probe.PrepareFeature(); Host.State.ParentLogonTime = 101;
            return Probe.ResumeAfterFreshLogon();
        }
        public void Dispose() { Directory.Delete(Root, true); }
    }
    private static void Check(bool value, string name)
    { assertions++; if (!value) throw new Exception("Assertion failed: " + name); }
    private static void Throws<T>(Action action, string name) where T : Exception
    { bool caught = false; try { action(); } catch (T) { caught = true; } Check(caught, name); }

    private static void PlanningAndApproval()
    {
        using (var f = new Fixture())
        {
            ProbePlan p = f.Probe.Plan();
            Check(p.NeedsEnable && p.Hash.Length == 64, "exact plan and feature need");
            Throws<InvalidOperationException>(() => f.Probe.Begin(p, "wrong", true), "wrong approval hash");
            Throws<InvalidOperationException>(() => f.Probe.Begin(p, p.Hash, false), "missing explicit consent");
            f.Host.State.FirewallFingerprint = "drift";
            Throws<InvalidOperationException>(() => f.Probe.Begin(p, p.Hash, true), "inventory drift before begin");
            f.Host.State.FirewallFingerprint = "firewall-1";
            f.Probe.Begin(p, p.Hash, true);
            Check(f.Store.Load().Stage == ProbeStage.Captured, "durable snapshot");
            Throws<InvalidOperationException>(() => f.Probe.Begin(p, p.Hash, true), "existing journal blocks repeat");
        }
        using (var f = new Fixture())
        {
            f.Host.State.ChildAccess = ResourceAccess.Unknown;
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "unknown child state blocks planning");
            f.Host.State.ChildAccess = ResourceAccess.Accessible;
            f.Host.State.AssociatedChild = new ChildSessionIdentity(31, 200);
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "existing child blocks planning");
            f.Host.State.ChildAccess = ResourceAccess.Absent; f.Host.State.AssociatedChild = null;
            f.Host.State.NetworkRdpClosed = false;
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "network RDP open blocks planning");
            f.Host.State.NetworkRdpClosed = true; f.Host.State.Edition = "Home";
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "unsupported edition blocks planning");
        }
    }

    private static void FeatureFailureAndRecovery()
    {
        using (var f = new Fixture())
        {
            f.Begin(); f.Host.Admin = false;
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(), "no automatic elevation");
            Check(f.Host.FeatureWrites == 0 && f.Store.Load().Stage == ProbeStage.Captured, "no write without privilege");
            f.Host.Admin = true; f.Host.FailBeforeFeature = true;
            Throws<IOException>(() => f.Probe.PrepareFeature(), "failure before feature mutation");
            Check(f.Store.Load().Stage == ProbeStage.PreparedEnable && !f.Host.State.FeatureEnabled, "prepared intent remains");
            Check(f.Probe.RestoreOriginal().Stage == ProbeStage.Restored, "restore after prewrite failure");
            Check(f.Host.FeatureWrites == 0, "no spurious restore write");
        }
        using (var f = new Fixture())
        {
            f.Begin(); f.Host.FailAfterFeature = true;
            Throws<IOException>(() => f.Probe.PrepareFeature(), "failure after feature mutation");
            Check(f.Store.Load().Stage == ProbeStage.PreparedEnable && f.Host.State.FeatureEnabled, "postwrite evidence persists");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(), "unverified enable intent needs recovery review");
            f.Host.FailAfterFeature = false; f.Host.FailRestore = true;
            Throws<IOException>(() => f.Probe.RestoreOriginal(true), "failed restoration reported");
            Check(f.Store.Load().Stage == ProbeStage.Restoring && f.Host.State.FeatureEnabled, "unresolved restoration persists");
            f.Host.FailRestore = false;
            Check(f.Probe.RestoreOriginal().Stage == ProbeStage.Restored && !f.Host.State.FeatureEnabled,
                "repeat recovery verifies original false state");
        }
        using (var f = new Fixture())
        {
            f.Host.State.FeatureEnabled = true; f.Begin();
            Check(f.Probe.PrepareFeature().Stage == ProbeStage.AwaitFreshParent && f.Host.FeatureWrites == 0,
                "preexisting enabled state preserved");
            Check(f.Probe.RestoreOriginal().Stage == ProbeStage.Restored && f.Host.State.FeatureEnabled,
                "original true state preserved");
        }
        using (var f = new Fixture())
        {
            f.Begin(); f.Host.State.FeatureEnabled = true;
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(true),
                "unplanned external feature change cannot be claimed as probe rollback");
        }
    }

    private static void FreshLogonAndConnection()
    {
        using (var f = new Fixture())
        {
            f.Begin(); f.Probe.PrepareFeature();
            Throws<InvalidOperationException>(() => f.Probe.ResumeAfterFreshLogon(), "same logon rejected");
            f.Host.State.ParentLogonTime = 101; f.Host.State.AccountBinding = "other-account";
            Throws<InvalidOperationException>(() => f.Probe.ResumeAfterFreshLogon(), "different account rejected");
            f.Host.State.AccountBinding = "sid-hash"; f.Probe.ResumeAfterFreshLogon();
            f.Host.State.ListenerFingerprint = "changed";
            Throws<InvalidOperationException>(() => f.Probe.ConnectOnce(), "RDP listener drift blocks connection");
            Check(f.Host.Connections == 0, "no connection after drift");
        }
        using (var f = new Fixture())
        {
            f.Ready(); f.Host.CredentialPrompt = true;
            Check(f.Probe.ConnectOnce().Stage == ProbeStage.OutcomeUnknown, "credential prompt is not success");
            Check(f.Store.Load().AuthenticationOutcome == "CredentialPrompt" && f.Store.Load().ErrorCode == 1326,
                "authentication evidence retained");
            Throws<InvalidOperationException>(() => f.Probe.ConnectOnce(), "one connection attempt only");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(), "child blocks restoration");
        }
        using (var f = new Fixture())
        {
            f.Ready(); f.Host.FailConnectAfterChild = true;
            Throws<IOException>(() => f.Probe.ConnectOnce(), "ambiguous creation reported");
            Check(f.Store.Load().Stage == ProbeStage.OutcomeUnknown && f.Host.Connections == 1,
                "ambiguous creation is durable and never retried");
            Throws<InvalidOperationException>(() => f.Probe.ConnectOnce(), "no second connection on ambiguity");
            Throws<InvalidOperationException>(() => f.Probe.EndPositiveChild(true), "unknown child cannot be torn down");
        }
    }

    private static void TeardownAndRollback()
    {
        using (var f = new Fixture())
        {
            f.Ready(); Check(f.Probe.ConnectOnce().Stage == ProbeStage.Connected, "automatic authentication and identity");
            Throws<InvalidOperationException>(() => f.Probe.EndPositiveChild(true), "console checkpoint required");
            f.Probe.ConfirmConsoleUsable(true);
            f.Host.State.AssociatedChild = new ChildSessionIdentity(32, 201);
            Throws<InvalidOperationException>(() => f.Probe.EndPositiveChild(true), "wrong child identity blocks teardown");
            Check(f.Host.Logoffs == 0, "wrong child never logged off");
            f.Host.State.AssociatedChild = f.Host.TestChild;
            Throws<InvalidOperationException>(() => f.Probe.EndPositiveChild(false), "teardown consent required");
            Check(f.Probe.EndPositiveChild(true).Stage == ProbeStage.ChildEnded && f.Host.Logoffs == 1,
                "one positively identified child ended");
            Check(f.Probe.RestoreOriginal().Stage == ProbeStage.Restored && !f.Host.State.FeatureEnabled,
                "feature restored and verified");
            f.Host.State.FeatureEnabled = true;
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(), "completed rollback is reverified");
        }
        using (var f = new Fixture())
        {
            f.Ready(); f.Probe.ConnectOnce(); f.Probe.ConfirmConsoleUsable(true);
            f.Host.FailLogoffAfterChild = true;
            Throws<IOException>(() => f.Probe.EndPositiveChild(true), "ambiguous logoff reported");
            Check(f.Store.Load().Stage == ProbeStage.TeardownPrepared && f.Host.Logoffs == 1,
                "destructive intent survives ambiguity");
            Throws<InvalidOperationException>(() => f.Probe.EndPositiveChild(true), "ambiguous logoff cannot repeat");
            Check(f.Probe.RestoreOriginal().Stage == ProbeStage.Restored, "feature can restore after verified absence");
        }
        using (var f = new Fixture())
        {
            f.Ready(); f.Probe.ConnectOnce(); f.Probe.ConfirmConsoleUsable(true);
            f.Host.State.ChildAccess = ResourceAccess.Unknown;
            Throws<InvalidOperationException>(() => f.Probe.EndPositiveChild(true), "uncertain child query blocks logoff");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(), "uncertain child blocks restore");
        }
    }

    private static void JournalAndOwnership()
    {
        using (var f = new Fixture())
        {
            ProbePlan plan = f.Probe.Plan();
            using (var lockHandle = new FileStream(Path.Combine(f.Root, "probe.lock"), FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None))
                Throws<InvalidOperationException>(() => f.Probe.Begin(plan, plan.Hash, true),
                    "another process ownership blocks begin");
            f.Probe.Begin(plan, plan.Hash, true);
            string path = Path.Combine(f.Root, "probe.journal");
            File.Copy(path, path + ".new");
            Throws<JournalStateException>(() => f.Probe.PrepareFeature(), "interrupted replacement blocks mutation");
            Check(f.Probe.ResolveInterruptedJournal().Stage == ProbeStage.Captured,
                "explicit locked journal repair retains snapshot");
            Check(f.Probe.PrepareFeature().Stage == ProbeStage.AwaitFreshParent,
                "operation can resume after explicit repair");
        }
        using (var f = new Fixture())
        {
            f.Begin();
            File.WriteAllBytes(Path.Combine(f.Root, "probe.journal"), new byte[] { 1, 2, 3 });
            Throws<JournalStateException>(() => f.Probe.PrepareFeature(), "corrupt journal blocks mutation");
            Check(f.Host.FeatureWrites == 0, "corrupt original snapshot never changes host");
        }
    }

    public static int Main()
    {
        try
        {
            PlanningAndApproval(); FeatureFailureAndRecovery(); FreshLogonAndConnection(); TeardownAndRollback();
            JournalAndOwnership();
            Console.WriteLine("Feasibility probe: " + assertions + " offline assertions passed."); return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
