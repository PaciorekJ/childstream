using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

internal static class FeasibilityProbeTests
{
    private static int assertions;
    private sealed class FakeHost : IFeasibilityHost
    {
        internal ProbeSnapshot State = Base();
        internal bool Admin = true, FailBeforeFeature, FailAfterFeature, FailRestore, FailConnectAfterChild,
            FailLogoffAfterChild, CredentialPrompt, LoseNetworkAfterFeature, StartRdpAfterFeature;
        internal int FeatureWrites, Connections, Logoffs;
        internal ChildSessionIdentity TestChild = new ChildSessionIdentity(31, 200);
        public bool HasAdministratorPrivilege { get { return Admin; } }
        public ProbeSnapshot Capture() { return Clone(State); }
        public bool CompareExchangeChildFeature(bool expected, bool desired)
        {
            if (State.FeatureEnabled != expected) return false;
            if (FailBeforeFeature || (FailRestore && !desired)) throw new IOException("Before feature write");
            FeatureWrites++; State.FeatureEnabled = desired;
            if (desired && LoseNetworkAfterFeature) State.NetworkIsolationAccepted = false;
            if (desired && StartRdpAfterFeature)
            {
                State.TermServiceStopped = false;
                State.RdpListenersAbsent = false;
                State.ListenerFingerprint = "listener-started";
            }
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
            ChildAccess = ResourceAccess.Absent, ChildApiErrorCode = 0,
            IndependentNoUnexpectedSessions = true, SessionInventoryFingerprint = "session-inventory-1",
            ParentSessionId = 2, ConsoleSessionId = 2, ParentProtocolType = 0, ParentLogonTime = 100,
            AccountBinding = "sid-hash", Edition = "Professional", WindowsBuild = 26100, LocalRdpPostureAccepted = true,
            RdpPolicyDenied = true, TermServiceStopped = true, RdpListenersAbsent = true,
            FirewallObservationComplete = true,
            RdpRegistryFingerprint = "registry-1", ListenerFingerprint = "listener-1", FirewallFingerprint = "firewall-1",
            DisplayFingerprint = "display-1", NativeResourceFingerprint = "native-1" };
    }
    private static ProbeSnapshot Clone(ProbeSnapshot x)
    {
        return new ProbeSnapshot { FormatVersion = x.FormatVersion, NetworkPosture = x.NetworkPosture,
            OperatorConfirmedIsolation = x.OperatorConfirmedIsolation,
            FeatureAccess = x.FeatureAccess, FeatureEnabled = x.FeatureEnabled,
            ChildAccess = x.ChildAccess, ChildApiErrorCode = x.ChildApiErrorCode,
            IndependentNoUnexpectedSessions = x.IndependentNoUnexpectedSessions,
            SessionInventoryFingerprint = x.SessionInventoryFingerprint,
            ParentSessionId = x.ParentSessionId, ConsoleSessionId = x.ConsoleSessionId,
            ParentProtocolType = x.ParentProtocolType,
            ParentLogonTime = x.ParentLogonTime, AccountBinding = x.AccountBinding, Edition = x.Edition,
            WindowsBuild = x.WindowsBuild, LocalRdpPostureAccepted = x.LocalRdpPostureAccepted,
            RdpPolicyDenied = x.RdpPolicyDenied, TermServiceStopped = x.TermServiceStopped,
            RdpListenersAbsent = x.RdpListenersAbsent,
            FirewallObservationComplete = x.FirewallObservationComplete,
            NetworkIsolationAccepted = x.NetworkIsolationAccepted, NetworkFingerprint = x.NetworkFingerprint,
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
        internal void SetIsolated()
        {
            Host.State.LocalRdpPostureAccepted = false;
            Host.State.NetworkIsolationAccepted = true;
            Host.State.NetworkFingerprint = "network-1";
        }
        internal ProbeJournal BeginIsolated()
        {
            SetIsolated();
            ProbePlan plan = Probe.Plan(ProbeNetworkPosture.NetworkIsolated, true);
            return Probe.Begin(plan, plan.Hash, true);
        }
        internal ProbeJournal Ready()
        {
            Begin(); Probe.PrepareFeature(); Host.State.ParentLogonTime = 101;
            ProbeJournal stageA = Probe.ResumeAfterFreshLogon();
            return Probe.ApproveStageB(stageA.Plan.Hash, true);
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
            Check(!File.Exists(Path.Combine(f.Root, "probe.lock")), "read-only planning creates no lock file");
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
            f.Host.State.LocalRdpPostureAccepted = false;
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "network RDP open blocks planning");
            f.Host.State.LocalRdpPostureAccepted = true; f.Host.State.Edition = "Home";
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "unsupported edition blocks planning");
            f.Host.State.Edition = "Professional"; f.Host.State.ParentProtocolType = 2;
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "remote RDP protocol cannot masquerade as console");
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

    private static void ObservedHostBoundary()
    {
        using (var f = new Fixture())
        {
            f.Host.State.ChildAccess = ResourceAccess.Unknown;
            f.Host.State.ChildApiErrorCode = 1168;
            f.Begin();
            Check(f.Probe.PrepareFeature().Stage == ProbeStage.AwaitFreshParent,
                "documented pre-feature 1168 can pass only with independent session evidence");
            f.Host.State.ParentLogonTime = 101;
            Check(f.Probe.ResumeAfterFreshLogon().Stage == ProbeStage.StageAQueryUnknown,
                "post-logon 1168 remains unknown");
            Throws<InvalidOperationException>(() => f.Probe.ApproveStageB(f.Store.Load().Plan.Hash, true),
                "unknown child query blocks Stage B");
            Check(f.Probe.RestoreOriginal().Stage == ProbeStage.Restored && !f.Host.State.FeatureEnabled,
                "Stage A only 1168 allows controlled feature restoration");
        }
        using (var f = new Fixture())
        {
            f.Host.State.ChildAccess = ResourceAccess.Unknown;
            f.Host.State.ChildApiErrorCode = 1168;
            f.Host.State.IndependentNoUnexpectedSessions = false;
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "1168 alone cannot establish child absence");
        }
        using (var f = new Fixture())
        {
            f.Begin(); f.Probe.PrepareFeature(); f.Host.State.ParentLogonTime = 101;
            Check(f.Probe.ResumeAfterFreshLogon().Stage == ProbeStage.StageAValidated,
                "positive API absence after fresh logon validates Stage A");
            Throws<InvalidOperationException>(() => f.Probe.ConnectOnce(), "Stage B cannot start before separate approval");
            Throws<InvalidOperationException>(() => f.Probe.ApproveStageB("wrong", true), "Stage B exact hash required");
            f.Probe.ApproveStageB(f.Store.Load().Plan.Hash, true);
            f.Host.State.LocalRdpPostureAccepted = false;
            Throws<InvalidOperationException>(() => f.Probe.ConnectOnce(), "new RDP exposure blocks connection");
            Check(f.Host.Connections == 0, "exposure never reaches adapter connect");
        }
    }

    private sealed class SyntheticInventory : IProbeInventory
    {
        internal string Json;
        public string ReadJson() { return Json; }
    }
    private sealed class SyntheticNative : IProbeNative
    {
        internal bool Feature, FailFeature;
        internal uint Child = uint.MaxValue;
        internal long Generation = 400;
        internal int FeatureWrites, Logoffs;
        public int LastError { get { return 5; } }
        public bool IsFeatureEnabled(out bool enabled) { enabled = Feature; return true; }
        public bool EnableFeature(bool enabled) { FeatureWrites++; if (FailFeature) return false; Feature = enabled; return true; }
        public bool GetChildId(out uint id) { id = Child; return true; }
        public long? LogonTime(uint id) { return id == Child ? (long?)Generation : null; }
        public bool Logoff(uint id) { Logoffs++; Child = uint.MaxValue; return true; }
    }
    private static Dictionary<string, object> SyntheticRule(string name, bool enabled, bool rdpNamed)
    {
        return new Dictionary<string, object> {
            { "Name", name }, { "Enabled", enabled ? (object)"True" : "False" },
            { "Direction", "Inbound" }, { "Action", "Allow" }, { "Profile", "Any" },
            { "Protocol", "TCP" }, { "LocalPort", new object[] { "Any" } },
            { "RemotePort", new object[] { "Any" } }, { "LocalAddress", new object[] { "Any" } },
            { "RemoteAddress", new object[] { "Any" } },
            { "ProgramState", enabled ? "Accessible" : "Any" },
            { "ProgramHash", enabled ? new string('b', 64) : null },
            { "PackageState", "Any" }, { "PackageHash", null }, { "Service", "Any" },
            { "InterfaceAliasHashes", new object[0] }, { "InterfaceType", "Any" },
            { "Authentication", "NotRequired" }, { "Encryption", "NotRequired" },
            { "OverrideBlockRules", "False" }, { "SecurityPrincipalHash", null },
            { "PolicyStoreSourceType", "Local" }, { "PolicyStoreSourceHash", new string('c', 64) },
            { "PrimaryStatus", "OK" }, { "StatusCode", 65536 },
            { "EnforcementStatus", new object[] { "Enforced" } }, { "RdpNamed", rdpNamed }
        };
    }
    private static string SyntheticJson()
    {
        var serializer = new JavaScriptSerializer();
        return serializer.Serialize(new {
            Schema = "ChildStream.ReadOnlyFeasibilityInventory.v2", HostMutation = false,
            Windows = new { State = "Accessible", Caption = "Microsoft Windows 11 Pro", BuildNumber = 26200 },
            AccountBindingHash = "synthetic-sid-hash",
            ChildFeature = new { State = "Accessible", Enabled = false, ErrorCode = 0 },
            Sessions = new {
                ProcessSessionId = 1, ActiveConsoleSessionId = 1,
                Current = new { State = "Accessible", SessionId = 1, LogonTime = 300L },
                CurrentProtocol = new { State = "Accessible", Value = 0, ErrorCode = 0 },
                AssociatedChild = new { State = "Unknown", SessionId = (int?)null, ErrorCode = 1168 },
                AssociatedChildDetails = (object)null,
                Enumerated = new { State = "Accessible", Items = new object[] {
                    new { SessionId = 0, ConnectionState = 4 }, new { SessionId = 1, ConnectionState = 0 } } }
            },
            Rdp = new {
                LocalDenyConnections = new { State = "Accessible", Data = 1 },
                PolicyDenyConnections = new { State = "Absent", Data = (int?)null },
                TcpPort = new { State = "Accessible", Data = 3389 },
                Services = new { State = "Accessible", Items = new object[] {
                    new { Name = "TermService", State = "Stopped", StartMode = "Manual" },
                    new { Name = "UmRdpService", State = "Stopped", StartMode = "Manual" },
                    new { Name = "SessionEnv", State = "Stopped", StartMode = "Manual" } },
                    TermServiceImageHash = new string('a', 64), TermServiceImageState = "Accessible",
                    TermServiceIsClassicHost = true },
                TcpListener = new { State = "Accessible", Items = new object[0] },
                UdpEndpoint = new { State = "Accessible", Items = new object[0] },
                FirewallProfiles = new { State = "Accessible", Items = new object[] {
                    new { Name = "Domain", Enabled = 1, DefaultInboundAction = 4 },
                    new { Name = "Private", Enabled = 1, DefaultInboundAction = 4 },
                    new { Name = "Public", Enabled = 1, DefaultInboundAction = 4 } } },
                Firewall = new { State = "Accessible", Items = new object[] {
                    SyntheticRule("RemoteDesktop-UserMode-In-TCP", false, true),
                    SyntheticRule("Sunshine", true, false) },
                    UnknownHeaderCount = 0, SelectedInboundAllowCount = 1, BroadInboundAllowCount = 1 }
            },
            Displays = new { State = "Accessible", Items = new object[] { new { Primary = true, Width = 3440, Height = 1440 } } },
            Sunshine = new { State = "Accessible", Services = new object[] { new { Name = "SunshineService", State = "Running" } } },
            Vdd = new { State = "Accessible", Items = new object[] {
                new { Name = "Virtual Display Driver", Class = "Display", InfName = "oem61.inf" } } }
        });
    }
    private static void WindowsAdapterSynthetic()
    {
        var input = new SyntheticInventory { Json = SyntheticJson() };
        var native = new SyntheticNative();
        var host = new WindowsFeasibilityHost(input, native, () => true);
        ProbeSnapshot s = host.Capture();
        Check(s.WindowsBuild == 26200 && s.ParentSessionId == 1 && s.ConsoleSessionId == 1,
            "synthetic Windows inventory mapped to console identity");
        Check(s.ChildAccess == ResourceAccess.Unknown && s.ChildApiErrorCode == 1168 &&
            s.IndependentNoUnexpectedSessions, "1168 preserved with independent session evidence");
        Check(s.LocalRdpPostureAccepted, "scoped Sunshine broad allowance does not masquerade as RDP allowance");
        Check(host.CompareExchangeChildFeature(false, true) && native.FeatureWrites == 1,
            "narrow feature write uses compare exchange");
        Check(!host.CompareExchangeChildFeature(false, true) && native.FeatureWrites == 1,
            "feature drift prevents second write");
        native.FailFeature = true;
        Throws<System.ComponentModel.Win32Exception>(() => host.CompareExchangeChildFeature(true, false),
            "feature API failure is surfaced");
        native.FailFeature = false;
        native.Child = 31;
        Check(!host.LogoffExact(new ChildSessionIdentity(31, 401)) && native.Logoffs == 0,
            "different logon generation cannot be logged off");
        Check(host.LogoffExact(new ChildSessionIdentity(31, 400)) && native.Logoffs == 1,
            "exact associated child may be logged off once");
        var denied = new WindowsFeasibilityHost(input, native, () => false);
        Throws<InvalidOperationException>(() => denied.CompareExchangeChildFeature(true, false),
            "adapter never elevates itself");
        var serializer = new JavaScriptSerializer();
        var document = (Dictionary<string, object>)serializer.DeserializeObject(SyntheticJson());
        var rdp = (Dictionary<string, object>)document["Rdp"];
        var firewall = (Dictionary<string, object>)rdp["Firewall"];
        var unscoped = SyntheticRule("Unscoped", true, false);
        unscoped["ProgramState"] = "Any"; unscoped["ProgramHash"] = null;
        firewall["Items"] = new object[] { unscoped };
        input.Json = serializer.Serialize(document);
        Check(!host.Capture().LocalRdpPostureAccepted, "unscoped broad firewall allow blocks local posture gate");
        rdp["Firewall"] = new { State = "Accessible", Items = new object[0],
            UnknownHeaderCount = 0, SelectedInboundAllowCount = 0, BroadInboundAllowCount = 0 };
        rdp["TcpListener"] = new { State = "Accessible", Items = new object[] { new { LocalPort = 3389 } } };
        input.Json = serializer.Serialize(document);
        Check(!host.Capture().LocalRdpPostureAccepted, "RDP listener blocks local posture gate");
        rdp["TcpListener"] = new { State = "Accessible", Items = new object[0] };
        var sessions = (Dictionary<string, object>)document["Sessions"];
        sessions["Enumerated"] = new { State = "Accessible", Items = new object[] {
            new { SessionId = 0 }, new { SessionId = 1 }, new { SessionId = 8 } } };
        input.Json = serializer.Serialize(document);
        Check(!host.Capture().IndependentNoUnexpectedSessions, "unexpected session blocks independent absence gate");
    }
    private static ProbeSnapshot FirewallSnapshot(Action<Dictionary<string, object>> change)
    {
        var serializer = new JavaScriptSerializer();
        var document = (Dictionary<string, object>)serializer.DeserializeObject(SyntheticJson());
        if (change != null) change(document);
        return WindowsFeasibilityHost.ParseInventory(serializer.Serialize(document));
    }
    private static Dictionary<string, object> RdpPart(Dictionary<string, object> document)
    { return (Dictionary<string, object>)document["Rdp"]; }
    private static Dictionary<string, object> SunshineRule(Dictionary<string, object> document)
    {
        var firewall = (Dictionary<string, object>)RdpPart(document)["Firewall"];
        return (Dictionary<string, object>)((object[])firewall["Items"])[1];
    }
    private static Dictionary<string, object> FirstProfile(Dictionary<string, object> document)
    {
        var profiles = (Dictionary<string, object>)RdpPart(document)["FirewallProfiles"];
        return (Dictionary<string, object>)((object[])profiles["Items"])[0];
    }
    private static void FirewallGateSynthetic()
    {
        ProbeSnapshot baseline = FirewallSnapshot(null);
        Check(baseline.LocalRdpPostureAccepted, "host-shaped numeric profile enums are accepted");
        ProbeSnapshot named = FirewallSnapshot(d => {
            foreach (object p in (object[])((Dictionary<string, object>)RdpPart(d)["FirewallProfiles"])["Items"])
            {
                var profile = (Dictionary<string, object>)p;
                profile["Enabled"] = "True"; profile["DefaultInboundAction"] = "Block";
            }
            SunshineRule(d)["Enabled"] = 1;
            SunshineRule(d)["Protocol"] = 6;
        });
        Check(named.LocalRdpPostureAccepted && baseline.FirewallFingerprint == named.FirewallFingerprint,
            "recognized enum representations share a deterministic firewall fingerprint");
        Check(!FirewallSnapshot(d => FirstProfile(d)["Enabled"] = 2).LocalRdpPostureAccepted,
            "disabled profile blocks");
        Check(!FirewallSnapshot(d => FirstProfile(d)["Enabled"] = 0).LocalRdpPostureAccepted,
            "NotConfigured profile is unknown and blocks");
        Check(!FirewallSnapshot(d => FirstProfile(d)["Enabled"] = "yes").LocalRdpPostureAccepted,
            "unrecognized profile state blocks");
        Check(!FirewallSnapshot(d => FirstProfile(d)["DefaultInboundAction"] = 2).LocalRdpPostureAccepted,
            "default inbound Allow blocks");
        Check(!FirewallSnapshot(d => FirstProfile(d)["DefaultInboundAction"] = "NotConfigured").LocalRdpPostureAccepted,
            "unknown default inbound action blocks");
        Check(!FirewallSnapshot(d => {
            var firewall = (Dictionary<string, object>)RdpPart(d)["Firewall"];
            firewall["UnknownHeaderCount"] = 1;
        }).LocalRdpPostureAccepted, "incomplete rule enumeration blocks");
        Check(!FirewallSnapshot(d => SunshineRule(d)["Direction"] = "Sideways").LocalRdpPostureAccepted,
            "unknown rule direction blocks");
        Check(!FirewallSnapshot(d => SunshineRule(d)["Action"] = "Maybe").LocalRdpPostureAccepted,
            "unknown rule action blocks");
        Check(!FirewallSnapshot(d => SunshineRule(d)["Profile"] = "Domain, Other").LocalRdpPostureAccepted,
            "unknown profile applicability blocks");
        Check(!FirewallSnapshot(d => {
            SunshineRule(d)["PrimaryStatus"] = "Unknown";
            SunshineRule(d)["ProgramState"] = "Any"; SunshineRule(d)["ProgramHash"] = null;
        }).LocalRdpPostureAccepted,
            "unknown active rule status blocks");
        Check(!FirewallSnapshot(d => {
            SunshineRule(d)["RemotePort"] = new object[] { "RPC" };
            SunshineRule(d)["ProgramState"] = "Any"; SunshineRule(d)["ProgramHash"] = null;
        }).LocalRdpPostureAccepted,
            "unresolved remote-port specification blocks");
        Check(!FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null;
        }).LocalRdpPostureAccepted, "unscoped broad TCP allow is potentially RDP permissive");
        Check(!FirewallSnapshot(d => {
            var firewall = (Dictionary<string, object>)RdpPart(d)["Firewall"];
            var rules = new object[21];
            rules[0] = ((object[])firewall["Items"])[0];
            for (int i = 1; i < rules.Length; i++)
            {
                var rule = SyntheticRule("AppLike-" + i, true, false);
                rule["ProgramState"] = "Any"; rule["ProgramHash"] = null;
                rule["PackageState"] = "Any"; rule["PackageHash"] = null;
                rule["OwnerKind"] = "AppPackage";
                if (i == 19) rule["LocalAddress"] = new object[] { "192.0.2.10" };
                if (i == 20) rule["LocalAddress"] = new object[] { "2001:db8::10" };
                rules[i] = rule;
            }
            firewall["Items"] = rules;
            firewall["SelectedInboundAllowCount"] = 20;
            firewall["BroadInboundAllowCount"] = 20;
        }).LocalRdpPostureAccepted,
            "twenty app-named or owner-tagged rules, including two specific local addresses, still block");
        Check(FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null;
            rule["PackageState"] = "AppPackage"; rule["PackageHash"] = new string('d', 64);
        }).LocalRdpPostureAccepted, "package-constrained rule excludes a classic TermService host");
        Check(!FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null;
            rule["PackageState"] = "AppPackage"; rule["PackageHash"] = new string('d', 64);
            ((Dictionary<string, object>)RdpPart(d)["Services"])["TermServiceIsClassicHost"] = false;
        }).LocalRdpPostureAccepted, "package exclusion requires classic service-host evidence");
        Check(!FirewallSnapshot(d => SunshineRule(d)["ProgramHash"] = new string('a', 64)).LocalRdpPostureAccepted,
            "allow for the TermService executable remains potentially permissive");
        Check(!FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null; rule["Service"] = "termservice";
        }).LocalRdpPostureAccepted, "TermService matching is case insensitive");
        Check(FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null; rule["Service"] = "OtherService";
        }).LocalRdpPostureAccepted, "other service binding excludes TermService");
        Check(FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null; rule["Protocol"] = "2";
        }).LocalRdpPostureAccepted, "non-TCP and non-UDP protocol excludes direct RDP");
        Check(FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null;
            rule["LocalPort"] = new object[] { "48010" };
            ((Dictionary<string, object>)RdpPart(d)["Firewall"])["BroadInboundAllowCount"] = 0;
        }).LocalRdpPostureAccepted, "different local port excludes configured RDP");
        Check(!FirewallSnapshot(d => {
            var rule = SunshineRule(d);
            rule["ProgramState"] = "Any"; rule["ProgramHash"] = null;
            rule["LocalPort"] = new object[] { "3380-3399" };
            ((Dictionary<string, object>)RdpPart(d)["Firewall"])["BroadInboundAllowCount"] = 0;
        }).LocalRdpPostureAccepted, "range including RDP port remains potentially permissive");
        ProbeSnapshot reordered = FirewallSnapshot(d => {
            Array.Reverse((object[])((Dictionary<string, object>)RdpPart(d)["FirewallProfiles"])["Items"]);
            Array.Reverse((object[])((Dictionary<string, object>)RdpPart(d)["Firewall"])["Items"]);
            Array.Reverse((object[])((Dictionary<string, object>)RdpPart(d)["Services"])["Items"]);
            Array.Reverse((object[])((Dictionary<string, object>)((Dictionary<string, object>)d["Sessions"])["Enumerated"])["Items"]);
        });
        Check(ProbeCodec.Hash(ProbeCodec.PlanBytes(baseline)) == ProbeCodec.Hash(ProbeCodec.PlanBytes(reordered)),
            "rule, profile, service, and session enumeration order does not change the plan hash");
        ProbeSnapshot drifted = FirewallSnapshot(d => SunshineRule(d)["RemoteAddress"] = new object[] { "LocalSubnet" });
        Check(baseline.FirewallFingerprint != drifted.FirewallFingerprint,
            "meaningful firewall address change changes approved inventory hash");
        ProbeSnapshot serviceDrift = FirewallSnapshot(d => {
            var services = (Dictionary<string, object>)RdpPart(d)["Services"];
            var term = (Dictionary<string, object>)((object[])services["Items"])[0];
            term["StartMode"] = "Automatic";
        });
        Check(baseline.ListenerFingerprint != serviceDrift.ListenerFingerprint,
            "meaningful service configuration drift changes approved inventory hash");
    }
    private static Dictionary<string, object> NetworkFixture()
    {
        var serializer = new JavaScriptSerializer();
        return (Dictionary<string, object>)serializer.DeserializeObject(serializer.Serialize(new {
            Adapters = new { State = "Accessible", Items = new object[] {
                new { InterfaceIndex = 5, Category = "Ethernet", Status = "Disconnected", MediaConnectionState = "Unknown" },
                new { InterfaceIndex = 6, Category = "WiFi", Status = "Disabled", MediaConnectionState = "Unknown" },
                new { InterfaceIndex = 7, Category = "VPN", Status = "Disabled", MediaConnectionState = "Unknown" },
                new { InterfaceIndex = 8, Category = "BluetoothPAN", Status = "Disabled", MediaConnectionState = "Unknown" },
                new { InterfaceIndex = 9, Category = "Mobile", Status = "Disabled", MediaConnectionState = "Unknown" },
                new { InterfaceIndex = 10, Category = "USB", Status = "Disabled", MediaConnectionState = "Unknown" },
                new { InterfaceIndex = 11, Category = "VirtualOrBridge", Status = "Disabled", MediaConnectionState = "Unknown" } } },
            IpInterfaces = new { State = "Accessible", Items = new object[] {
                new { InterfaceIndex = 1, CompartmentId = 1, AddressFamily = "IPv4", LoopbackAlias = true, ConnectionState = "Connected" },
                new { InterfaceIndex = 1, CompartmentId = 1, AddressFamily = "IPv6", LoopbackAlias = true, ConnectionState = "Connected" },
                new { InterfaceIndex = 5, CompartmentId = 1, AddressFamily = "IPv4", LoopbackAlias = false, ConnectionState = "Disconnected" },
                new { InterfaceIndex = 6, CompartmentId = 1, AddressFamily = "IPv4", LoopbackAlias = false, ConnectionState = "Disconnected" } } },
            IpAddresses = new { State = "Accessible", Items = new object[] {
                new { InterfaceIndex = 1, CompartmentId = 0, AddressFamily = "IPv4", Address = "127.0.0.1", PrefixLength = 8 },
                new { InterfaceIndex = 1, CompartmentId = 0, AddressFamily = "IPv6", Address = "::1", PrefixLength = 128 } } },
            Routes = new { State = "Accessible", Items = new object[] {
                new { InterfaceIndex = 1, CompartmentId = 1, AddressFamily = "IPv4", DestinationPrefix = "127.0.0.0/8", NextHop = "0.0.0.0" },
                new { InterfaceIndex = 1, CompartmentId = 1, AddressFamily = "IPv6", DestinationPrefix = "::1/128", NextHop = "::" } } }
        }));
    }
    private static Dictionary<string, object> NetworkPart(Dictionary<string, object> document)
    { return (Dictionary<string, object>)document["Network"]; }
    private static ProbeSnapshot IsolatedInventorySnapshot(Action<Dictionary<string, object>> change)
    {
        var serializer = new JavaScriptSerializer();
        var document = (Dictionary<string, object>)serializer.DeserializeObject(SyntheticJson());
        document["Schema"] = "ChildStream.ReadOnlyFeasibilityInventory.v3";
        document["Network"] = NetworkFixture();
        SunshineRule(document)["ProgramState"] = "Any";
        SunshineRule(document)["ProgramHash"] = null;
        if (change != null) change(document);
        return WindowsFeasibilityHost.ParseInventory(serializer.Serialize(document));
    }
    private static void NetworkGateSynthetic()
    {
        ProbeSnapshot baseline = IsolatedInventorySnapshot(null);
        Check(baseline.NetworkIsolationAccepted && !baseline.LocalRdpPostureAccepted,
            "verified isolation is independent from the connected-network firewall blocker");
        for (int i = 0; i < 7; i++)
        {
            int index = i;
            Check(!IsolatedInventorySnapshot(d => {
                var adapters = (Dictionary<string, object>)NetworkPart(d)["Adapters"];
                var adapter = (Dictionary<string, object>)((object[])adapters["Items"])[index];
                adapter["Status"] = "Up"; adapter["MediaConnectionState"] = "Connected";
            }).NetworkIsolationAccepted, "active Ethernet/Wi-Fi/VPN/PAN/mobile/USB/virtual adapter blocks: " + i);
        }
        Check(!IsolatedInventorySnapshot(d => {
            var routes = (Dictionary<string, object>)NetworkPart(d)["Routes"];
            routes["Items"] = new object[] { new { InterfaceIndex = 5, CompartmentId = 1, AddressFamily = "IPv4",
                DestinationPrefix = "192.0.2.0/24", NextHop = "0.0.0.0" } };
        }).NetworkIsolationAccepted, "active local-subnet route blocks even without a default route");
        Check(!IsolatedInventorySnapshot(d => {
            var addresses = (Dictionary<string, object>)NetworkPart(d)["IpAddresses"];
            addresses["Items"] = new object[] { new { InterfaceIndex = 6, CompartmentId = 0, AddressFamily = "IPv6",
                Address = "fe80::1", PrefixLength = 64 } };
        }).NetworkIsolationAccepted, "non-loopback link-local address blocks without a route");
        Check(!IsolatedInventorySnapshot(d => {
            var interfaces = (Dictionary<string, object>)NetworkPart(d)["IpInterfaces"];
            ((Dictionary<string, object>)((object[])interfaces["Items"])[2])["ConnectionState"] = "Connected";
        }).NetworkIsolationAccepted, "connected IP interface blocks even without an address or route");
        Check(!IsolatedInventorySnapshot(d => {
            ((Dictionary<string, object>)NetworkPart(d)["Routes"])["State"] = "Unknown";
        }).NetworkIsolationAccepted, "inaccessible route enumeration fails closed");
        Check(!IsolatedInventorySnapshot(d => {
            var adapters = (Dictionary<string, object>)NetworkPart(d)["Adapters"];
            ((Dictionary<string, object>)((object[])adapters["Items"])[0])["Status"] = "Mystery";
        }).NetworkIsolationAccepted, "unrecognized adapter status fails closed");
        Check(!IsolatedInventorySnapshot(d => {
            var adapters = (Dictionary<string, object>)NetworkPart(d)["Adapters"];
            ((Dictionary<string, object>)((object[])adapters["Items"])[0])["MediaConnectionState"] = "Connected";
        }).NetworkIsolationAccepted, "contradictory connected media blocks a disconnected adapter");
        ProbeSnapshot reordered = IsolatedInventorySnapshot(d => {
            foreach (string part in new[] { "Adapters", "IpInterfaces", "IpAddresses", "Routes" })
                Array.Reverse((object[])((Dictionary<string, object>)NetworkPart(d)[part])["Items"]);
        });
        Check(baseline.NetworkFingerprint == reordered.NetworkFingerprint,
            "network inventory ordering does not change the approved fingerprint");
        ProbeSnapshot drifted = IsolatedInventorySnapshot(d => {
            var adapters = (Dictionary<string, object>)NetworkPart(d)["Adapters"];
            ((Dictionary<string, object>)((object[])adapters["Items"])[1])["Status"] = "Disconnected";
            ((Dictionary<string, object>)((object[])adapters["Items"])[1])["MediaConnectionState"] = "Disconnected";
        });
        Check(drifted.NetworkIsolationAccepted && baseline.NetworkFingerprint != drifted.NetworkFingerprint,
            "safe-looking adapter-state drift still changes the approved fingerprint");
    }
    private static void IsolatedLifecycle()
    {
        using (var f = new Fixture())
        {
            f.SetIsolated();
            Throws<InvalidOperationException>(() => f.Probe.Plan(), "connected posture remains blocked by broad firewall allowances");
            Throws<InvalidOperationException>(() => f.Probe.Plan(ProbeNetworkPosture.NetworkIsolated, false),
                "operator isolation confirmation is mandatory");
            ProbePlan plan = f.Probe.Plan(ProbeNetworkPosture.NetworkIsolated, true);
            Check(plan.Original.FormatVersion == 4 && plan.Original.NetworkPosture == ProbeNetworkPosture.NetworkIsolated,
                "isolated posture and confirmation are bound into v4 plan");
            f.Host.State.NetworkFingerprint = "network-2";
            Throws<InvalidOperationException>(() => f.Probe.Begin(plan, plan.Hash, true),
                "network-state drift invalidates exact approved plan");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated();
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(),
                "connected prepare command cannot enable an isolated plan");
            f.Host.State.NetworkFingerprint = "network-2";
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(true),
                "network drift stops feature enablement");
            Check(f.Host.FeatureWrites == 0 && f.Store.Load().NetworkDeviationObserved,
                "prewrite network deviation is durably recorded without a feature write");
            f.Host.State.NetworkFingerprint = "network-1";
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(true),
                "recorded deviation prohibits resumed feature enablement");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(false, false, true),
                "ordinary restoration cannot ignore recorded deviation");
            Check(f.Probe.RestoreOriginal(false, true, true).Stage == ProbeStage.Restored,
                "reviewed recovery closes prewrite deviation after isolation is restored");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Host.State.FirewallFingerprint = "firewall-changed";
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(true),
                "isolated posture does not permit changing existing firewall rules");
            Check(f.Host.FeatureWrites == 0, "firewall drift blocks before feature enablement");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Host.LoseNetworkAfterFeature = true;
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(true),
                "network loss after non-atomic enablement stops progression");
            Check(f.Host.FeatureWrites == 1 && f.Store.Load().Stage == ProbeStage.PreparedEnable &&
                f.Store.Load().NetworkDeviationObserved, "enable intent and network deviation remain durable");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(true, true, true),
                "restoration is blocked while network isolation is lost");
            Check(f.Host.FeatureWrites == 1, "lost network causes no further feature write");
            f.Host.State.NetworkIsolationAccepted = true;
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(true, false, true),
                "restored isolation still requires reviewed recovery");
            Check(f.Probe.RestoreOriginal(true, true, true).Stage == ProbeStage.Restored &&
                !f.Host.State.FeatureEnabled && f.Store.Load().NetworkRecoveryReviewed,
                "reviewed same-account recovery verifies original feature state");
            Check(f.Probe.AssessReconnect(true).Ready,
                "reconnect check requires restored feature, isolation, and original infrastructure");
            Throws<InvalidOperationException>(() => f.Probe.ApproveStageB(f.Store.Load().Plan.Hash, true),
                "isolated Stage A journal can never authorize Stage B");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Host.StartRdpAfterFeature = true;
            Throws<InvalidOperationException>(() => f.Probe.PrepareFeature(true),
                "unexpected TermService or RDP listener stops Stage A after the feature write");
            Check(f.Store.Load().Stage == ProbeStage.PreparedEnable && f.Host.FeatureWrites == 1,
                "unexpected listener leaves a durable ambiguous enable intent");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(true, false, true),
                "feature restoration cannot clear unrelated service or listener drift");
            Check(!f.Host.State.FeatureEnabled && f.Store.Load().Stage == ProbeStage.Conflict &&
                !f.Probe.AssessReconnect(true).Ready,
                "restored feature with active listener forbids network reconnection");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Host.FailBeforeFeature = true;
            Throws<IOException>(() => f.Probe.PrepareFeature(true), "failed isolated feature enablement remains ambiguous");
            Check(f.Store.Load().Stage == ProbeStage.PreparedEnable && f.Host.FeatureWrites == 0,
                "prewrite failure preserves enable intent without assuming mutation");
            Check(f.Probe.RestoreOriginal(false, false, true).Stage == ProbeStage.Restored,
                "verified unchanged feature can close failed enable intent");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Host.FailAfterFeature = true;
            Throws<IOException>(() => f.Probe.PrepareFeature(true),
                "exception after isolated feature write remains ambiguous");
            Check(f.Store.Load().Stage == ProbeStage.PreparedEnable && f.Host.State.FeatureEnabled,
                "postwrite failure retains intent and observed enabled feature");
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(false, false, true),
                "ambiguous feature write needs reviewed restoration");
            f.Host.FailAfterFeature = false;
            Check(f.Probe.RestoreOriginal(true, false, true).Stage == ProbeStage.Restored,
                "reviewed restoration returns original feature after postwrite failure");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Probe.PrepareFeature(true); f.Host.State.ParentLogonTime = 101;
            f.Host.State.NetworkIsolationAccepted = false;
            Throws<InvalidOperationException>(() => f.Probe.ResumeAfterFreshLogon(true),
                "reappearing Wi-Fi after fresh logon blocks Stage A verification");
            Check(f.Store.Load().NetworkDeviationObserved && f.Store.Load().Stage == ProbeStage.AwaitFreshParent,
                "post-logon network loss is durable without creating a child");
            f.Host.State.NetworkIsolationAccepted = true;
            Check(f.Probe.RestoreOriginal(true, true, true).Stage == ProbeStage.Restored,
                "re-isolation plus reviewed recovery restores feature after post-logon deviation");
        }
        using (var f = new Fixture())
        {
            f.SetIsolated(); f.Host.State.ChildAccess = ResourceAccess.Unknown; f.Host.State.ChildApiErrorCode = 1168;
            ProbePlan plan = f.Probe.Plan(ProbeNetworkPosture.NetworkIsolated, true);
            f.Probe.Begin(plan, plan.Hash, true); f.Probe.PrepareFeature(true);
            f.Host.State.ParentLogonTime = 101;
            Check(f.Probe.ResumeAfterFreshLogon(true).Stage == ProbeStage.StageAQueryUnknown,
                "persistent post-logon 1168 remains unknown in isolated Stage A");
            Throws<InvalidOperationException>(() => f.Probe.ApproveStageB(plan.Hash, true),
                "1168 and isolated posture both block Stage B");
            Check(f.Probe.RestoreOriginal(false, false, true).Stage == ProbeStage.Restored,
                "Stage A only 1168 permits controlled feature restoration while isolated");
        }
        using (var f = new Fixture())
        {
            f.BeginIsolated(); f.Probe.PrepareFeature(true);
            f.Host.FailRestore = true;
            Throws<IOException>(() => f.Probe.RestoreOriginal(false, false, true),
                "failed restoration is not reported as complete");
            Check(!f.Probe.AssessReconnect(true).Ready && f.Store.Load().Stage == ProbeStage.Restoring,
                "incomplete feature restoration forbids reconnection");
            f.Host.FailRestore = false;
            f.Host.State.TermServiceStopped = false;
            f.Host.State.ListenerFingerprint = "listener-changed";
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(false, false, true),
                "unexpected TermService or listener drift is a conflict after feature restoration");
            Check(f.Store.Load().Stage == ProbeStage.Conflict && !f.Probe.AssessReconnect(true).Ready,
                "service/listener conflict forbids reconnection even after feature is restored");
            f.Host.State.TermServiceStopped = true; f.Host.State.ListenerFingerprint = "listener-1";
            Check(f.Probe.RestoreOriginal(false, false, true).Stage == ProbeStage.Restored &&
                f.Probe.AssessReconnect(true).Ready, "reconnection requires original infrastructure verified again");
            f.Host.State.NetworkIsolationAccepted = false;
            Check(!f.Probe.AssessReconnect(true).Ready && f.Store.Load().NetworkDeviationObserved,
                "network loss after restoration is recorded and prevents reconnection");
            f.Host.State.NetworkIsolationAccepted = true;
            Throws<InvalidOperationException>(() => f.Probe.RestoreOriginal(false, false, true),
                "post-restoration deviation still requires reviewed recovery");
            Check(f.Probe.RestoreOriginal(true, true, true).Stage == ProbeStage.Restored &&
                f.Probe.AssessReconnect(true).Ready,
                "reviewed re-isolation restores reconnect eligibility without another feature write");
        }
    }
    private static void PrivateStateSynthetic()
    {
        using (var f = new Fixture())
        {
            string path = Path.Combine(f.Root, "private");
            Throws<DirectoryNotFoundException>(() => ProbePrivateState.VerifyAt(path, false),
                "read-only state verification never creates a directory");
            ProbePrivateState.VerifyAt(path, true);
            Check(Directory.GetAccessControl(path).AreAccessRulesProtected,
                "created state directory has protected ACL");
            File.WriteAllText(Path.Combine(path, "probe.lock"), "synthetic");
            ProbePrivateState.VerifyAt(path, false);
            File.WriteAllText(Path.Combine(path, "unexpected"), "synthetic");
            Throws<InvalidDataException>(() => ProbePrivateState.VerifyAt(path, false),
                "unexpected state file is rejected");
        }
    }

    public static int Main()
    {
        try
        {
            PlanningAndApproval(); FeatureFailureAndRecovery(); FreshLogonAndConnection(); TeardownAndRollback();
            JournalAndOwnership(); ObservedHostBoundary(); WindowsAdapterSynthetic(); FirewallGateSynthetic();
            NetworkGateSynthetic(); IsolatedLifecycle(); PrivateStateSynthetic();
            Console.WriteLine("Feasibility probe: " + assertions + " offline assertions passed."); return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
