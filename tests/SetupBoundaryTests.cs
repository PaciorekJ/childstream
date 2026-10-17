using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
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
    private sealed class RdpHost : IRdpContainmentHost
    {
        internal RdpContainmentObservation State;
        internal Func<bool> Feature;
        internal int Adds;
        public RdpContainmentObservation Read()
        { if (Feature != null) State.FeatureEnabled = Feature(); return State; }
        public void Add(RdpContainmentRule rule)
        { Adds++; State.PersistentRules.Add(rule); State.ActiveRules.Add(rule); }
        public void Remove(RdpContainmentRule rule)
        { State.PersistentRules.RemoveAll(x => x.Name == rule.Name);
          State.ActiveRules.RemoveAll(x => x.Name == rule.Name); }
    }
    private sealed class PacketHost : IConnectedQualificationHost
    {
        internal long Now = new DateTime(2026, 10, 16, 12, 0, 0, DateTimeKind.Utc).Ticks;
        internal QualificationBoundary Boundary = new QualificationBoundary { MachineId = "machine-1" };
        public long UtcNowTicks { get { return Now; } }
        public QualificationBoundary Observe(long since, int port) { return Boundary; }
        internal void AddPath(int index, string path, int port)
        {
            Boundary.Interfaces.Add(new QualificationInterface { Index = index, Path = path,
                Identity = path + "-interface-" + index, Addresses = "192.0.2.5" });
            foreach (int protocol in new[] { 6, 17 })
                Boundary.Drops.Add(new QualificationDrop { RecordId = index * 100 + protocol,
                    UtcTicks = Now - TimeSpan.TicksPerMinute, InterfaceIndex = index,
                    Protocol = protocol, LocalPort = port,
                    FilterOrigin = RdpContainmentTransaction.Expected(protocol).Name,
                    RemoteAddress = "192.0.2.4", LocalAddress = "192.0.2.5" });
        }
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
    private sealed class PipeWorkflow : ISetupWorkflow
    {
        private readonly SetupTransaction transaction;
        internal PipeWorkflow(SetupTransaction transaction) { this.transaction = transaction; }
        public string Execute(SetupRequest request)
        {
            string name = "ChildStream-Setup-Integration-" + Guid.NewGuid().ToString("N");
            using (var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096))
            using (var client = new NamedPipeClientStream(".", name, PipeDirection.InOut,
                PipeOptions.Asynchronous))
            {
                var helper = Task.Run(() =>
                {
                    client.Connect(5000);
                    using (var wire = new BoundedPipe(client, 5000))
                    {
                        SetupRequest fromApp = SetupWire.ReadRequest(wire);
                        string sid = "S-1-5-21-100-200-300-1001", hash = new string('c',64);
                        var app = new ProductProcessIdentity { Pid = 71, SessionId = 2,
                            StartTimeUtcTicks = 100, ExecutablePath = @"C:\Program Files\ChildStream\ChildStream.exe",
                            ExecutableSha256 = hash };
                        SetupPeerPolicy.RequireElevatedConsole(RuntimeTokenStatus.Elevated, true, 2, 2, 2);
                        SetupPeerPolicy.RequireRequester(app, new ProcessTokenObservation {
                            Sid = sid, Elevation = RuntimeTokenStatus.Limited }, 71, 2, sid,
                            app.ExecutablePath, hash);
                        try { SetupWire.SendResult(wire, true, transaction.Execute(fromApp, true)); }
                        catch (Exception ex) { SetupWire.SendResult(wire, false, ex.GetType().Name + ": " + ex.Message); }
                    }
                });
                BoundedPipe.WaitForConnection(server, 5000);
                using (var wire = new BoundedPipe(server, 5000))
                {
                    string helperHash = new string('d',64);
                    SetupPeerPolicy.RequireAuthenticatedHelper(new ProductProcessIdentity {
                        Pid = 72, SessionId = 2, StartTimeUtcTicks = 101,
                        ExecutablePath = @"C:\Program Files\ChildStream\ChildStreamSetup.exe",
                        ExecutableSha256 = helperHash }, new ProcessTokenObservation {
                        Sid = "S-1-5-32-544", Elevation = RuntimeTokenStatus.Elevated },
                        72, 2, @"C:\Program Files\ChildStream\ChildStreamSetup.exe", helperHash);
                    SetupWire.SendRequest(wire, request);
                    string result = SetupWire.ReadResult(wire);
                    helper.GetAwaiter().GetResult();
                    return result;
                }
            }
        }
        public void RegisterOwnAgentTask() { throw new Exception("not in fixture"); }
        public void RemoveOwnAgentTask() { throw new Exception("not in fixture"); }
    }
    private static void WaitUi(Func<bool> done, string step)
    {
        for (int i = 0; i < 1500; i++) { Application.DoEvents(); if (done()) return; Thread.Sleep(10); }
        var form = Application.OpenForms.OfType<SetupDialog>().FirstOrDefault();
        string status = form == null ? "form closed" : form.Controls.OfType<Label>()
            .OrderByDescending(x => x.Top).FirstOrDefault().Text;
        throw new TimeoutException("Simulated setup form did not complete " + step + ": " + status);
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
            FirewallFingerprint = "firewall", DisplayFingerprint = "display", NativeResourceFingerprint = "native",
            NetworkFingerprint = "network" };
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
            NativeResourceFingerprint = x.NativeResourceFingerprint, NetworkFingerprint = x.NetworkFingerprint };
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
        string eventXml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
            "<System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5157</EventID>" +
            "<Channel>Security</Channel></System><EventData>" +
            "<Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>192.0.2.4</Data>" +
            "<Data Name='SourcePort'>49152</Data><Data Name='DestAddress'>192.0.2.5</Data>" +
            "<Data Name='DestPort'>3391</Data><Data Name='Protocol'>6</Data>" +
            "<Data Name='InterfaceIndex'>7</Data><Data Name='FilterOrigin'>" +
            RdpContainmentTransaction.Expected(6).Name + "</Data></EventData></Event>";
        var parsedDrop = WindowsConnectedQualificationHost.ParseSecurityEvent(eventXml, 92, 100,
            new[] { "192.0.2.5" }, 3391);
        Check(parsedDrop != null && parsedDrop.LocalPort == 3391 && parsedDrop.InterfaceIndex == 7 &&
            parsedDrop.RemoteAddress == "192.0.2.4" && parsedDrop.FilterOrigin ==
            RdpContainmentTransaction.Expected(6).Name,
            "raw Windows WFP XML fields reach the production packet parser");
        Check(WindowsConnectedQualificationHost.ParseSecurityEvent(
            eventXml.Replace("%%14592", "Outbound"), 92, 100, new[] { "192.0.2.5" }, 3391) == null,
            "outbound event is not inbound denial proof");
        Check(WindowsConnectedQualificationHost.ParseSecurityEvent(
            eventXml.Replace("<Data Name='FilterOrigin'>", "<Data Name='Other'>"),
            92, 100, new[] { "192.0.2.5" }, 3391) == null,
            "missing filter origin cannot become packet proof");
        Check(WindowsConnectedQualificationHost.ParseSecurityEvent(eventXml, 92, 100,
            new[] { "192.0.2.5" }, 3389) == null, "wrong RDP port cannot become packet proof");
        string versionedDir = Path.Combine(Directory.GetCurrentDirectory(), "tests", ".artifacts",
            "ChildStream-v7-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(versionedDir);
        try
        {
            ProbeSnapshot v7 = Good(); v7.FormatVersion = 7;
            v7.LocalRdpPostureAccepted = false; v7.QualifiedContainmentHash = new string('b',64);
            var planV7 = new ProbePlan { Original = v7,
                Hash = ProbeCodec.Hash(ProbeCodec.PlanBytes(v7)) };
            var saved = new ProbeJournal { Plan = planV7, Stage = ProbeStage.Captured,
                ActiveParentId = v7.ParentSessionId, ActiveParentLogonTime = v7.ParentLogonTime };
            var disk = new FileProbeStore(Path.Combine(versionedDir, "probe.journal"));
            disk.Save(saved);
            ProbeJournal restored = disk.Load();
            Check(restored.Plan.Original.FormatVersion == 7 && restored.Plan.Hash == planV7.Hash &&
                restored.Plan.Original.QualifiedContainmentHash == v7.QualifiedContainmentHash &&
                restored.Stage == ProbeStage.Captured,
                "qualified connected plan and progress round-trip through durable production journal");
        }
        finally { Directory.Delete(versionedDir, true); }
        var host = new Host(); var store = new Store();
        var transaction = new SetupTransaction(new FeasibilityProbe(host, store, new Lock()), store);
        host.State.LocalRdpPostureAccepted = false; // Protected connected host fixture.
        Reject(() => transaction.Execute(Request(SetupOperation.PlanConnected, ""), true),
            "connected-network firewall gate rejects planning");
        Check(host.Writes == 0 && store.Journal == null, "protected host has zero native writes/journal");
        string rdpDir = Path.Combine(Directory.GetCurrentDirectory(), "tests", ".artifacts",
            "ChildStream-setup-rdp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rdpDir);
        try
        {
            var rdpHost = new RdpHost { State = new RdpContainmentObservation {
                Complete = true, FeatureKnown = true, PolicyDenied = true,
                TermServiceState = "Running", ListenersAbsent = true,
                ConfiguredRdpPort = 3391, BypassCountKnown = true } };
            foreach (string name in new[] { "Domain", "Private", "Public" })
                rdpHost.State.Profiles.Add(new RdpContainmentProfile { Name = name,
                    Enabled = "True", DefaultInboundAction = "Block",
                    AllowLocalFirewallRules = "True", ExclusionsKnown = true });
            var rdp = new RdpContainmentTransaction(rdpHost, rdpDir, new string('a',64));
            var integrated = new SetupTransaction(new FeasibilityProbe(host, store, new Lock()),
                store, null, rdp);
            string rdpPlan = integrated.Execute(Request(SetupOperation.PlanRdpContainment, ""), true);
            string rdpHash = rdpPlan.Substring("RDP plan ".Length);
            Reject(() => integrated.Execute(Request(SetupOperation.ApplyRdpContainment, rdpHash), false),
                "normal setup requires separate containment approval");
            Check(rdpHost.Adds == 0 && host.Writes == 0,
                "denied containment has zero firewall and feature writes");
            integrated.Execute(Request(SetupOperation.ApplyRdpContainment, rdpHash), true);
            Check(rdpHost.Adds == 2 && rdp.Verify() && host.Writes == 0,
                "normal setup invokes approved policy adapter and effective readback");
            Check(integrated.Execute(Request(SetupOperation.ReadRdpContainment, ""), true)
                .Contains("live child-loopback qualification=unrun"),
                "normal setup reports unrun packet and loopback qualification");
            host.State.LocalRdpPostureAccepted = true;
            string qualifiedPlan = integrated.Execute(Request(SetupOperation.PlanConnected, ""), true)
                .Substring(5,64);
            Reject(() => integrated.Execute(Request(SetupOperation.BeginConnected, qualifiedPlan), true),
                "configured policy alone cannot reach feature transaction");
            Check(host.Writes == 0 && store.Journal == null,
                "unrun live qualification causes zero feature writes and no feature journal");
            integrated.Execute(Request(SetupOperation.RecoverRdpContainment, rdpHash), true);
            Check(rdpHost.State.PersistentRules.Count == 0,
                "normal setup recovery removes only exact owned containment");
        }
        finally { Directory.Delete(rdpDir, true); }
        string qualificationDir = Path.Combine(Directory.GetCurrentDirectory(), "tests", ".artifacts",
            "ChildStream-qualified-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(qualificationDir);
        try
        {
            var native = new Host(); var qualifiedStore = new Store();
            native.State.LocalRdpPostureAccepted = false; // Existing permissive rules still block the old gate.
            native.State.AccountBinding = new string('a',64);
            var policyHost = new RdpHost { State = new RdpContainmentObservation {
                Complete = true, FeatureKnown = true, PolicyDenied = true,
                TermServiceState = "Running", ListenersAbsent = true,
                ConfiguredRdpPort = 3391, BypassCountKnown = true } };
            policyHost.Feature = () => native.State.FeatureEnabled;
            foreach (string name in new[] { "Domain", "Private", "Public" })
                policyHost.State.Profiles.Add(new RdpContainmentProfile { Name = name,
                    Enabled = "True", DefaultInboundAction = "Block",
                    AllowLocalFirewallRules = "True", ExclusionsKnown = true });
            var blocks = new RdpContainmentTransaction(policyHost, qualificationDir, new string('a',64));
            var packets = new PacketHost(); packets.AddPath(7, "External", 3391);
            packets.AddPath(51, "Guest", 3391);
            var gate = new ConnectedQualificationGate(packets, qualificationDir, new string('a',64));
            var connected = new SetupTransaction(new FeasibilityProbe(native, qualifiedStore, new Lock()),
                qualifiedStore, null, blocks, gate);
            string blockHash = connected.Execute(Request(SetupOperation.PlanRdpContainment, ""), true).Substring(9,64);
            connected.Execute(Request(SetupOperation.ApplyRdpContainment, blockHash), true);
            string connectedHash = connected.Execute(Request(SetupOperation.PlanConnected, ""), true).Substring(5,64);
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "no packet record never admits a feature journal");
            Check(native.Writes == 0 && qualifiedStore.Journal == null,
                "missing evidence produces zero feature writes");
            packets.Boundary.Interfaces[1].Path = "Unknown";
            Reject(() => connected.Execute(Request(SetupOperation.ObserveQualification, connectedHash), true),
                "unattributed virtual path fails closed");
            packets.Boundary.Interfaces[1].Path = "Guest";
            var udp = packets.Boundary.Drops.Single(x => x.InterfaceIndex == 51 && x.Protocol == 17);
            packets.Boundary.Drops.Remove(udp);
            Reject(() => connected.Execute(Request(SetupOperation.ObserveQualification, connectedHash), true),
                "missing guest UDP packet proof fails closed");
            packets.Boundary.Drops.Add(udp);
            bool realPipe = Environment.GetEnvironmentVariable("CI") == "true" ||
                Environment.GetEnvironmentVariable("CHILDSTREAM_RUN_LOCAL_PIPE") == "1";
            long originalUdpRecord = udp.RecordId; udp.RecordId = packets.Boundary.Drops[0].RecordId;
            Reject(() => connected.Execute(Request(SetupOperation.ObserveQualification, connectedHash), true),
                "reused Security event ID cannot cover two paths");
            udp.RecordId = originalUdpRecord;
            string proof = connected.Execute(Request(SetupOperation.ObserveQualification, connectedHash), true);
            string proofHash = proof.Substring("Pending qualification ".Length,64);
            Reject(() => connected.Execute(Request(SetupOperation.ReviewQualification, new string('b',64)), true),
                "wrong human-review hash rejected");
            Reject(() => connected.Execute(Request(SetupOperation.ReviewQualification, proofHash), false),
                "human review cannot be synthesized by a captured record");
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "unreviewed evidence cannot begin");
            Check(native.Writes == 0 && qualifiedStore.Journal == null,
                "unreviewed evidence has zero feature writes");
            packets.Boundary.Drops[0].FilterOrigin = "default block";
            Reject(() => connected.Execute(Request(SetupOperation.ReviewQualification, proofHash), true),
                "changed WFP filter origin rejects review");
            packets.Boundary.Drops[0].FilterOrigin = RdpContainmentTransaction.Expected(6).Name;
            if (realPipe)
            {
                Application.EnableVisualStyles();
                using (var form = new SetupDialog(new PipeWorkflow(connected), true,
                    (operation, reviewedHash) => true))
                {
                    form.StartPosition = FormStartPosition.Manual;
                    form.Location = new Point(-2000, -2000); form.Show(); Application.DoEvents();
                    form.Controls.OfType<Button>().Single(x => x.Text == "Read proof status").PerformClick();
                    TextBox entry = form.Controls.OfType<TextBox>().Single(x =>
                        x.AccessibleName == "Exact reviewed setup plan hash");
                    WaitUi(() => entry.Text == proofHash &&
                        form.Controls.OfType<Button>().Single(x => x.Text == "Review proof hash").Enabled,
                        "proof readback");
                    form.Controls.OfType<Button>().Single(x => x.Text == "Review proof hash").PerformClick();
                    WaitUi(() => File.Exists(Path.Combine(qualificationDir, "qualification.reviewed.hash")) &&
                        form.Controls.OfType<Button>().Single(x => x.Text == "Review proof hash").Enabled,
                        "proof review");
                    form.Hide();
                }
            }
            else connected.Execute(Request(SetupOperation.ReviewQualification, proofHash), true);
            string reviewMarker = Path.Combine(qualificationDir, "qualification.reviewed.hash");
            File.WriteAllText(reviewMarker, new string('b',64) + "\n");
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "changed private review marker cannot authorize a journal");
            File.WriteAllText(reviewMarker, proofHash + "\n");
            packets.Now += 11 * TimeSpan.TicksPerMinute;
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "expired native packet proof cannot begin");
            packets.Now -= 11 * TimeSpan.TicksPerMinute;
            packets.Boundary.MachineId = "different-machine";
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "machine binding drift blocks admission");
            packets.Boundary.MachineId = "machine-1";
            native.State.FirewallFingerprint = "changed-firewall";
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "firewall fingerprint drift blocks admission");
            native.State.FirewallFingerprint = "firewall";
            native.State.AccountBinding = new string('b',64);
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "requester drift blocks admission");
            native.State.AccountBinding = new string('a',64);
            packets.Now += TimeSpan.TicksPerMinute;
            native.State.NetworkFingerprint = "drift";
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "changed network fingerprint rejects before journal");
            Check(native.Writes == 0 && qualifiedStore.Journal == null,
                "network drift still has zero feature writes");
            native.State.NetworkFingerprint = "network";
            if (realPipe)
            {
                Application.EnableVisualStyles();
                using (var form = new SetupDialog(new PipeWorkflow(connected), true,
                    (operation, reviewedHash) => true))
                {
                    form.StartPosition = FormStartPosition.Manual;
                    form.Location = new Point(-2000, -2000); form.Show(); Application.DoEvents();
                    form.Controls.OfType<Button>().Single(x => x.Text == "Read-only plan").PerformClick();
                    TextBox entry = form.Controls.OfType<TextBox>().Single(x =>
                        x.AccessibleName == "Exact reviewed setup plan hash");
                    WaitUi(() => entry.Text == connectedHash &&
                        form.Controls.OfType<Button>().Single(x => x.Text == "Begin approved plan").Enabled,
                        "plan");
                    form.Controls.OfType<Button>().Single(x => x.Text == "Begin approved plan").PerformClick();
                    WaitUi(() => qualifiedStore.Journal != null &&
                        qualifiedStore.Journal.Stage == ProbeStage.Captured &&
                        form.Controls.OfType<Button>().Single(x => x.Text == "Begin approved plan").Enabled,
                        "begin");
                    form.Hide();
                }
            }
            else
                connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true);
            Check(qualifiedStore.Journal.Stage == ProbeStage.Captured && native.Writes == 0,
                "reviewed exact packet proof reaches captured journal without feature write");
            Reject(() => connected.Execute(Request(SetupOperation.BeginConnected, connectedHash), true),
                "packet evidence cannot replay for another begin");
            if (realPipe)
            {
                using (var form = new SetupDialog(new PipeWorkflow(connected), true,
                    (operation, reviewedHash) => true))
                {
                    form.StartPosition = FormStartPosition.Manual;
                    form.Location = new Point(-2000, -2000); form.Show(); Application.DoEvents();
                    form.Controls.OfType<Button>().Single(x => x.Text == "Read journal").PerformClick();
                    TextBox entry = form.Controls.OfType<TextBox>().Single(x =>
                        x.AccessibleName == "Exact reviewed setup plan hash");
                    WaitUi(() => entry.Text == connectedHash &&
                        form.Controls.OfType<Button>().Single(x => x.Text == "Enable feature").Enabled,
                        "read journal");
                    form.Controls.OfType<Button>().Single(x => x.Text == "Enable feature").PerformClick();
                    WaitUi(() => native.Writes == 1 && qualifiedStore.Journal.Stage == ProbeStage.AwaitFreshParent &&
                        form.Controls.OfType<Button>().Single(x => x.Text == "Enable feature").Enabled,
                        "feature");
                    form.Hide();
                    Check(native.Writes == 1,
                        "rendered setup form, real pipe, authenticated simulated helper and transaction reached one feature adapter write");
                }
            }
            else connected.Execute(Request(SetupOperation.PrepareFeature, connectedHash), true);
            Check(native.Writes == 1 && native.State.FeatureEnabled &&
                qualifiedStore.Journal.Stage == ProbeStage.AwaitFreshParent,
                "separate exact feature approval reaches substituted native adapter once");
            policyHost.State.FeatureEnabled = true;
            Reject(() => connected.Execute(Request(SetupOperation.RecoverRdpContainment, blockHash), true),
                "containment cannot be removed while feature is enabled");
            policyHost.State.ListenersAbsent = false;
            Reject(() => connected.Execute(Request(SetupOperation.VerifyStageA, connectedHash), true),
                "unexpected listener blocks Stage A verification");
            Check(native.Writes == 1 && policyHost.State.ActiveRules.Count == 2,
                "listener ambiguity retains both owned protections and original feature write count");
            policyHost.State.ListenersAbsent = true;
            native.State.ParentLogonTime = 101;
            connected.Execute(Request(SetupOperation.VerifyStageA, connectedHash), true);
            Check(qualifiedStore.Journal.Stage == ProbeStage.StageAValidated && native.Writes == 1,
                "fresh-parent Stage A validates without another feature write or child connection");
            connected.Execute(Request(SetupOperation.RestoreOriginal, connectedHash), true);
            policyHost.State.FeatureEnabled = false;
            Check(native.Writes == 2 && !native.State.FeatureEnabled && blocks.Verify(),
                "feature restoration precedes owned containment removal");
            Reject(() => connected.Execute(Request(SetupOperation.RecoverRdpContainment, blockHash), true),
                "reviewed proof must retire before owned blocks are removed");
            connected.Execute(Request(SetupOperation.RetireQualification, proofHash), true);
            connected.Execute(Request(SetupOperation.RecoverRdpContainment, blockHash), true);
            Check(policyHost.State.ActiveRules.Count == 0, "exact owned blocks recover only after feature restoration");
        }
        finally { Directory.Delete(qualificationDir, true); }
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
