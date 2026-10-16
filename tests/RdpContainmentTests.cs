using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

internal static class RdpContainmentTests
{
    private sealed class Host : IRdpContainmentHost
    {
        internal RdpContainmentObservation State = Baseline();
        internal int Adds, Removes;
        internal bool FailAfterFirstAdd;
        public RdpContainmentObservation Read() { return State; }
        public void Add(RdpContainmentRule rule)
        {
            Adds++; State.PersistentRules.Add(rule); State.ActiveRules.Add(rule);
            if (FailAfterFirstAdd && Adds == 1) throw new IOException("Injected non-atomic firewall failure");
        }
        public void Remove(RdpContainmentRule rule)
        {
            Removes++;
            State.PersistentRules.RemoveAll(r => r.Name == rule.Name);
            State.ActiveRules.RemoveAll(r => r.Name == rule.Name);
        }
    }
    private static RdpContainmentObservation Baseline()
    {
        var state = new RdpContainmentObservation { Complete = true, FeatureKnown = true,
            FeatureEnabled = false, PolicyDenied = true, TermServiceState = "Running",
            ListenersAbsent = true, BypassCountKnown = true, BypassCount = 0,
            ConfiguredRdpPort = 3391 };
        foreach (string name in new[] { "Domain", "Private", "Public" })
            state.Profiles.Add(new RdpContainmentProfile { Name = name, Enabled = "True",
                DefaultInboundAction = "Block", AllowLocalFirewallRules = "True", ExclusionsKnown = true });
        return state;
    }
    private static object Raw(RdpContainmentRule rule, object enforcement)
    {
        return new { Name = rule.Name, Description = rule.Description, Service = rule.Service,
            Protocol = rule.Protocol == 6 ? "TCP" : "UDP", Profiles = "Domain, Private, Public",
            Direction = "Inbound", Action = "Block", Enabled = "True", EdgeTraversal = "Block",
            OverrideBlockRules = "False", LocalPorts = "Any", RemotePorts = "Any",
            LocalAddresses = "Any", RemoteAddresses = rule.RemoteAddresses,
            InterfaceTypes = "Any", InterfaceAlias = new[] { "Any" },
            Application = "Any", Authentication = "NotRequired", Encryption = "NotRequired",
            LocalUser = "Any", RemoteUser = "Any", RemoteMachine = "Any",
            SourceType = "Local", PrimaryStatus = "OK", EnforcementStatus = enforcement };
    }
    private static string RawJson(int port = 3391)
    {
        var tcp = RdpContainmentTransaction.Expected(6);
        var udp = RdpContainmentTransaction.Expected(17);
        return new JavaScriptSerializer().Serialize(new {
            Schema = "ChildStream.RdpContainmentObservation.v1", FeatureKnown = true,
            FeatureEnabled = false, PolicyDenied = true, TermServiceState = "Running",
            ListenersAbsent = true, ConfiguredRdpPort = port, BypassCount = 0,
            OrdinaryAllowCount = 20,
            Profiles = new[] { "Domain", "Private", "Public" }.Select(name => new {
                Name = name, Enabled = "True", DefaultInboundAction = "Block",
                AllowLocalFirewallRules = "True", ExcludedInterfaces = new string[0] }).ToArray(),
            PersistentRules = new[] { Raw(tcp, new int[0]), Raw(udp, new int[0]) },
            ActiveRules = new[] { Raw(tcp, new[] { 1 }), Raw(udp, new[] { 1 }) }
        });
    }
    private static int checks;
    private static void Check(bool condition, string label)
    { checks++; if (!condition) throw new Exception(label); }
    private static void Reject(Action action, string label)
    { bool rejected = false; try { action(); } catch { rejected = true; } Check(rejected, label); }
    private static string Replace(string value, string oldValue, string newValue)
    {
        string result = value.Replace(oldValue, newValue);
        Check(result != value, "raw fixture replacement hit " + oldValue);
        return result;
    }
    public static int Main()
    {
        var expected = RdpContainmentTransaction.Expected(6);
        Check(expected.Service == "TermService" && expected.Protocol == 6 && expected.Profiles == 7 &&
            expected.Action == 0 && expected.Direction == 1 && expected.LocalPorts == "*" &&
            expected.InterfaceTypes == "All", "service-scoped all-port all-profile block");
        Check(!expected.RemoteAddresses.Contains("127.0.0.1") && expected.RemoteAddresses.Contains("::2-"),
            "IPv4 and IPv6 loopback excluded from remote scope");
        var parsed = WindowsRdpContainmentHost.Parse(RawJson());
        Check(RdpContainmentTransaction.Configured(parsed) && parsed.OrdinaryAllowCount == 20,
            "ordinary allows do not override a full enforced block; bypass allows remain rejected");
        Check(parsed.ConfiguredRdpPort == 3391, "nondefault RDP endpoint retained");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "Domain, Private, Public", "Private"))), "profile mask mismatch rejected");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "\"ExcludedInterfaces\":[]", "\"ExcludedInterfaces\":[\"vEthernet\"]"))),
            "profile-specific interface exclusion rejected");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "\"AllowLocalFirewallRules\":\"True\"", "\"AllowLocalFirewallRules\":\"False\""))),
            "effective local-rule merge disabled is rejected");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "\"SourceType\":\"Local\"", "\"SourceType\":\"GroupPolicy\""))),
            "active policy cannot be attributed to foreign GPO");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "\"EnforcementStatus\":[1]", "\"EnforcementStatus\":[16]"))),
            "local rule disallowed enforcement status rejected");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "::2-ffff", "::3-ffff"))), "IPv6 coverage drift rejected");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "\"PolicyDenied\":true", "\"PolicyDenied\":false"))),
            "ordinary RDP policy allowed is rejected");
        Check(!RdpContainmentTransaction.Configured(WindowsRdpContainmentHost.Parse(
            Replace(RawJson(), "\"BypassCount\":0", "\"BypassCount\":1"))),
            "override-block allow rejected");
        Reject(() => WindowsRdpContainmentHost.Parse(Replace(RawJson(),
            "\"Profiles\":[", "\"Profiles\":null,")), "unavailable raw profile is unknown");
        string dir = Path.Combine(Directory.GetCurrentDirectory(), "tests", ".artifacts",
            "ChildStream-rdp-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string account = new string('a', 64);
            var host = new Host(); var txn = new RdpContainmentTransaction(host, dir, account);
            string hash = txn.Plan().Hash;
            Reject(() => txn.Apply(new string('b', 64)), "approval mismatch before writes");
            Check(host.Adds == 0 && !File.Exists(Path.Combine(dir, "rdp-containment.journal")),
                "denied approval has no writes or journal");
            host.State.PolicyDenied = false;
            Reject(() => txn.Apply(hash), "RDP policy drift blocks transaction");
            Check(host.Adds == 0, "drift causes zero rule or feature writes");
            host.State.PolicyDenied = true;
            txn.Apply(hash);
            Check(host.Adds == 2 && txn.Verify(), "approved exact rules written and read back");
            txn.Apply(hash); Check(host.Adds == 2, "duplicate apply is an exact verified no-op");
            host.State.FeatureEnabled = true;
            Reject(() => txn.Recover(hash), "feature enabled retains protection");
            Check(host.Removes == 0, "feature uncertainty causes zero block removals");
            host.State.FeatureEnabled = false; host.State.ListenersAbsent = false;
            Reject(() => txn.Recover(hash), "listener recovery uncertain retains protection");
            Check(host.Removes == 0, "listener uncertainty causes zero block removals");
            host.State.ListenersAbsent = true;
            txn.Recover(hash);
            Check(host.Removes == 2 && host.State.PersistentRules.Count == 0 &&
                !File.Exists(Path.Combine(dir, "rdp-containment.journal")), "only exact owned rules removed after verified restoration");
            string dir2 = Path.Combine(dir, "partial"); Directory.CreateDirectory(dir2);
            var partial = new Host { FailAfterFirstAdd = true };
            var interrupted = new RdpContainmentTransaction(partial, dir2, account);
            string partialHash = interrupted.Plan().Hash;
            Reject(() => interrupted.Apply(partialHash), "injected partial native firewall write");
            Check(partial.Adds == 1 && File.Exists(Path.Combine(dir2, "rdp-containment.journal")),
                "intent durable before partial native effect");
            partial.State.TermServiceState = "Unknown";
            Reject(() => interrupted.Recover(partialHash), "partial rule retained while service uncertain");
            Check(partial.Removes == 0, "unknown service restoration cannot remove block");
            partial.State.TermServiceState = "Running";
            interrupted.Recover(partialHash);
            Check(partial.Removes == 1, "partial exact owned rule recovered only after baseline reverified");
        }
        finally { Directory.Delete(dir, true); }
        Console.WriteLine("RDP containment raw-policy/transaction assertions passed: " + checks);
        return 0;
    }
}
