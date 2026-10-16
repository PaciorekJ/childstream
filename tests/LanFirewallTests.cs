using System;
using System.Collections.Generic;
using System.IO;

internal static class LanFirewallTests
{
    private static int checks;
    private static void Check(bool condition, string label)
    { checks++; if (!condition) throw new Exception(label); }
    private static void Reject(Action action, string label)
    { bool failed = false; try { action(); } catch (InvalidOperationException) { failed = true; }
      catch (InvalidDataException) { failed = true; } Check(failed, label); }
    private sealed class FakeHost : ILanFirewallHost
    {
        internal readonly Dictionary<string, LanFirewallRule> Rules = new Dictionary<string, LanFirewallRule>();
        internal bool Complete = true, Physical = true, Private = true, Enabled = true, Block = true;
        internal int Foreign;
        internal string Network = "physical-adapter|192.168.50.10|192.168.50.0/24";
        public LanFirewallObservation Read(string address, SunshinePortFamily family, string executable)
        {
            var result = new LanFirewallObservation { LocalAddress = address,
                RemoteSubnet = "192.168.50.0/24", NetworkIdentity = Network,
                PhysicalInterfaceUp = Physical, PrivateProfileActive = Private,
                FirewallEnabled = Enabled, DefaultInboundBlocked = Block,
                ForeignAllowRules = Foreign, Complete = Complete };
            result.OwnedRules.AddRange(Rules.Values); return result;
        }
        public void Add(LanFirewallRule rule) { Rules.Add(rule.Name, rule); }
        public void Remove(LanFirewallRule rule)
        {
            if (Rules.ContainsKey(rule.Name) && Rules[rule.Name].Canonical() != rule.Canonical())
                throw new InvalidOperationException("Rule changed at removal boundary.");
            Rules.Remove(rule.Name);
        }
    }
    public static int Main()
    {
        const string nic = "29d8a111-4468-4e16-a341-607183241104";
        const string another = "f899524a-9e34-41fc-a349-4e245e3f2401";
        Check(WindowsLanFirewallHost.IsPhysicalAdapterEvidence(nic, 7, "{" + nic + "}", 7,
            true, false, "PCI\\VEN_1234"), "exact physical interface identity is admitted");
        Check(!WindowsLanFirewallHost.IsPhysicalAdapterEvidence(nic, 7, another, 7,
            true, false, "PCI\\VEN_1234"), "different interface identity is rejected");
        Check(!WindowsLanFirewallHost.IsPhysicalAdapterEvidence(nic, 7, nic, 51,
            true, false, "PCI\\VEN_1234"), "interface index drift is rejected");
        Check(!WindowsLanFirewallHost.IsPhysicalAdapterEvidence(nic, 7, nic, 7,
            false, true, "ROOT\\VMS_MP"), "virtual adapter is not physical LAN evidence");
        Check(!WindowsLanFirewallHost.IsPhysicalAdapterEvidence(nic, 7, nic, 7,
            null, null, null), "unknown hardware evidence fails closed");
        string fixture = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "ChildStreamLan-" + Guid.NewGuid().ToString("N"));
        string root = Path.Combine(fixture, "ChildStream");
        string executable = Path.Combine(root, "versions", SunshineReleasePin.Version, "sunshine.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(executable));
        File.WriteAllText(executable, "fixture sunshine");
        try
        {
            string digest = SetupInstallTrust.Hash(executable);
            var host = new FakeHost();
            var transaction = new LanFirewallTransaction(host, root, executable, new SunshinePortFamily(48089));
            var plan = transaction.Plan("192.168.50.10", digest);
            var setup = new SetupTransaction(transaction, digest);
            string setupPlan = setup.Execute(new SetupRequest { Operation = SetupOperation.PlanLan,
                LanAddress = "192.168.50.10" }, false);
            Check(setupPlan.EndsWith(plan.Hash), "authenticated setup controller returns exact read-only LAN plan");
            using (var wire = new MemoryStream())
            {
                SetupWire.SendRequest(wire, new SetupRequest { Operation = SetupOperation.ApplyLan,
                    LanAddress = "192.168.50.10", ApprovedPlanHash = plan.Hash });
                wire.Position = 0;
                Check(SetupWire.ReadRequest(wire).LanAddress == "192.168.50.10",
                    "production pipe frame carries exact LAN approval address");
            }
            Check(plan.Tcp.LocalPorts.Contains("48084") && !plan.Tcp.LocalPorts.Contains("48090") &&
                plan.Udp.LocalPorts.Contains("48098"), "stream ports omit LAN access to Web UI");
            Reject(() => transaction.Apply(plan, "wrong"), "exact approval hash required");
            Check(host.Rules.Count == 0 && !File.Exists(Path.Combine(root, "lan-firewall.journal")),
                "unapproved exposure has no effect");
            host.Foreign = 1;
            Reject(() => transaction.Plan("192.168.50.10", digest), "pre-existing broad allow blocks plan");
            host.Foreign = 0; host.Private = false;
            Reject(() => transaction.Plan("192.168.50.10", digest), "non-private profile blocks plan");
            host.Private = true; host.Block = false;
            Reject(() => transaction.Plan("192.168.50.10", digest), "allow-by-default firewall blocks plan");
            host.Block = true; host.Network = "drift";
            Reject(() => transaction.Apply(plan, plan.Hash), "network identity drift blocks apply");
            host.Network = "physical-adapter|192.168.50.10|192.168.50.0/24";
            setup.Execute(new SetupRequest { Operation = SetupOperation.ApplyLan,
                LanAddress = "192.168.50.10", ApprovedPlanHash = plan.Hash }, true);
            Check(transaction.Verify("192.168.50.10") && host.Rules.Count == 2,
                "scoped rules and protected journal verify together");
            setup.Execute(new SetupRequest { Operation = SetupOperation.ApplyLan,
                LanAddress = "192.168.50.10", ApprovedPlanHash = plan.Hash }, true);
            Check(host.Rules.Count == 2, "repeat approved LAN apply is a verified no-op");
            Check(setup.Execute(new SetupRequest { Operation = SetupOperation.ReadLanJournal,
                LanAddress = "192.168.50.10" }, false).Contains(plan.Hash),
                "interrupted setup can retrieve the exact private LAN journal hash");
            Reject(() => setup.Execute(new SetupRequest { Operation = SetupOperation.RecoverLan,
                LanAddress = "192.168.50.10", ApprovedPlanHash = new string('0', 64) }, true),
                "LAN recovery requires the reviewed journal hash");
            Check(File.Exists(Path.Combine(root, "lan-firewall.journal")),
                "journal durable before approved firewall changes");
            host.Foreign = 1;
            Check(!transaction.Verify("192.168.50.10"), "new broad allowance invalidates runtime admission");
            host.Foreign = 0; host.Network = "changed-after-logon";
            Check(!transaction.Verify("192.168.50.10"), "adapter or subnet drift invalidates runtime admission");
            host.Network = "physical-adapter|192.168.50.10|192.168.50.0/24";
            host.Rules[plan.Tcp.Name].RemoteSubnet = "Any";
            Reject(() => transaction.Recover(), "changed owned rule preserved for review");
            host.Rules[plan.Tcp.Name].RemoteSubnet = plan.Subnet;
            host.Physical = false;
            setup.Execute(new SetupRequest { Operation = SetupOperation.RecoverLan,
                LanAddress = "192.168.50.10", ApprovedPlanHash = plan.Hash }, true);
            Check(host.Rules.Count == 0 && !File.Exists(Path.Combine(root, "lan-firewall.journal")),
                "exact owned rules reversed even after selected physical interface disconnects");
            transaction.Recover();
            Check(File.Exists(Path.Combine(root, "lan-firewall.journal.rolledback." + plan.Hash)),
                "repeated recovery is idempotent");
            host.Physical = true;
            transaction.Apply(plan, plan.Hash);
            transaction.Recover();
            Check(host.Rules.Count == 0, "same reviewed LAN plan can be reapplied and reversed after recovery");
            Console.WriteLine("LAN firewall transaction fixture assertions passed: " + checks);
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        finally { if (Directory.Exists(fixture)) Directory.Delete(fixture, true); }
    }
}
