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
        internal bool Complete = true, Physical = true, Private = true, Enabled = true, Block = true,
            LocalEffective = true, InterfaceProtected = true, Wildcard = true;
        internal int Foreign, ConflictingBlock;
        internal string Network = "physical-adapter|192.168.50.10|192.168.50.0/24";
        public LanFirewallObservation Read(string address, SunshinePortFamily family, string executable)
        {
            var result = new LanFirewallObservation { LocalAddress = address,
                RemoteSubnet = "192.168.50.0/24", NetworkIdentity = Network,
                PhysicalInterfaceUp = Physical, PrivateProfileActive = Private,
                FirewallEnabled = Enabled, DefaultInboundBlocked = Block,
                LocalRulesEffective = LocalEffective, InterfaceFirewallApplies = InterfaceProtected,
                WildcardScopeComplete = Wildcard,
                ForeignAllowRules = Foreign, ConflictingBlockRules = ConflictingBlock,
                Complete = Complete };
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
        Check(WindowsLanFirewallHost.IsSelectedPrivateProfileEvidence(7, "Wi-Fi", 7,
            "Wi-Fi", 1, 2), "selected physical interface itself is Private");
        Check(!WindowsLanFirewallHost.IsSelectedPrivateProfileEvidence(7, "Wi-Fi", 51,
            "vEthernet", 1, 2) &&
            !WindowsLanFirewallHost.IsSelectedPrivateProfileEvidence(7, "Wi-Fi", 7,
            "Wi-Fi", 0, 2) &&
            !WindowsLanFirewallHost.IsSelectedPrivateProfileEvidence(7, "Wi-Fi", 7,
            "Wi-Fi", 1, 1), "another private profile cannot substitute for selected interface");
        var selected = new WildcardInterfaceEvidence { Identity = nic, Address = "192.168.50.10",
            Selected = true, Profile = 2, ProfileKnown = true, FirewallEnabled = true,
            DefaultInboundBlocked = true, InterfaceProtected = true, LocalRulesEffective = true };
        var second = new WildcardInterfaceEvidence { Identity = another, Address = "10.0.0.2",
            Profile = 1, ProfileKnown = true, FirewallEnabled = true,
            DefaultInboundBlocked = true, InterfaceProtected = true, LocalRulesEffective = true };
        Check(WindowsLanFirewallHost.WildcardScopeAccepted(new [] { selected, second }),
            "all wildcard-reachable profiles require individual protected observations");
        second.FirewallEnabled = false;
        Check(!WindowsLanFirewallHost.WildcardScopeAccepted(new [] { selected, second }),
            "Private selected interface cannot mask disabled Public firewall");
        second.FirewallEnabled = true; second.DefaultInboundBlocked = false;
        Check(!WindowsLanFirewallHost.WildcardScopeAccepted(new [] { selected, second }),
            "Public default allow blocks wildcard binding");
        second.DefaultInboundBlocked = true; second.InterfaceProtected = false;
        Check(!WindowsLanFirewallHost.WildcardScopeAccepted(new [] { selected, second }),
            "firewall-excluded alternate interface blocks wildcard binding");
        second.InterfaceProtected = true; second.Profile = 4; second.ProfileKnown = false;
        Check(!WindowsLanFirewallHost.WildcardScopeAccepted(new [] { selected, second }),
            "unattributed Domain path fails closed");
        second.ProfileKnown = true; second.Profile = 2;
        Check(WindowsLanFirewallHost.WildcardScopeAccepted(new [] { selected, second }),
            "multiple same-profile interfaces are each assessed");
        Check(WindowsLanFirewallHost.RuleIntersectsWildcard(1, 3) &&
            WindowsLanFirewallHost.RuleIntersectsWildcard(4, 6) &&
            WindowsLanFirewallHost.RuleIntersectsWildcard(0, 2) &&
            !WindowsLanFirewallHost.RuleIntersectsWildcard(4, 3),
            "Public, Domain and unknown-profile broad rules are assessed against all reachable profiles");
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
            host.Block = true; host.LocalEffective = false;
            Reject(() => transaction.Plan("192.168.50.10", digest), "group policy suppression of local rules blocks plan");
            host.LocalEffective = true; host.InterfaceProtected = false;
            Reject(() => transaction.Plan("192.168.50.10", digest), "firewall excluded selected interface blocks plan");
            host.InterfaceProtected = true; host.ConflictingBlock = 1;
            Reject(() => transaction.Plan("192.168.50.10", digest), "overlapping inbound block rule blocks plan");
            host.ConflictingBlock = 0;
            host.Wildcard = false;
            Reject(() => transaction.Plan("192.168.50.10", digest),
                "unprotected alternate wildcard path blocks pre-start plan");
            host.Wildcard = true;
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
            host.Foreign = 0; host.Wildcard = false;
            Check(!transaction.Verify("192.168.50.10"),
                "idle supervision sees the same complete wildcard scope as pre-start planning");
            host.Wildcard = true;
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
