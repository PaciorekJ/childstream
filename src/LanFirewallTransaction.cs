using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

internal sealed class LanFirewallRule
{
    internal string Name, Executable, LocalAddress, RemoteSubnet, LocalPorts;
    internal int Protocol;
    internal bool Enabled = true, InboundAllow = true, PrivateOnly = true, NoEdgeTraversal = true;
    internal string Canonical()
    { return Name + "|" + Executable + "|" + LocalAddress + "|" + RemoteSubnet + "|" + LocalPorts + "|" +
        Protocol + "|" + Enabled + "|" + InboundAllow + "|" + PrivateOnly + "|" + NoEdgeTraversal; }
}
internal sealed class LanFirewallObservation
{
    internal string LocalAddress, RemoteSubnet, NetworkIdentity;
    internal bool PhysicalInterfaceUp, PrivateProfileActive, FirewallEnabled, DefaultInboundBlocked,
        LocalRulesEffective, InterfaceFirewallApplies, Complete;
    internal int ForeignAllowRules, ConflictingBlockRules;
    internal readonly List<LanFirewallRule> OwnedRules = new List<LanFirewallRule>();
}
internal interface ILanFirewallHost
{
    LanFirewallObservation Read(string address, SunshinePortFamily family, string executable);
    void Add(LanFirewallRule rule);
    void Remove(LanFirewallRule expected);
}
internal sealed class LanFirewallPlan
{
    internal string Address, Subnet, NetworkIdentity, Executable, ExecutableHash, Hash;
    internal LanFirewallRule Tcp, Udp;
}

// The ordinary child runtime accepts only this completed, protected journal
// and a fresh matching Windows observation. An installed file or user-selected
// IP alone is never authorization for a wildcard Sunshine listener.
internal sealed class LanFirewallTransaction
{
    private readonly ILanFirewallHost host;
    private readonly string journal;
    private readonly string executable;
    private readonly SunshinePortFamily family;
    internal LanFirewallTransaction(ILanFirewallHost host, string protectedRoot, string executable,
        SunshinePortFamily family)
    {
        this.host = host; this.family = family;
        string root = InstallerPolicy.ValidateCanonicalFilePath(protectedRoot, true).TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(root), "ChildStream", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("LAN journal must be under a dedicated protected ChildStream root.");
        journal = Path.Combine(root, "lan-firewall.journal");
        this.executable = InstallerPolicy.ValidateCanonicalFilePath(executable);
        if (!this.executable.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("LAN rule must target ChildStream-owned Sunshine only.");
    }
    private static string Digest(string value)
    {
        using (var sha = SHA256.Create())
            return ProductInstallPayload.Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }
    private static void RequireBaseline(LanFirewallObservation state, string address)
    {
        if (state == null || !state.Complete || !state.PhysicalInterfaceUp ||
            !state.PrivateProfileActive || !state.FirewallEnabled || !state.DefaultInboundBlocked ||
            !state.LocalRulesEffective || !state.InterfaceFirewallApplies ||
            state.ForeignAllowRules != 0 || state.ConflictingBlockRules != 0 ||
            state.OwnedRules.Count != 0 ||
            !String.Equals(state.LocalAddress, address, StringComparison.Ordinal) ||
            String.IsNullOrEmpty(state.RemoteSubnet) || String.IsNullOrEmpty(state.NetworkIdentity))
            throw new InvalidOperationException("Connected LAN exposure baseline is incomplete, changed, or already permissive.");
    }
    private static string Ports(int[] ports, int excluded)
    { return String.Join(",", ports.Where(p => p != excluded).Select(p => p.ToString()).ToArray()); }
    internal LanFirewallPlan Plan(string address, string expectedExecutableSha256)
    {
        var candidate = new SunshineLanCandidate { Child = new ChildSessionIdentity(2, 1),
            BindAddress = address, Port = family.BasePort };
        candidate.Validate();
        if (!ProductInstallPayload.IsHex256(expectedExecutableSha256) ||
#if !TEST_ONLY
            !String.Equals(expectedExecutableSha256, SunshineReleasePin.ExecutableSha256,
                StringComparison.OrdinalIgnoreCase))
#else
            false)
#endif
            throw new InvalidDataException("LAN plan requires the pinned portable Sunshine executable.");
        if (!File.Exists(executable) ||
            !String.Equals(SetupInstallTrust.Hash(executable), expectedExecutableSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Owned Sunshine bytes differ from the LAN executable pin.");
        LanFirewallObservation state = host.Read(address, family, executable);
        RequireBaseline(state, address);
        var plan = new LanFirewallPlan { Address = address, Subnet = state.RemoteSubnet,
            NetworkIdentity = state.NetworkIdentity, Executable = executable,
            ExecutableHash = expectedExecutableSha256.ToLowerInvariant() };
        plan.Tcp = new LanFirewallRule { Name = "ChildStream LAN TCP v1", Executable = executable,
            LocalAddress = address, RemoteSubnet = state.RemoteSubnet, Protocol = 6,
            LocalPorts = Ports(family.Tcp, family.BasePort + 1) }; // Never allow Web UI from LAN.
        plan.Udp = new LanFirewallRule { Name = "ChildStream LAN UDP v1", Executable = executable,
            LocalAddress = address, RemoteSubnet = state.RemoteSubnet, Protocol = 17,
            LocalPorts = Ports(family.Udp, -1) };
        plan.Hash = Digest("ChildStream.LanFirewall.v1\n" + plan.NetworkIdentity + "\n" +
            plan.ExecutableHash + "\n" + plan.Tcp.Canonical() + "\n" + plan.Udp.Canonical() + "\n");
        return plan;
    }
    private string Payload(LanFirewallPlan plan)
    { return String.Join("\n", new[] { "ChildStream.LanFirewall.v1", plan.Hash, plan.Address,
        plan.Subnet, plan.NetworkIdentity, plan.Executable, plan.ExecutableHash,
        plan.Tcp.Canonical(), plan.Udp.Canonical(), "" }); }
    private static LanFirewallRule ParseRule(string value)
    {
        string[] fields = value.Split('|');
        int protocol;
        if (fields.Length != 10 || !Int32.TryParse(fields[5], out protocol))
            throw new InvalidDataException("LAN journal rule is malformed.");
        bool enabled, inbound, privateOnly, noEdge;
        if (!Boolean.TryParse(fields[6], out enabled) || !Boolean.TryParse(fields[7], out inbound) ||
            !Boolean.TryParse(fields[8], out privateOnly) || !Boolean.TryParse(fields[9], out noEdge))
            throw new InvalidDataException("LAN journal rule properties are malformed.");
        return new LanFirewallRule { Name = fields[0], Executable = fields[1],
            LocalAddress = fields[2], RemoteSubnet = fields[3], LocalPorts = fields[4],
            Protocol = protocol, Enabled = enabled, InboundAllow = inbound,
            PrivateOnly = privateOnly, NoEdgeTraversal = noEdge };
    }
    private LanFirewallPlan ReadJournal()
    {
        InstallerPolicy.ValidateCanonicalFilePath(journal);
        string[] lines = File.ReadAllLines(journal);
        if (lines.Length != 9 || lines[0] != "ChildStream.LanFirewall.v1" ||
            !ProductInstallPayload.IsHex256(lines[1]) || !ProductInstallPayload.IsHex256(lines[6]))
            throw new InvalidDataException("LAN journal is incomplete or malformed.");
        var plan = new LanFirewallPlan { Hash = lines[1], Address = lines[2], Subnet = lines[3],
            NetworkIdentity = lines[4], Executable = lines[5], ExecutableHash = lines[6],
            Tcp = ParseRule(lines[7]), Udp = ParseRule(lines[8]) };
        if (!String.Equals(plan.Executable, executable, StringComparison.OrdinalIgnoreCase) ||
            plan.Hash != Digest("ChildStream.LanFirewall.v1\n" + plan.NetworkIdentity + "\n" +
                plan.ExecutableHash + "\n" + plan.Tcp.Canonical() + "\n" + plan.Udp.Canonical() + "\n"))
            throw new InvalidDataException("LAN journal integrity or executable changed.");
        return plan;
    }
    private static bool Exact(LanFirewallRule actual, LanFirewallRule expected)
    { return actual != null && String.Equals(actual.Canonical(), expected.Canonical(), StringComparison.OrdinalIgnoreCase); }
    internal void Apply(LanFirewallPlan plan, string approvedHash)
    {
        if (plan == null || !String.Equals(plan.Hash, approvedHash, StringComparison.OrdinalIgnoreCase) ||
            plan.Hash != Digest("ChildStream.LanFirewall.v1\n" + plan.NetworkIdentity + "\n" +
                plan.ExecutableHash + "\n" + plan.Tcp.Canonical() + "\n" + plan.Udp.Canonical() + "\n"))
            throw new InvalidOperationException("Exact LAN firewall plan hash was not approved.");
        if (File.Exists(journal))
        {
            var prior = ReadJournal();
            if (prior.Hash != plan.Hash) throw new InvalidOperationException("Another LAN journal owns this installation.");
            if (!Verify(plan.Address)) throw new InvalidOperationException("Interrupted LAN rule installation needs reviewed recovery.");
            return;
        }
        LanFirewallObservation now = host.Read(plan.Address, family, executable);
        RequireBaseline(now, plan.Address);
        if (now.NetworkIdentity != plan.NetworkIdentity || now.RemoteSubnet != plan.Subnet ||
            !String.Equals(SetupInstallTrust.Hash(executable), plan.ExecutableHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("LAN network or executable changed since planning.");
        string payload = Payload(plan);
        using (var file = new FileStream(journal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { byte[] bytes = Encoding.UTF8.GetBytes(payload); file.Write(bytes, 0, bytes.Length); file.Flush(true); }
        host.Add(plan.Tcp); host.Add(plan.Udp);
        if (!Verify(plan.Address)) throw new InvalidOperationException("LAN rule postcondition failed; reviewed recovery is required.");
    }
    internal bool Verify(string address)
    {
        if (!File.Exists(journal)) return false;
        LanFirewallPlan plan = ReadJournal();
        if (plan.Address != address || !File.Exists(executable) ||
            !String.Equals(SetupInstallTrust.Hash(executable), plan.ExecutableHash, StringComparison.OrdinalIgnoreCase))
            return false;
        LanFirewallObservation state = host.Read(address, family, executable);
        return state != null && state.Complete && state.PhysicalInterfaceUp && state.PrivateProfileActive &&
            state.FirewallEnabled && state.DefaultInboundBlocked && state.LocalRulesEffective &&
            state.InterfaceFirewallApplies && state.ForeignAllowRules == 0 &&
            state.ConflictingBlockRules == 0 &&
            state.NetworkIdentity == plan.NetworkIdentity && state.RemoteSubnet == plan.Subnet &&
            state.OwnedRules.Count == 2 && state.OwnedRules.Any(r => Exact(r, plan.Tcp)) &&
            state.OwnedRules.Any(r => Exact(r, plan.Udp));
    }
    internal string ReadJournalHash(string address)
    {
        LanFirewallPlan plan = ReadJournal();
        if (!String.Equals(plan.Address, address, StringComparison.Ordinal))
            throw new InvalidOperationException("LAN journal belongs to a different selected address.");
        return plan.Hash;
    }
    internal bool ApprovedNoOp(string address, string approvedHash)
    {
        return File.Exists(journal) &&
            String.Equals(ReadJournalHash(address), approvedHash, StringComparison.OrdinalIgnoreCase) &&
            Verify(address);
    }
    internal void Recover()
    {
        if (!File.Exists(journal))
        {
            if (Directory.GetFiles(Path.GetDirectoryName(journal),
                Path.GetFileName(journal) + ".rolledback.*").Length != 0) return;
            throw new InvalidOperationException("No ChildStream LAN firewall journal exists.");
        }
        LanFirewallPlan plan = ReadJournal();
        LanFirewallObservation state = host.Read(plan.Address, family, executable);
        if (state == null || !state.Complete || state.OwnedRules.Any(r =>
            !Exact(r, plan.Tcp) && !Exact(r, plan.Udp)))
            throw new InvalidOperationException("LAN rules drifted; recovery preserved them for review.");
        foreach (LanFirewallRule rule in state.OwnedRules)
            host.Remove(rule);
        state = host.Read(plan.Address, family, executable);
        if (state == null || !state.Complete || state.OwnedRules.Count != 0)
            throw new InvalidOperationException("LAN rule restoration is incomplete.");
        string retired = journal + ".rolledback." + plan.Hash;
        if (File.Exists(retired))
        {
            if (!String.Equals(File.ReadAllText(retired), File.ReadAllText(journal), StringComparison.Ordinal))
                throw new InvalidOperationException("A different retired LAN journal occupies the plan identity.");
            File.Delete(journal);
        }
        else File.Move(journal, retired);
    }
    internal void RecoverApproved(string address, string approvedHash)
    {
        LanFirewallPlan plan = ReadJournal();
        if (!String.Equals(plan.Address, address, StringComparison.Ordinal) ||
            !String.Equals(plan.Hash, approvedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The reviewed LAN rule journal does not match this recovery request.");
        Recover();
    }
}
