using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

// This is an owned firewall transaction, not a child-feature authorization.
// ActiveStore policy readback cannot prove packet filtering or child loopback.
internal sealed class RdpContainmentRule
{
    internal string Name, Description, Service, RemoteAddresses, LocalAddresses, LocalPorts, RemotePorts,
        InterfaceTypes, InterfaceAlias, Application, Authentication, Encryption,
        LocalUser, RemoteUser, RemoteMachine, SourceType, PrimaryStatus, EnforcementStatus;
    internal int Protocol, Profiles, Direction, Action;
    internal bool Enabled, EdgeTraversal, OverrideBlockRules;
    internal string Configuration()
    { return String.Join("|", new[] { Name, Description, Service, RemoteAddresses, LocalAddresses,
        LocalPorts, RemotePorts, InterfaceTypes, InterfaceAlias, Application,
        Authentication, Encryption, LocalUser, RemoteUser, RemoteMachine,
        Protocol.ToString(), Profiles.ToString(),
        Direction.ToString(), Action.ToString(), Enabled.ToString(), EdgeTraversal.ToString(),
        OverrideBlockRules.ToString() }); }
}

internal sealed class RdpContainmentProfile
{
    internal string Name, Enabled, DefaultInboundAction, AllowLocalFirewallRules;
    internal bool ExclusionsKnown;
    internal readonly List<string> ExcludedInterfaces = new List<string>();
    internal string Canonical()
    { return Name + "|" + Enabled + "|" + DefaultInboundAction + "|" +
        AllowLocalFirewallRules + "|" + ExclusionsKnown + "|" +
        String.Join(",", ExcludedInterfaces.OrderBy(x => x, StringComparer.Ordinal)); }
}

internal sealed class RdpContainmentObservation
{
    internal bool Complete, FeatureKnown, FeatureEnabled, PolicyDenied,
        ListenersAbsent, BypassCountKnown;
    internal string TermServiceState;
    internal int BypassCount, OrdinaryAllowCount, ConfiguredRdpPort;
    internal readonly List<RdpContainmentProfile> Profiles = new List<RdpContainmentProfile>();
    internal readonly List<RdpContainmentRule> PersistentRules = new List<RdpContainmentRule>();
    internal readonly List<RdpContainmentRule> ActiveRules = new List<RdpContainmentRule>();
    internal string Baseline()
    { return Complete + "|" + FeatureKnown + "|" + FeatureEnabled + "|" + PolicyDenied + "|" +
        TermServiceState + "|" + ListenersAbsent + "|" + ConfiguredRdpPort + "|" +
        BypassCountKnown + "|" + BypassCount + "|" + String.Join(";",
        Profiles.OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => p.Canonical())); }
}

internal interface IRdpContainmentHost
{
    RdpContainmentObservation Read();
    void Add(RdpContainmentRule rule);
    void Remove(RdpContainmentRule rule);
}

internal sealed class RdpContainmentPlan
{
    internal string Hash, BaselineHash, AccountHash;
}

internal sealed class RdpContainmentTransaction
{
    internal const string RemoteNonLoopback =
        "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    private const string Marker = "ChildStream.RdpContainment.v1";
    private readonly IRdpContainmentHost host;
    private readonly string journal, accountHash;
    internal RdpContainmentTransaction(IRdpContainmentHost host, string protectedRoot, string accountHash)
    {
        if (host == null || !ProductInstallPayload.IsHex256(accountHash))
            throw new InvalidDataException("RDP containment needs a concrete host and requesting account binding.");
        string root = InstallerPolicy.ValidateCanonicalFilePath(protectedRoot, true)
            .TrimEnd(Path.DirectorySeparatorChar);
        this.host = host; this.accountHash = accountHash.ToLowerInvariant();
        journal = Path.Combine(root, "rdp-containment.journal");
    }
    private static string Digest(string value)
    { using (var sha = SHA256.Create())
        return ProductInstallPayload.Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(value))); }
    internal static RdpContainmentRule Expected(int protocol)
    {
        if (protocol != 6 && protocol != 17) throw new InvalidDataException("Only RDP TCP and UDP are in scope.");
        return new RdpContainmentRule {
            Name = protocol == 6 ? "ChildStream RDP containment TCP v1" : "ChildStream RDP containment UDP v1",
            Description = "ChildStream approved non-loopback TermService containment",
            Service = "TermService", Protocol = protocol, Profiles = 7, Direction = 1, Action = 0,
            RemoteAddresses = RemoteNonLoopback, LocalAddresses = "*", LocalPorts = "*",
            RemotePorts = "*", InterfaceTypes = "All", InterfaceAlias = "Any", Application = "Any",
            Authentication = "NotRequired", Encryption = "NotRequired",
            LocalUser = "Any", RemoteUser = "Any", RemoteMachine = "Any", Enabled = true,
            EdgeTraversal = false, OverrideBlockRules = false,
            SourceType = "Local", PrimaryStatus = "OK", EnforcementStatus = "Full" };
    }
    private static RdpContainmentRule[] Rules()
    { return new[] { Expected(6), Expected(17) }; }
    private static void RequireBaseline(RdpContainmentObservation state)
    {
        if (state == null || !state.Complete || !state.FeatureKnown || state.FeatureEnabled ||
            !state.PolicyDenied ||
            (state.TermServiceState != "Running" && state.TermServiceState != "Stopped") ||
            !state.ListenersAbsent ||
            state.ConfiguredRdpPort < 1 || state.ConfiguredRdpPort > 65535 ||
            !state.BypassCountKnown || state.BypassCount != 0)
            throw new InvalidOperationException("Child feature, ordinary RDP policy, TermService/listener baseline, or bypass policy is unknown or unsafe.");
        if (state.Profiles.Count != 3 || state.Profiles.Select(p => p.Name).Distinct().Count() != 3 ||
            new[] { "Domain", "Private", "Public" }.Any(name => !state.Profiles.Any(p => p.Name == name)))
            throw new InvalidOperationException("Effective firewall profile coverage is incomplete.");
        foreach (RdpContainmentProfile profile in state.Profiles)
            if (profile.Enabled != "True" || profile.DefaultInboundAction != "Block" ||
                profile.AllowLocalFirewallRules != "True" ||
                !profile.ExclusionsKnown || profile.ExcludedInterfaces.Count != 0)
                throw new InvalidOperationException("Effective firewall profile, local-rule merge, or interface coverage is uncertain.");
    }
    private static bool Exact(RdpContainmentRule actual, RdpContainmentRule expected, bool effective)
    { return actual != null && String.Equals(actual.Configuration(), expected.Configuration(),
        StringComparison.OrdinalIgnoreCase) && (!effective ||
        actual.SourceType == "Local" && actual.PrimaryStatus == "OK" &&
        actual.EnforcementStatus == "Full"); }
    private static bool OwnedExactly(IList<RdpContainmentRule> rules, bool effective)
    { return rules != null && rules.Count == 2 &&
        Rules().All(expected => rules.Count(actual => Exact(actual, expected, effective)) == 1); }
    internal static bool Configured(RdpContainmentObservation state)
    {
        try { RequireBaseline(state); }
        catch { return false; }
        return OwnedExactly(state.PersistentRules, false) && OwnedExactly(state.ActiveRules, true);
    }
    private static string PlanHash(string baselineHash, string account)
    { return Digest(Marker + "\n" + account + "\n" + baselineHash + "\n" +
        String.Join("\n", Rules().Select(r => r.Configuration())) + "\n"); }
    internal RdpContainmentPlan Plan()
    {
        RdpContainmentObservation state = host.Read(); RequireBaseline(state);
        if (state.PersistentRules.Count != 0 || state.ActiveRules.Count != 0 || File.Exists(journal))
            throw new InvalidOperationException("An owned containment rule or journal already exists; inspect or recover it.");
        string baseline = Digest(state.Baseline());
        return new RdpContainmentPlan { AccountHash = accountHash, BaselineHash = baseline,
            Hash = PlanHash(baseline, accountHash) };
    }
    private RdpContainmentPlan ReadJournal()
    {
        InstallerPolicy.ValidateCanonicalFilePath(journal);
        string[] lines = File.ReadAllLines(journal);
        if (lines.Length != 4 || lines[0] != Marker ||
            !ProductInstallPayload.IsHex256(lines[1]) || !ProductInstallPayload.IsHex256(lines[2]) ||
            !ProductInstallPayload.IsHex256(lines[3]) || lines[1] != accountHash ||
            lines[3] != PlanHash(lines[2], lines[1]))
            throw new InvalidDataException("RDP containment journal is not exact or belongs to another account.");
        return new RdpContainmentPlan { AccountHash = lines[1], BaselineHash = lines[2], Hash = lines[3] };
    }
    internal string JournalHash() { return ReadJournal().Hash; }
    internal bool Verify()
    {
        if (!File.Exists(journal)) return false;
        RdpContainmentPlan saved = ReadJournal();
        RdpContainmentObservation state = host.Read();
        return Digest(state.Baseline()) == saved.BaselineHash && Configured(state);
    }
    internal void Apply(string approvedHash)
    {
        if (!ProductInstallPayload.IsHex256(approvedHash))
            throw new InvalidOperationException("Exact containment approval hash is required.");
        if (File.Exists(journal))
        {
            if (ReadJournal().Hash != approvedHash || !Verify())
                throw new InvalidOperationException("Interrupted or changed containment needs reviewed recovery.");
            return;
        }
        RdpContainmentPlan plan = Plan();
        if (!String.Equals(plan.Hash, approvedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Containment source or approved plan changed.");
        // Record intent durably before the first non-atomic firewall API call.
        byte[] bytes = Encoding.UTF8.GetBytes(Marker + "\n" + accountHash + "\n" +
            plan.BaselineHash + "\n" + plan.Hash + "\n");
        using (var file = new FileStream(journal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
        foreach (RdpContainmentRule rule in Rules()) host.Add(rule);
        if (!Verify()) throw new InvalidOperationException("Owned containment is not effective in ActiveStore; retain journal and review recovery.");
    }
    internal void Recover(string approvedHash)
    {
        RdpContainmentPlan saved = ReadJournal();
        if (!String.Equals(saved.Hash, approvedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Exact containment recovery hash differs.");
        RdpContainmentObservation state = host.Read(); RequireBaseline(state);
        if (Digest(state.Baseline()) != saved.BaselineHash ||
            state.PersistentRules.Any(r => !Rules().Any(e => Exact(r, e, false))) ||
            state.ActiveRules.Any(r => !Rules().Any(e => Exact(r, e, false))))
            throw new InvalidOperationException("Feature/listener baseline or owned firewall rules changed; protection retained.");
        foreach (RdpContainmentRule expected in Rules())
            if (state.PersistentRules.Any(r => Exact(r, expected, false))) host.Remove(expected);
        state = host.Read(); RequireBaseline(state);
        if (Digest(state.Baseline()) != saved.BaselineHash ||
            state.PersistentRules.Count != 0 || state.ActiveRules.Count != 0)
            throw new InvalidOperationException("Containment removal was incomplete; journal retained.");
        string retired = journal + ".restored." + saved.Hash;
        if (File.Exists(retired))
        {
            if (File.ReadAllText(retired) != File.ReadAllText(journal))
                throw new InvalidOperationException("A different retired containment record occupies this identity.");
            File.Delete(journal);
        }
        else File.Move(journal, retired);
    }
}
