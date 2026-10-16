using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

// The reader executes only the protected fixed observation script. The writer
// can add/remove only the two transaction-specified TermService block rules.
internal sealed class WindowsRdpContainmentHost : IRdpContainmentHost
{
    private readonly string script;
    internal WindowsRdpContainmentHost(string scriptPath) { script = scriptPath; }
    private static Dictionary<string, object> Map(object value)
    {
        var map = value as Dictionary<string, object>;
        if (map == null) throw new InvalidDataException("RDP policy observation object is missing.");
        return map;
    }
    private static object At(Dictionary<string, object> map, string key)
    {
        object value;
        if (!map.TryGetValue(key, out value) || value == null)
            throw new InvalidDataException("RDP policy observation lacks " + key + ".");
        return value;
    }
    private static string Str(Dictionary<string, object> map, string key)
    { return Convert.ToString(At(map, key), System.Globalization.CultureInfo.InvariantCulture); }
    private static bool Bool(Dictionary<string, object> map, string key)
    {
        object value = At(map, key);
        if (value is bool) return (bool)value;
        throw new InvalidDataException("RDP policy Boolean has an unknown shape: " + key);
    }
    private static int Int(Dictionary<string, object> map, string key)
    {
        int result;
        if (!Int32.TryParse(Str(map, key), out result))
            throw new InvalidDataException("RDP policy integer has an unknown shape: " + key);
        return result;
    }
    private static object[] Rows(Dictionary<string, object> map, string key)
    {
        object[] rows = At(map, key) as object[];
        if (rows == null) throw new InvalidDataException("RDP policy rows have an unknown shape: " + key);
        return rows;
    }
    private static string Address(object value)
    {
        if (value is string) return (string)value == "Any" ? "*" : (string)value;
        object[] items = value as object[];
        if (items == null || items.Length == 0 || items.Any(x => !(x is string)))
            throw new InvalidDataException("Firewall address filter has an unknown shape.");
        return String.Join(",", items.Cast<string>());
    }
    private static int Protocol(string raw)
    {
        if (raw == "TCP" || raw == "6") return 6;
        if (raw == "UDP" || raw == "17") return 17;
        throw new InvalidDataException("Firewall protocol is unknown.");
    }
    private static int Profiles(string raw)
    {
        if (raw == "Any" || raw == "Domain, Private, Public" || raw == "7") return 7;
        int value = 0;
        foreach (string item in raw.Split(','))
            switch (item.Trim()) {
                case "Domain": value |= 1; break; case "Private": value |= 2; break;
                case "Public": value |= 4; break;
                default: throw new InvalidDataException("Firewall profile mask is unknown.");
            }
        return value;
    }
    private static string OneAlias(object value)
    {
        object[] aliases = value as object[];
        if (aliases == null || aliases.Length != 1 || !(aliases[0] is string))
            throw new InvalidDataException("Firewall interface alias is ambiguous.");
        return (string)aliases[0];
    }
    private static string Enforcement(object value)
    {
        object[] states = value as object[];
        if (states == null || states.Length != 1 || Convert.ToString(states[0]) != "1")
            return "NotFull";
        return "Full";
    }
    private static RdpContainmentRule Rule(object value)
    {
        var row = Map(value);
        string type = Str(row, "InterfaceTypes");
        return new RdpContainmentRule {
            Name = Str(row, "Name"), Description = Str(row, "Description"), Service = Str(row, "Service"),
            Protocol = Protocol(Str(row, "Protocol")), Profiles = Profiles(Str(row, "Profiles")),
            Direction = Str(row, "Direction") == "Inbound" ? 1 : -1,
            Action = Str(row, "Action") == "Block" ? 0 : -1,
            Enabled = Str(row, "Enabled") == "True", EdgeTraversal = Str(row, "EdgeTraversal") != "Block",
            OverrideBlockRules = Str(row, "OverrideBlockRules") == "True",
            LocalPorts = Address(At(row, "LocalPorts")), RemotePorts = Address(At(row, "RemotePorts")),
            LocalAddresses = Address(At(row, "LocalAddresses")),
            RemoteAddresses = Address(At(row, "RemoteAddresses")),
            InterfaceTypes = type == "Any" ? "All" : type,
            InterfaceAlias = OneAlias(At(row, "InterfaceAlias")),
            Application = Str(row, "Application"),
            Authentication = Str(row, "Authentication"), Encryption = Str(row, "Encryption"),
            LocalUser = Str(row, "LocalUser"), RemoteUser = Str(row, "RemoteUser"),
            RemoteMachine = Str(row, "RemoteMachine"),
            SourceType = Str(row, "SourceType"), PrimaryStatus = Str(row, "PrimaryStatus"),
            EnforcementStatus = Enforcement(At(row, "EnforcementStatus")) };
    }
    internal static RdpContainmentObservation Parse(string json)
    {
        if (String.IsNullOrWhiteSpace(json) || json.Length > 256 * 1024)
            throw new InvalidDataException("RDP policy observation is empty or oversized.");
        var root = Map(new JavaScriptSerializer { MaxJsonLength = 256 * 1024 }.DeserializeObject(json));
        if (Str(root, "Schema") != "ChildStream.RdpContainmentObservation.v1")
            throw new InvalidDataException("RDP observation schema changed.");
        var result = new RdpContainmentObservation {
            Complete = true, FeatureKnown = Bool(root, "FeatureKnown"),
            FeatureEnabled = Bool(root, "FeatureEnabled"), PolicyDenied = Bool(root, "PolicyDenied"),
            TermServiceState = Str(root, "TermServiceState"),
            ListenersAbsent = Bool(root, "ListenersAbsent"),
            ConfiguredRdpPort = Int(root, "ConfiguredRdpPort"), BypassCountKnown = true,
            BypassCount = Int(root, "BypassCount"),
            OrdinaryAllowCount = Int(root, "OrdinaryAllowCount") };
        if (result.BypassCount < 0 || result.OrdinaryAllowCount < 0)
            throw new InvalidDataException("Firewall rule counts are invalid.");
        foreach (object value in Rows(root, "Profiles"))
        {
            var row = Map(value);
            var profile = new RdpContainmentProfile { Name = Str(row, "Name"),
                Enabled = Str(row, "Enabled"), DefaultInboundAction = Str(row, "DefaultInboundAction"),
                AllowLocalFirewallRules = Str(row, "AllowLocalFirewallRules"), ExclusionsKnown = true };
            foreach (object alias in Rows(row, "ExcludedInterfaces"))
            {
                if (!(alias is string)) throw new InvalidDataException("Profile exclusion is ambiguous.");
                profile.ExcludedInterfaces.Add((string)alias);
            }
            result.Profiles.Add(profile);
        }
        foreach (object value in Rows(root, "PersistentRules")) result.PersistentRules.Add(Rule(value));
        foreach (object value in Rows(root, "ActiveRules")) result.ActiveRules.Add(Rule(value));
        return result;
    }
    public RdpContainmentObservation Read()
    { return Parse(ScriptProbeInventory.Run(script, "", "RDP containment policy observation")); }
    private static dynamic Policy()
    { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)); }
    internal static bool AnyOwnedPolicyRule()
    {
        foreach (dynamic raw in Policy().Rules)
        {
            string name = Convert.ToString(raw.Name);
            if (name == RdpContainmentTransaction.Expected(6).Name ||
                name == RdpContainmentTransaction.Expected(17).Name) return true;
        }
        return false;
    }
    public void Add(RdpContainmentRule rule)
    {
        RdpContainmentRule expected = RdpContainmentTransaction.Expected(rule.Protocol);
        if (rule.Configuration() != expected.Configuration())
            throw new InvalidDataException("Only an exact ChildStream TermService block may be added.");
        dynamic policy = Policy();
        foreach (dynamic old in policy.Rules)
            if (String.Equals(Convert.ToString(old.Name), rule.Name, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("RDP containment rule name is occupied.");
        dynamic created = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
        created.Name = rule.Name; created.Description = rule.Description;
        created.Direction = 1; created.Action = 0; created.Protocol = rule.Protocol;
        created.ServiceName = "TermService"; created.LocalPorts = "*"; created.RemotePorts = "*";
        created.LocalAddresses = "*"; created.RemoteAddresses = rule.RemoteAddresses;
        created.InterfaceTypes = "All"; created.Profiles = 7;
        created.EdgeTraversal = false; created.Enabled = true;
        policy.Rules.Add(created);
    }
    public void Remove(RdpContainmentRule expected)
    {
        if (expected.Configuration() != RdpContainmentTransaction.Expected(expected.Protocol).Configuration())
            throw new InvalidDataException("Only an exact ChildStream block may be removed.");
        RdpContainmentObservation state = Read();
        if (state.PersistentRules.Count(r => r.Name == expected.Name) != 1 ||
            state.PersistentRules.Single(r => r.Name == expected.Name).Configuration() != expected.Configuration())
            throw new InvalidOperationException("Owned RDP containment rule drifted before removal.");
        // COM has no compare-and-remove primitive. The protected journal stays
        // until the independent post-removal readback succeeds.
        Policy().Rules.Remove(expected.Name);
    }
}
