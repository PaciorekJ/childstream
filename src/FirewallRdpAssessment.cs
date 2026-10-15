using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

// A local ActiveStore assessment. Excluded means a rule cannot authorize the
// configured ordinary RDP listener, even if that listener starts during Stage A.
// It does not assert that every network path or future firewall policy is closed.
internal enum FirewallRuleDisposition { Excluded, PotentiallyPermissive, Unknown }

internal sealed class FirewallRdpAssessment
{
    internal bool ProfilesAccepted;
    internal bool CoverageAccepted;
    internal int Excluded, PotentiallyPermissive, Unknown;
    internal readonly object Canonical;
    internal bool Accepted { get { return ProfilesAccepted && CoverageAccepted &&
        PotentiallyPermissive == 0 && Unknown == 0; } }

    private FirewallRdpAssessment(object canonical) { Canonical = canonical; }

    private static Dictionary<string, object> Map(object value)
    { return value as Dictionary<string, object> ?? new Dictionary<string, object>(); }
    private static object At(object value, string key)
    { object found; return Map(value).TryGetValue(key, out found) ? found : null; }
    private static string Text(object value) { return value as string; }
    private static object[] Array(object value) { return value as object[] ?? new object[0]; }
    private static bool Is(object value, string state) { return Text(At(value, "State")) == state; }
    private static int? Number(object value)
    {
        if (value is int) return (int)value;
        if (value is long && (long)value >= int.MinValue && (long)value <= int.MaxValue) return (int)(long)value;
        return null;
    }
    private static string Switch(object value)
    {
        // GpoBoolean/Enabled: NotConfigured=0, True=1, False=2.
        if (value is bool) return (bool)value ? "True" : "False";
        int? n = Number(value);
        if (n.HasValue) return n.Value == 1 ? "True" : n.Value == 2 ? "False" : "Unknown";
        string s = Text(value);
        return s == "True" || s == "False" ? s : "Unknown";
    }
    private static string Action(object value)
    {
        // The NetSecurity Action enum serializes Allow=2 and Block=4.
        int? n = Number(value);
        if (n.HasValue) return n.Value == 2 ? "Allow" : n.Value == 4 ? "Block" : "Unknown";
        string s = Text(value);
        return s == "Allow" || s == "Block" ? s : "Unknown";
    }
    private static string Direction(object value)
    {
        int? n = Number(value);
        if (n.HasValue) return n.Value == 1 ? "Inbound" : n.Value == 2 ? "Outbound" : "Unknown";
        string s = Text(value);
        return s == "Inbound" || s == "Outbound" ? s : "Unknown";
    }
    private static string Protocol(object value)
    {
        string s = Text(value);
        if (s == "Any" || s == "TCP" || s == "UDP") return s;
        if (s == "ICMPv4") return "Other:1";
        if (s == "ICMPv6") return "Other:58";
        int n;
        if (Number(value).HasValue) n = Number(value).Value;
        else if (s == null || !int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out n)) return "Unknown";
        if (n < 0 || n > 255) return "Unknown";
        return n == 6 ? "TCP" : n == 17 ? "UDP" : "Other:" + n.ToString(CultureInfo.InvariantCulture);
    }
    private static string Profiles(object value)
    {
        string s = Text(value);
        if (s == "Any") return "Any";
        if (s == null) return "Unknown";
        string[] bits = s.Split(',');
        var accepted = new HashSet<string>(StringComparer.Ordinal);
        foreach (string bit in bits)
        {
            string name = bit.Trim();
            if (name != "Domain" && name != "Private" && name != "Public" || !accepted.Add(name))
                return "Unknown";
        }
        return String.Join(",", accepted.OrderBy(x => x, StringComparer.Ordinal));
    }
    private static string Port(object value)
    {
        string s = value as string;
        if (s == "Any") return "Any";
        int n;
        if (Number(value).HasValue) n = Number(value).Value;
        else if (s != null && int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out n)) { }
        else
        {
            Match range = Regex.Match(s ?? "", @"^([0-9]{1,5})-([0-9]{1,5})$");
            int lo, hi;
            if (!range.Success || !int.TryParse(range.Groups[1].Value, out lo) ||
                !int.TryParse(range.Groups[2].Value, out hi) || lo < 1 || hi > 65535 || lo > hi) return "Unknown";
            return lo.ToString(CultureInfo.InvariantCulture) + "-" + hi.ToString(CultureInfo.InvariantCulture);
        }
        return n >= 1 && n <= 65535 ? n.ToString(CultureInfo.InvariantCulture) : "Unknown";
    }
    private static string[] Ports(object value)
    {
        object[] items = Array(value);
        if (items.Length == 0) return new[] { "Unknown" };
        string[] result = items.Select(Port).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        return result.Contains("Any") && result.Length != 1 ? new[] { "Unknown" } : result;
    }
    private static bool Covers(string port, int target)
    {
        if (port == "Any") return true;
        if (port == "Unknown") return true;
        int dash = port.IndexOf('-');
        if (dash < 0) return int.Parse(port, CultureInfo.InvariantCulture) == target;
        return target >= int.Parse(port.Substring(0, dash), CultureInfo.InvariantCulture) &&
            target <= int.Parse(port.Substring(dash + 1), CultureInfo.InvariantCulture);
    }
    private static bool AddressKnown(string address)
    {
        if (String.IsNullOrEmpty(address)) return false;
        if (new[] { "Any", "LocalSubnet", "LocalSubnet4", "LocalSubnet6", "Internet",
            "Intranet", "DNS", "DHCP", "WINS", "DefaultGateway" }.Contains(address)) return true;
        IPAddress parsed;
        if (IPAddress.TryParse(address, out parsed)) return true;
        string[] parts = address.Split('/');
        int prefix;
        if (parts.Length == 2 && IPAddress.TryParse(parts[0], out parsed) &&
            int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix))
            return prefix >= 0 && prefix <= (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
        parts = address.Split('-');
        IPAddress first, second;
        return parts.Length == 2 && IPAddress.TryParse(parts[0], out first) && IPAddress.TryParse(parts[1], out second) &&
            first.AddressFamily == second.AddressFamily;
    }
    private static string[] Addresses(object value)
    {
        object[] items = Array(value);
        if (items.Length == 0) return new[] { "Unknown" };
        return items.Select(x => Text(x) != null && AddressKnown(Text(x)) ? Text(x) : "Unknown")
            .Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }
    private static bool HashKnown(object value)
    { return Regex.IsMatch(Text(value) ?? "", "^[0-9a-f]{64}$"); }
    private static string KnownText(object value, params string[] accepted)
    {
        string s = Text(value);
        return s != null && accepted.Contains(s, StringComparer.Ordinal) ? s : "Unknown";
    }
    private static object CanonicalRule(object rule, string enabled, string direction, string action,
        string profiles, string protocol, string[] localPorts, string[] remotePorts,
        string[] localAddresses, string[] remoteAddresses)
    {
        var copy = new Dictionary<string, object>(Map(rule), StringComparer.Ordinal);
        copy["Enabled"] = enabled; copy["Direction"] = direction; copy["Action"] = action;
        copy["Profile"] = profiles; copy["Protocol"] = protocol;
        copy["LocalPort"] = localPorts; copy["RemotePort"] = remotePorts;
        copy["LocalAddress"] = localAddresses; copy["RemoteAddress"] = remoteAddresses;
        return copy;
    }
    internal static FirewallRdpAssessment Assess(object profiles, object firewall, object services, object configuredPort)
    {
        var normalizedProfiles = new List<object>();
        var normalizedRules = new List<object>();
        var result = new FirewallRdpAssessment(new object[] { normalizedProfiles, normalizedRules });
        var profileNames = new HashSet<string>(StringComparer.Ordinal);
        result.ProfilesAccepted = Is(profiles, "Accessible") && Array(At(profiles, "Items")).Length == 3;
        foreach (object item in Array(At(profiles, "Items")))
        {
            string name = KnownText(At(item, "Name"), "Domain", "Private", "Public");
            string enabled = Switch(At(item, "Enabled"));
            string inbound = Action(At(item, "DefaultInboundAction"));
            normalizedProfiles.Add(new Dictionary<string, object> {
                { "Name", name }, { "Enabled", enabled }, { "DefaultInboundAction", inbound } });
            if (name == "Unknown" || !profileNames.Add(name) || enabled != "True" || inbound != "Block")
                result.ProfilesAccepted = false;
        }
        if (profileNames.Count != 3) result.ProfilesAccepted = false;
        int? port = Number(At(configuredPort, "Data"));
        bool portKnown = Is(configuredPort, "Accessible") && port.HasValue && port.Value >= 1 && port.Value <= 65535;
        string termHash = Text(At(services, "TermServiceImageHash"));
        bool termImageKnown = Is(services, "Accessible") &&
            Text(At(services, "TermServiceImageState")) == "Accessible" && HashKnown(termHash);
        bool classicHost = At(services, "TermServiceIsClassicHost") is bool &&
            (bool)At(services, "TermServiceIsClassicHost");
        result.CoverageAccepted = Is(firewall, "Accessible") && Number(At(firewall, "UnknownHeaderCount")) == 0 &&
            portKnown && termImageKnown;
        int selectedInboundAllow = 0, broadInboundAllow = 0;
        foreach (object rule in Array(At(firewall, "Items")))
        {
            string enabled = Switch(At(rule, "Enabled")), direction = Direction(At(rule, "Direction"));
            string action = Action(At(rule, "Action")), profile = Profiles(At(rule, "Profile"));
            string protocol = Protocol(At(rule, "Protocol"));
            string[] localPorts = Ports(At(rule, "LocalPort")), remotePorts = Ports(At(rule, "RemotePort"));
            string[] localAddresses = Addresses(At(rule, "LocalAddress")), remoteAddresses = Addresses(At(rule, "RemoteAddress"));
            normalizedRules.Add(CanonicalRule(rule, enabled, direction, action, profile, protocol,
                localPorts, remotePorts, localAddresses, remoteAddresses));
            if (enabled == "True" && direction == "Inbound" && action == "Allow")
            {
                selectedInboundAllow++;
                if (localPorts.Contains("Any")) broadInboundAllow++;
            }
            if (enabled == "Unknown" || direction == "Unknown" || action == "Unknown" || profile == "Unknown")
            { result.Unknown++; continue; }
            if (enabled == "False" || direction == "Outbound" || action == "Block")
            { result.Excluded++; continue; }
            if (!(At(rule, "RdpNamed") is bool)) { result.Unknown++; continue; }
            if ((bool)At(rule, "RdpNamed")) { result.PotentiallyPermissive++; continue; }
            if (protocol.StartsWith("Other:", StringComparison.Ordinal))
            { result.Excluded++; continue; }
            if (portKnown && protocol != "Unknown" && !localPorts.Contains("Unknown") &&
                !localPorts.Any(x => Covers(x, 3389) || Covers(x, 3392) || Covers(x, port.Value)))
            { result.Excluded++; continue; }
            string service = Text(At(rule, "Service"));
            string programState = KnownText(At(rule, "ProgramState"), "Any", "Accessible", "Unknown");
            string packageState = KnownText(At(rule, "PackageState"), "Any", "AppPackage", "Unknown");
            if (service != null && service.Length > 0 &&
                !String.Equals(service, "Any", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(service, "TermService", StringComparison.OrdinalIgnoreCase) ||
                programState == "Accessible" && HashKnown(At(rule, "ProgramHash")) &&
                    Text(At(rule, "ProgramHash")) != termHash ||
                packageState == "AppPackage" && HashKnown(At(rule, "PackageHash")) && classicHost)
            { result.Excluded++; continue; }
            bool requiredKnown = protocol != "Unknown" && !localPorts.Contains("Unknown") &&
                !remotePorts.Contains("Unknown") && !localAddresses.Contains("Unknown") &&
                !remoteAddresses.Contains("Unknown") &&
                KnownText(At(rule, "InterfaceType"), "Any", "Lan", "Wireless", "RemoteAccess") != "Unknown" &&
                KnownText(At(rule, "PolicyStoreSourceType"), "Local", "GroupPolicy", "Dynamic", "Generated", "Hardcoded", "Mdm") != "Unknown" &&
                KnownText(At(rule, "PrimaryStatus"), "OK", "Inactive", "Error") != "Unknown" &&
                Number(At(rule, "StatusCode")) == 65536 &&
                At(rule, "RdpNamed") is bool &&
                KnownText(At(rule, "Authentication"), "NotRequired", "Required", "NoEncap") != "Unknown" &&
                KnownText(At(rule, "Encryption"), "NotRequired", "Required", "Dynamic") != "Unknown" &&
                Switch(At(rule, "OverrideBlockRules")) != "Unknown" &&
                service != null && service.Length > 0 &&
                programState != "Unknown" && packageState != "Unknown" &&
                !(programState == "Any" && At(rule, "ProgramHash") != null) &&
                !(programState == "Accessible" && !HashKnown(At(rule, "ProgramHash"))) &&
                !(packageState == "Any" && At(rule, "PackageHash") != null) &&
                !(packageState == "AppPackage" && !HashKnown(At(rule, "PackageHash")));
            string[] enforcement = Array(At(rule, "EnforcementStatus")).Select(Text).ToArray();
            if (enforcement.Length == 0 || enforcement.Any(x => !new[] { "Enforced", "ProfileInactive",
                "Disabled", "Duplicate", "NoDynamicTransport", "NoLocalPort", "NoRemoteAddress" }.Contains(x)))
                requiredKnown = false;
            if (!requiredKnown) { result.Unknown++; continue; }
            if (packageState == "AppPackage" && !classicHost)
            { result.Unknown++; continue; }
            if (KnownText(At(rule, "PrimaryStatus"), "OK") == "OK" &&
                enforcement.Contains("Enforced"))
                result.PotentiallyPermissive++;
            else result.Unknown++;
        }
        if (Number(At(firewall, "SelectedInboundAllowCount")) != selectedInboundAllow ||
            Number(At(firewall, "BroadInboundAllowCount")) != broadInboundAllow)
            result.CoverageAccepted = false;
        return result;
    }
}
