using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Management;
using System.Collections;

// Host adapter for a future separately approved LAN transaction. It is never
// called by the offline suite against workstation network/firewall state.
internal sealed class WindowsLanFirewallHost : ILanFirewallHost
{
    // NetworkInterfaceType.Ethernet also describes host vEthernet adapters.
    // Require an exact CIM identity and positive hardware/nonvirtual evidence.
    internal static bool IsPhysicalAdapterEvidence(string expectedGuid, int expectedIndex,
        string observedGuid, int observedIndex, bool? hardware, bool? virtualAdapter,
        string pnpDeviceId)
    {
        Guid expected, observed;
        return Guid.TryParse(expectedGuid, out expected) && Guid.TryParse(observedGuid, out observed) &&
            expected == observed && expectedIndex == observedIndex && hardware == true &&
            virtualAdapter == false && !String.IsNullOrWhiteSpace(pnpDeviceId);
    }
    internal static bool IsSelectedPrivateProfileEvidence(int expectedIndex, string expectedAlias,
        int observedIndex, string observedAlias, int networkCategory, int activeProfiles)
    {
        return expectedIndex > 0 && expectedIndex == observedIndex &&
            String.Equals(expectedAlias, observedAlias, StringComparison.Ordinal) &&
            networkCategory == 1 && (activeProfiles & 2) != 0;
    }
    private static bool IsPhysicalAdapter(NetworkInterface adapter)
    {
        int index = adapter.GetIPProperties().GetIPv4Properties().Index;
        int matches = 0;
        bool accepted = false;
        var scope = new ManagementScope(@"\\.\root\StandardCimv2");
        scope.Connect();
        using (var search = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT InterfaceGuid, InterfaceIndex, HardwareInterface, Virtual, PnPDeviceID FROM MSFT_NetAdapter")))
        using (var rows = search.Get())
            foreach (ManagementBaseObject row in rows)
            {
                Guid expected, observed;
                if (!Guid.TryParse(adapter.Id, out expected) ||
                    !Guid.TryParse(Convert.ToString(row["InterfaceGuid"]), out observed) ||
                    expected != observed) continue;
                matches++;
                int observedIndex;
                if (!Int32.TryParse(Convert.ToString(row["InterfaceIndex"]), out observedIndex)) continue;
                accepted = IsPhysicalAdapterEvidence(adapter.Id, index,
                    Convert.ToString(row["InterfaceGuid"]), observedIndex,
                    row["HardwareInterface"] as bool?, row["Virtual"] as bool?,
                    Convert.ToString(row["PnPDeviceID"]));
            }
        return matches == 1 && accepted;
    }
    private static bool SelectedPrivateProfile(NetworkInterface adapter, int activeProfiles)
    {
        int index = adapter.GetIPProperties().GetIPv4Properties().Index;
        int matches = 0; bool privateProfile = false;
        var scope = new ManagementScope(@"\\.\root\StandardCimv2");
        scope.Connect();
        using (var search = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT InterfaceIndex, InterfaceAlias, NetworkCategory FROM MSFT_NetConnectionProfile")))
        using (var rows = search.Get())
            foreach (ManagementBaseObject row in rows)
            {
                if (Convert.ToInt32(row["InterfaceIndex"]) != index) continue;
                matches++;
                privateProfile = IsSelectedPrivateProfileEvidence(index, adapter.Name,
                    Convert.ToInt32(row["InterfaceIndex"]), Convert.ToString(row["InterfaceAlias"]),
                    Convert.ToInt32(row["NetworkCategory"]), activeProfiles);
            }
        return matches == 1 && privateProfile;
    }
    private static bool FirewallAppliesTo(dynamic policy, string alias)
    {
        object excluded = policy.ExcludedInterfaces[2];
        if (excluded == null || excluded is string) return false; // Unknown provider shape fails closed.
        var list = excluded as IEnumerable;
        if (list == null) return false;
        foreach (object item in list)
            if (String.Equals(Convert.ToString(item), alias, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }
    private static dynamic Policy()
    {
        Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true);
        return Activator.CreateInstance(type);
    }
    private static string Subnet(IPAddress address, IPAddress mask)
    {
        byte[] ip = address.GetAddressBytes(), bits = mask.GetAddressBytes();
        if (ip.Length != 4 || bits.Length != 4) throw new InvalidDataException("LAN interface is not IPv4.");
        int prefix = 0; bool zero = false;
        var network = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            network[i] = (byte)(ip[i] & bits[i]);
            for (int shift = 7; shift >= 0; shift--)
            {
                bool one = ((bits[i] >> shift) & 1) != 0;
                if (one && zero) throw new InvalidDataException("LAN mask is noncontiguous.");
                if (one) prefix++; else zero = true;
            }
        }
        if (prefix < 8 || prefix > 30) throw new InvalidDataException("LAN subnet is unexpectedly broad or narrow.");
        return new IPAddress(network) + "/" + prefix;
    }
    private static bool PortsOverlap(string value, int[] ports)
    {
        if (String.IsNullOrWhiteSpace(value) || value.Equals("Any", StringComparison.OrdinalIgnoreCase) || value == "*") return true;
        foreach (string item in value.Split(','))
        {
            string[] ends = item.Trim().Split('-');
            int first, last;
            if (ends.Length < 1 || ends.Length > 2 || !Int32.TryParse(ends[0], out first) ||
                !Int32.TryParse(ends[ends.Length - 1], out last) || first < 1 || last > 65535 || first > last)
                throw new InvalidDataException("A firewall port expression could not be classified.");
            if (ports.Any(p => p >= first && p <= last)) return true;
        }
        return false;
    }
    private static LanFirewallRule Capture(dynamic rule)
    {
        return new LanFirewallRule { Name = (string)rule.Name,
            Executable = Convert.ToString(rule.ApplicationName), LocalAddress = Convert.ToString(rule.LocalAddresses),
            RemoteSubnet = Convert.ToString(rule.RemoteAddresses), LocalPorts = Convert.ToString(rule.LocalPorts),
            Protocol = Convert.ToInt32(rule.Protocol), Enabled = Convert.ToBoolean(rule.Enabled),
            InboundAllow = Convert.ToInt32(rule.Direction) == 1 && Convert.ToInt32(rule.Action) == 1,
            PrivateOnly = Convert.ToInt32(rule.Profiles) == 2,
            NoEdgeTraversal = !Convert.ToBoolean(rule.EdgeTraversal) };
    }
    public LanFirewallObservation Read(string address, SunshinePortFamily family, string executable)
    {
        IPAddress parsed;
        if (!IPAddress.TryParse(address, out parsed) || parsed.AddressFamily !=
            System.Net.Sockets.AddressFamily.InterNetwork)
            throw new InvalidDataException("LAN address must be concrete IPv4.");
        var found = NetworkInterface.GetAllNetworkInterfaces().SelectMany(n =>
            n.GetIPProperties().UnicastAddresses.Where(a => a.Address.Equals(parsed))
             .Select(a => new { Adapter = n, Address = a })).ToArray();
        var result = new LanFirewallObservation { LocalAddress = address };
        NetworkInterface selectedAdapter = null;
        if (found.Length == 1)
        {
            var item = found[0];
            if ((item.Adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                 item.Adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) &&
                item.Adapter.OperationalStatus == OperationalStatus.Up && item.Address.IPv4Mask != null &&
                IsPhysicalAdapter(item.Adapter))
            {
                result.PhysicalInterfaceUp = true;
                selectedAdapter = item.Adapter;
                result.RemoteSubnet = Subnet(parsed, item.Address.IPv4Mask);
                result.NetworkIdentity = item.Adapter.Id + "|" + address + "|" + result.RemoteSubnet;
            }
        }
        dynamic policy = Policy();
        int activeProfiles = Convert.ToInt32(policy.CurrentProfileTypes);
        result.PrivateProfileActive = selectedAdapter != null && (activeProfiles & 2) != 0 &&
            SelectedPrivateProfile(selectedAdapter, activeProfiles);
        result.FirewallEnabled = Convert.ToBoolean(policy.FirewallEnabled[2]);
        result.DefaultInboundBlocked = Convert.ToInt32(policy.DefaultInboundAction[2]) == 0 &&
            !Convert.ToBoolean(policy.BlockAllInboundTraffic[2]);
        result.LocalRulesEffective = Convert.ToInt32(policy.LocalPolicyModifyState) == 0;
        result.InterfaceFirewallApplies = selectedAdapter != null &&
            FirewallAppliesTo(policy, selectedAdapter.Name);
        foreach (dynamic raw in policy.Rules)
        {
            string name = Convert.ToString(raw.Name);
            bool ownedName = name == "ChildStream LAN TCP v1" || name == "ChildStream LAN UDP v1";
            if (ownedName) { result.OwnedRules.Add(Capture(raw)); continue; }
            if (!Convert.ToBoolean(raw.Enabled) || Convert.ToInt32(raw.Direction) != 1 ||
                (Convert.ToInt32(raw.Profiles) & 2) == 0)
                continue;
            string app = Convert.ToString(raw.ApplicationName);
            if (!String.IsNullOrWhiteSpace(app) && !String.Equals(app, executable, StringComparison.OrdinalIgnoreCase))
                continue;
            int protocol = Convert.ToInt32(raw.Protocol);
            if (protocol != 6 && protocol != 17 && protocol != 256)
                continue;
            string ports = Convert.ToString(raw.LocalPorts);
            if ((protocol == 6 || protocol == 256) && PortsOverlap(ports, family.Tcp) ||
                (protocol == 17 || protocol == 256) && PortsOverlap(ports, family.Udp))
            {
                if (Convert.ToInt32(raw.Action) == 1) result.ForeignAllowRules++;
                else if (Convert.ToInt32(raw.Action) == 0) result.ConflictingBlockRules++;
            }
        }
        result.Complete = true;
        return result;
    }
    public void Add(LanFirewallRule rule)
    {
        dynamic policy = Policy();
        foreach (dynamic existing in policy.Rules)
            if (String.Equals(Convert.ToString(existing.Name), rule.Name, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("A LAN rule name collision exists.");
        dynamic created = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
        created.Name = rule.Name; created.Description = "ChildStream-owned approved LAN streaming ports";
        created.ApplicationName = rule.Executable; created.Protocol = rule.Protocol;
        created.LocalPorts = rule.LocalPorts; created.LocalAddresses = rule.LocalAddress;
        created.RemoteAddresses = rule.RemoteSubnet; created.Profiles = 2;
        created.Direction = 1; created.Action = 1; created.EdgeTraversal = false;
        created.Enabled = true;
        policy.Rules.Add(created);
    }
    public void Remove(LanFirewallRule expected)
    {
        dynamic policy = Policy();
        bool found = false;
        foreach (dynamic raw in policy.Rules)
            if (String.Equals(Convert.ToString(raw.Name), expected.Name, StringComparison.OrdinalIgnoreCase))
            {
                found = true;
                if (!String.Equals(Capture(raw).Canonical(), expected.Canonical(), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Owned LAN rule changed before reversal.");
                break;
            }
        if (!found) return;
        // COM has no compare-and-remove primitive. The durable journal remains
        // until post-verification; concurrent third-party edits require review.
        policy.Rules.Remove(expected.Name);
    }
}
