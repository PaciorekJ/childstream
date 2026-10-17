using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Xml;
using Microsoft.Win32;

// Read-only Security-log and adapter evidence. Unknown virtual topology blocks
// admission; this adapter never enumerates containers, WSL distributions, or apps.
internal sealed class WindowsConnectedQualificationHost : IConnectedQualificationHost
{
    public long UtcNowTicks { get { return DateTime.UtcNow.Ticks; } }
    private static string Field(XmlDocument xml, string name)
    {
        XmlNode node = xml.SelectSingleNode("//*[local-name()='EventData']/*[local-name()='Data' and @Name='" + name + "']");
        return node == null ? null : node.InnerText;
    }
    internal static QualificationDrop ParseSecurityEvent(string xmlText, long recordId,
        long utcTicks, ICollection<string> localAddresses, int rdpPort)
    {
        if (String.IsNullOrEmpty(xmlText) || recordId <= 0 || utcTicks <= 0 ||
            localAddresses == null) return null;
        var xml = new XmlDocument(); xml.XmlResolver = null; xml.LoadXml(xmlText);
        XmlNode eventId = xml.SelectSingleNode("//*[local-name()='System']/*[local-name()='EventID']");
        XmlNode provider = xml.SelectSingleNode("//*[local-name()='System']/*[local-name()='Provider']");
        XmlNode channel = xml.SelectSingleNode("//*[local-name()='System']/*[local-name()='Channel']");
        if (eventId == null || eventId.InnerText != "5152" && eventId.InnerText != "5157" ||
            provider == null || provider.Attributes == null ||
            provider.Attributes["Name"] == null ||
            provider.Attributes["Name"].Value != "Microsoft-Windows-Security-Auditing" ||
            channel == null || channel.InnerText != "Security") return null;
        string direction = Field(xml, "Direction"), origin = Field(xml, "FilterOrigin");
        int protocol, index, sourcePort, destinationPort;
        if (direction != "%%14592" && direction != "Inbound" ||
            String.IsNullOrEmpty(origin) ||
            !Int32.TryParse(Field(xml, "Protocol"), out protocol) ||
            !Int32.TryParse(Field(xml, "InterfaceIndex"), out index) || index <= 0 ||
            !Int32.TryParse(Field(xml, "SourcePort"), out sourcePort) ||
            !Int32.TryParse(Field(xml, "DestPort"), out destinationPort)) return null;
        string source = Field(xml, "SourceAddress"), destination = Field(xml, "DestAddress");
        bool sourceLocal = localAddresses.Contains(source ?? ""),
            destinationLocal = localAddresses.Contains(destination ?? "");
        if (sourceLocal == destinationLocal) return null;
        int localPort = sourceLocal ? sourcePort : destinationPort;
        if (localPort != rdpPort) return null;
        return new QualificationDrop { RecordId = recordId, UtcTicks = utcTicks,
            InterfaceIndex = index, Protocol = protocol, LocalPort = localPort,
            FilterOrigin = origin, LocalAddress = sourceLocal ? source : destination,
            RemoteAddress = sourceLocal ? destination : source };
    }
    private static Dictionary<int, bool?> PhysicalAdapters()
    {
        var result = new Dictionary<int, bool?>();
        using (var search = new ManagementObjectSearcher("root\\CIMV2",
            "SELECT InterfaceIndex, PhysicalAdapter, PNPDeviceID FROM Win32_NetworkAdapter"))
        using (var matches = search.Get())
            foreach (ManagementObject item in matches)
            {
                if (item["InterfaceIndex"] == null) continue;
                int index = Convert.ToInt32(item["InterfaceIndex"]);
                string pnp = Convert.ToString(item["PNPDeviceID"] ?? "");
                bool? physical = item["PhysicalAdapter"] == null ? (bool?)null :
                    Convert.ToBoolean(item["PhysicalAdapter"]) &&
                    (pnp.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase) ||
                     pnp.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase));
                if (result.ContainsKey(index)) result[index] = null; else result.Add(index, physical);
            }
        return result;
    }
    private static List<QualificationInterface> RelevantInterfaces()
    {
        var physical = PhysicalAdapters();
        var result = new List<QualificationInterface>();
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            IPInterfaceProperties props = adapter.GetIPProperties();
            string addresses = String.Join(",", props.UnicastAddresses.Select(x => x.Address)
                .Where(x => !IPAddress.IsLoopback(x) && !x.Equals(IPAddress.Any) &&
                    !x.Equals(IPAddress.IPv6Any)).Select(x => x.ToString())
                .OrderBy(x => x, StringComparer.Ordinal));
            if (addresses.Length == 0) continue;
            int index = props.GetIPv4Properties() == null ? -1 : props.GetIPv4Properties().Index;
            if (index <= 0 && props.GetIPv6Properties() != null) index = props.GetIPv6Properties().Index;
            bool? isPhysical;
            physical.TryGetValue(index, out isPhysical);
            result.Add(new QualificationInterface { Index = index,
                Path = isPhysical == true ? "External" : "Unknown",
                Identity = adapter.Id + "|" + adapter.NetworkInterfaceType,
                Addresses = addresses });
        }
        return result;
    }
    private static string MachineId()
    {
        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false))
        {
            Guid id;
            string value = key == null ? null : key.GetValue("MachineGuid") as string;
            if (!Guid.TryParse(value, out id)) throw new InvalidOperationException("Windows machine identity is inaccessible.");
            return id.ToString("D");
        }
    }
    public QualificationBoundary Observe(long notBeforeUtcTicks, int rdpPort)
    {
        var boundary = new QualificationBoundary { MachineId = MachineId() };
        boundary.Interfaces.AddRange(RelevantInterfaces());
        if (boundary.Interfaces.Count == 0) return boundary;
        var locals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (QualificationInterface item in boundary.Interfaces)
            foreach (string address in item.Addresses.Split(',')) locals.Add(address);
        const string query = "*[System[(EventID=5152 or EventID=5157)]]";
        var logQuery = new EventLogQuery("Security", PathType.LogName, query) { ReverseDirection = true };
        using (var reader = new EventLogReader(logQuery))
        {
            int count = 0;
            EventRecord record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    if (++count > 4096) throw new InvalidOperationException("Security-log packet window is too large to qualify.");
                    if (!record.TimeCreated.HasValue || record.TimeCreated.Value.ToUniversalTime().Ticks < notBeforeUtcTicks)
                        continue;
                    QualificationDrop drop = ParseSecurityEvent(record.ToXml(), record.RecordId ?? 0,
                        record.TimeCreated.Value.ToUniversalTime().Ticks, locals, rdpPort);
                    if (drop != null) boundary.Drops.Add(drop);
                }
            }
        }
        return boundary;
    }
}
