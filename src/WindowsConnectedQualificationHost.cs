using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Win32;

// Read-only Security-log and adapter evidence. Unknown virtual topology blocks
// admission; this adapter never enumerates containers, WSL distributions, or apps.
internal sealed class QualificationLogItem
{
    internal int Id;
    internal long RecordId;
    internal long? UtcTicks;
    internal string Xml;
}
internal sealed class QualificationAdapter
{
    internal int Index;
    internal string Id, Name, Description, Mac, Type, Addresses;
    internal bool? Physical;
    internal bool Relevant;
}
internal sealed class QualificationSwitch
{
    internal Guid Id;
    internal string Name, Type;
}
internal sealed class QualificationHostPort
{
    internal Guid Id, SwitchId;
    internal string SwitchName, Mac;
}
internal sealed class QualificationHostTopology
{
    internal readonly List<QualificationSwitch> Switches = new List<QualificationSwitch>();
    internal readonly List<QualificationHostPort> Ports = new List<QualificationHostPort>();
}
internal sealed class WindowsConnectedQualificationHost : IConnectedQualificationHost
{
    private const int MaxRecentEvents = 4096;
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
        if (eventId == null || provider == null || provider.Attributes == null ||
            provider.Attributes["Name"] == null || channel == null)
            throw new InvalidDataException("Security packet event metadata is incomplete.");
        if (eventId.InnerText != "5152" && eventId.InnerText != "5157") return null;
        if (provider.Attributes["Name"].Value != "Microsoft-Windows-Security-Auditing" ||
            channel.InnerText != "Security")
            throw new InvalidDataException("Security packet event provenance is unexpected.");
        string direction = Field(xml, "Direction"), origin = Field(xml, "FilterOrigin");
        int protocol, index, sourcePort, destinationPort;
        if (String.IsNullOrEmpty(direction) || String.IsNullOrEmpty(origin) ||
            !Int32.TryParse(Field(xml, "Protocol"), out protocol) ||
            !Int32.TryParse(Field(xml, "InterfaceIndex"), out index) || index <= 0 ||
            !Int32.TryParse(Field(xml, "SourcePort"), out sourcePort) ||
            !Int32.TryParse(Field(xml, "DestPort"), out destinationPort))
            throw new InvalidDataException("A Security packet event lacks required native fields.");
        if (direction != "%%14592" && direction != "Inbound" ||
            sourcePort != rdpPort && destinationPort != rdpPort) return null;
        string source = Field(xml, "SourceAddress"), destination = Field(xml, "DestAddress");
        IPAddress sourceIp, destinationIp;
        if (!IPAddress.TryParse(source, out sourceIp) || !IPAddress.TryParse(destination, out destinationIp))
            throw new InvalidDataException("A relevant Security packet event has malformed addresses.");
        string sourceCanonical, destinationCanonical;
        try
        {
            sourceCanonical = ConnectedQualificationGate.Address(source);
            destinationCanonical = ConnectedQualificationGate.Address(destination);
        }
        catch { return null; } // loopback, mapped, or unscoped traffic is never proof.
        var locals = new HashSet<string>(localAddresses.Select(ConnectedQualificationGate.Address),
            StringComparer.Ordinal);
        bool sourceLocal = locals.Contains(sourceCanonical),
            destinationLocal = locals.Contains(destinationCanonical);
        if (sourceLocal == destinationLocal) return null;
        int localPort = sourceLocal ? sourcePort : destinationPort;
        if (localPort != rdpPort) return null;
        return new QualificationDrop { RecordId = recordId, UtcTicks = utcTicks,
            InterfaceIndex = index, Protocol = protocol, LocalPort = localPort,
            FilterOrigin = origin, LocalAddress = sourceLocal ? sourceCanonical : destinationCanonical,
            RemoteAddress = sourceLocal ? destinationCanonical : sourceCanonical };
    }
    // Windows Event Log evaluates this relative-time predicate in the native
    // query. The managed scan separately enforces the exact absolute window.
    internal static string QueryForWindow(long notBeforeUtcTicks, long nowUtcTicks)
    {
        if (notBeforeUtcTicks <= 0 || nowUtcTicks < notBeforeUtcTicks ||
            nowUtcTicks - notBeforeUtcTicks > 20L * TimeSpan.TicksPerMinute)
            throw new InvalidOperationException("Security event window is invalid or too broad.");
        long milliseconds = (nowUtcTicks - notBeforeUtcTicks + TimeSpan.TicksPerMillisecond - 1) /
            TimeSpan.TicksPerMillisecond + 1000;
        return "*[System[(EventID=5152 or EventID=5157 or EventID=1102) and " +
            "TimeCreated[timediff(@SystemTime) <= " + milliseconds + "]]]";
    }
    internal static List<QualificationDrop> ReadWindow(Func<QualificationLogItem> next,
        long notBeforeUtcTicks, long nowUtcTicks, ICollection<string> localAddresses, int rdpPort)
    {
        QueryForWindow(notBeforeUtcTicks, nowUtcTicks);
        var drops = new List<QualificationDrop>();
        int recent = 0;
        var seen = new HashSet<long>();
        QualificationLogItem item;
        while ((item = next()) != null)
        {
            if (!item.UtcTicks.HasValue)
                throw new InvalidDataException("Security event time is unavailable.");
            if (item.UtcTicks.Value > nowUtcTicks)
                throw new InvalidDataException("Security event is newer than the captured observation boundary.");
            if (item.UtcTicks.Value < notBeforeUtcTicks) continue;
            if (item.RecordId <= 0)
                throw new InvalidDataException("Current Security event identity is unavailable.");
            if (++recent > MaxRecentEvents)
                throw new InvalidOperationException("The current Security packet window is overloaded.");
            if (!seen.Add(item.RecordId))
                throw new InvalidDataException("Security event identity was repeated during acquisition.");
            if (item.Id == 1102)
                throw new InvalidDataException("Security log was cleared during the qualification window.");
            if (item.Id != 5152 && item.Id != 5157)
                throw new InvalidDataException("The native Security query returned an unexpected event.");
            if (String.IsNullOrWhiteSpace(item.Xml))
                throw new InvalidDataException("Current Security packet event XML is unavailable.");
            QualificationDrop drop = ParseSecurityEvent(item.Xml, item.RecordId,
                item.UtcTicks.Value, localAddresses, rdpPort);
            if (drop != null) drops.Add(drop);
        }
        return drops;
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
    private static string DecodeName(string encoded)
    {
        string value = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(encoded));
        if (String.IsNullOrWhiteSpace(value) || value.Contains("\r") || value.Contains("\n") ||
            value.Contains("|")) throw new InvalidDataException("Hyper-V switch name is ambiguous.");
        return value;
    }
    internal static QualificationHostTopology ParseHostTopology(string lines)
    {
        if (String.IsNullOrWhiteSpace(lines) || lines.Length > 16384)
            throw new InvalidDataException("Hyper-V host-port inventory is missing or unbounded.");
        var result = new QualificationHostTopology();
        foreach (string line in lines.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = line.Split('|');
            Guid id, switchId;
            if (parts.Length == 4 && parts[0] == "S" && Guid.TryParse(parts[1], out id))
                result.Switches.Add(new QualificationSwitch { Id = id, Type = parts[2],
                    Name = DecodeName(parts[3]) });
            else if (parts.Length == 5 && parts[0] == "P" && Guid.TryParse(parts[1], out id) &&
                Guid.TryParse(parts[3], out switchId) && Regex.IsMatch(parts[2], "\\A[0-9A-Fa-f]{12}\\z"))
                result.Ports.Add(new QualificationHostPort { Id = id, Mac = parts[2].ToUpperInvariant(),
                    SwitchId = switchId, SwitchName = DecodeName(parts[4]) });
            else throw new InvalidDataException("Hyper-V host-port inventory has an unknown field shape.");
        }
        if (result.Switches.Count > 32 || result.Ports.Count > 32 ||
            result.Switches.Select(x => x.Id).Distinct().Count() != result.Switches.Count ||
            result.Switches.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != result.Switches.Count ||
            result.Ports.Select(x => x.Id).Distinct().Count() != result.Ports.Count ||
            result.Ports.Select(x => x.Mac).Distinct().Count() != result.Ports.Count ||
            result.Ports.Any(x => result.Switches.Count(s => s.Id == x.SwitchId &&
                s.Name == x.SwitchName) != 1))
            throw new InvalidDataException("Hyper-V host-port or switch identity is ambiguous.");
        return result;
    }
    private static QualificationHostTopology ReadHostTopology()
    {
        // Only management-OS ports and switch metadata are read. No VM, WSL,
        // Docker, container, endpoint, or process inventory is queried.
        const string script = "$ErrorActionPreference='Stop';" +
            "foreach($s in @(Get-VMSwitch -ErrorAction Stop)){" +
            "$n=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$s.Name));" +
            "[Console]::WriteLine('S|'+$s.Id+'|'+$s.SwitchType+'|'+$n)};" +
            "foreach($p in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop)){" +
            "$n=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$p.SwitchName));" +
            "$m=([string]$p.MacAddress -replace '[^0-9A-Fa-f]','').ToUpperInvariant();" +
            "[Console]::WriteLine('P|'+$p.Id+'|'+$m+'|'+$p.SwitchId+'|'+$n)}";
        string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(powershell, "-NoProfile -NonInteractive -EncodedCommand " +
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script))) {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        using (var process = Process.Start(start))
        {
            if (process == null) throw new InvalidOperationException("Hyper-V read-only query did not start.");
            Task<string> output = process.StandardOutput.ReadToEndAsync();
            Task<string> error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(10000))
            { process.Kill(); throw new TimeoutException("Hyper-V host-port query exceeded ten seconds."); }
            if (process.ExitCode != 0 || !String.IsNullOrWhiteSpace(error.GetAwaiter().GetResult()))
                throw new InvalidOperationException("Hyper-V host-port query is inaccessible.");
            return ParseHostTopology(output.GetAwaiter().GetResult());
        }
    }
    internal static List<QualificationInterface> ClassifyAdapters(
        IList<QualificationAdapter> adapters, QualificationHostTopology topology)
    {
        var result = new List<QualificationInterface>();
        if (adapters == null) throw new InvalidDataException("Network adapter inventory is unavailable.");
        foreach (QualificationAdapter adapter in adapters)
        {
            if (!adapter.Relevant) continue;
            string path = adapter.Physical == true ? "External" : "Unknown";
            string association = "";
            if (adapter.Physical != true && topology != null &&
                Regex.IsMatch(adapter.Mac ?? "", "\\A[0-9A-Fa-f]{12}\\z") &&
                adapters.Count(x => String.Equals(x.Mac, adapter.Mac,
                    StringComparison.OrdinalIgnoreCase)) == 1)
            {
                var ports = topology.Ports.Where(x => String.Equals(x.Mac, adapter.Mac,
                    StringComparison.OrdinalIgnoreCase)).ToArray();
                if (ports.Length == 1)
                {
                    var matches = topology.Switches.Where(x => x.Id == ports[0].SwitchId &&
                        x.Name == ports[0].SwitchName).ToArray();
                    if (matches.Length == 1 && (matches[0].Type == "Internal" ||
                        matches[0].Type == "Private") &&
                        Regex.IsMatch(adapter.Description ?? "",
                            "\\AHyper-V Virtual Ethernet Adapter(?: #[1-9][0-9]*)?\\z") &&
                        adapter.Name == "vEthernet (" + matches[0].Name + ")")
                    {
                        path = "Guest";
                        association = "|" + ports[0].Id.ToString("D") + "|" +
                            matches[0].Id.ToString("D");
                    }
                }
            }
            result.Add(new QualificationInterface { Index = adapter.Index, Path = path,
                Identity = adapter.Id + "|" + adapter.Type + "|" + adapter.Mac + association,
                Addresses = adapter.Addresses });
        }
        return result;
    }
    private static List<QualificationInterface> RelevantInterfaces()
    {
        var physical = PhysicalAdapters();
        var adapters = new List<QualificationAdapter>();
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            IPInterfaceProperties props = adapter.GetIPProperties();
            string addresses = String.Join(",", props.UnicastAddresses.Select(x => x.Address)
                .Where(x => !IPAddress.IsLoopback(x) && !x.Equals(IPAddress.Any) &&
                    !x.Equals(IPAddress.IPv6Any)).Select(x => x.ToString())
                .OrderBy(x => x, StringComparer.Ordinal));
            int index = props.GetIPv4Properties() == null ? -1 : props.GetIPv4Properties().Index;
            if (index <= 0 && props.GetIPv6Properties() != null) index = props.GetIPv6Properties().Index;
            bool? isPhysical;
            physical.TryGetValue(index, out isPhysical);
            adapters.Add(new QualificationAdapter { Index = index, Physical = isPhysical,
                Relevant = adapter.OperationalStatus == OperationalStatus.Up && addresses.Length != 0,
                Id = adapter.Id, Name = adapter.Name, Description = adapter.Description,
                Mac = adapter.GetPhysicalAddress().ToString(),
                Type = adapter.NetworkInterfaceType.ToString(), Addresses = addresses });
        }
        QualificationHostTopology topology = null;
        if (adapters.Any(x => x.Relevant && x.Physical != true))
            try { topology = ReadHostTopology(); }
            catch { /* Inaccessible host-port graph remains Unknown, never Guest. */ }
        return ClassifyAdapters(adapters, topology);
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
        long now = UtcNowTicks;
        var logQuery = new EventLogQuery("Security", PathType.LogName,
            QueryForWindow(notBeforeUtcTicks, now)) { ReverseDirection = true,
                TolerateQueryErrors = false };
        using (var reader = new EventLogReader(logQuery))
        {
            boundary.Drops.AddRange(ReadWindow(() =>
            {
                EventRecord record = reader.ReadEvent();
                if (record == null) return null;
                using (record)
                {
                    return new QualificationLogItem { Id = record.Id, RecordId = record.RecordId ?? 0,
                        UtcTicks = record.TimeCreated.HasValue ?
                            (long?)record.TimeCreated.Value.ToUniversalTime().Ticks : null,
                        Xml = record.Id == 1102 ? null : record.ToXml() };
                }
            }, notBeforeUtcTicks, now, locals, rdpPort));
        }
        return boundary;
    }
}
