using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

// Deliberately stricter than an Internet-connectivity test. Any non-loopback
// adapter link, IP address, or active route can reach a peer without a gateway.
// Unknown inventory is never interpreted as isolation.
internal sealed class NetworkIsolationAssessment
{
    internal bool CoverageAccepted;
    internal int ActiveAdapters, ConnectedIpInterfaces, NonLoopbackAddresses, NonLoopbackRoutes, Unknown;
    internal bool Accepted { get { return CoverageAccepted && ActiveAdapters == 0 &&
        ConnectedIpInterfaces == 0 && NonLoopbackAddresses == 0 && NonLoopbackRoutes == 0 && Unknown == 0; } }

    private static Dictionary<string, object> Map(object value)
    { return value as Dictionary<string, object> ?? new Dictionary<string, object>(); }
    private static object At(object value, string key)
    { object found; return Map(value).TryGetValue(key, out found) ? found : null; }
    private static string Text(object value) { return value as string; }
    private static int? Number(object value)
    {
        if (value is int) return (int)value;
        if (value is long && (long)value >= int.MinValue && (long)value <= int.MaxValue) return (int)(long)value;
        return null;
    }
    private static object[] Items(object section)
    { return At(section, "Items") as object[]; }
    private static bool Accessible(object section)
    { return Text(At(section, "State")) == "Accessible" && Items(section) != null; }
    private static bool FamilyKnown(object item)
    { return Text(At(item, "AddressFamily")) == "IPv4" || Text(At(item, "AddressFamily")) == "IPv6"; }
    private static bool LoopbackInterface(object item)
    { return Number(At(item, "InterfaceIndex")) == 1 && At(item, "LoopbackAlias") is bool &&
        (bool)At(item, "LoopbackAlias"); }

    internal static NetworkIsolationAssessment Assess(object network)
    {
        var result = new NetworkIsolationAssessment();
        object adapters = At(network, "Adapters"), interfaces = At(network, "IpInterfaces");
        object addresses = At(network, "IpAddresses"), routes = At(network, "Routes");
        result.CoverageAccepted = Accessible(adapters) && Accessible(interfaces) &&
            Accessible(addresses) && Accessible(routes) && Items(adapters).Length > 0 &&
            Items(interfaces).Length > 0 && Items(addresses).Length > 0 && Items(routes).Length > 0;
        if (!result.CoverageAccepted) { result.Unknown++; return result; }

        var adapterIndices = new HashSet<int>();
        foreach (object adapter in Items(adapters))
        {
            int? index = Number(At(adapter, "InterfaceIndex"));
            string status = Text(At(adapter, "Status"));
            string category = Text(At(adapter, "Category"));
            string media = Text(At(adapter, "MediaConnectionState"));
            if (!index.HasValue || index.Value < 1 || !adapterIndices.Add(index.Value) ||
                String.IsNullOrEmpty(category) || String.IsNullOrEmpty(status))
            { result.Unknown++; continue; }
            if (index.Value == 1)
            {
                if (category != "Loopback") result.Unknown++;
                continue;
            }
            if (status == "Up" || media == "Connected") { result.ActiveAdapters++; continue; }
            if (!new[] { "Disconnected", "Disabled", "Not Present", "NotPresent", "Down", "LowerLayerDown" }.Contains(status))
            { result.Unknown++; continue; }
            // Some disconnected Windows miniports report no media state. Their
            // disconnected adapter status is corroborated by the IP and route views.
        }

        var loopbacks = new HashSet<string>(StringComparer.Ordinal);
        foreach (object ipInterface in Items(interfaces))
        {
            int? index = Number(At(ipInterface, "InterfaceIndex"));
            int? compartment = Number(At(ipInterface, "CompartmentId"));
            string state = Text(At(ipInterface, "ConnectionState"));
            if (!index.HasValue || index.Value < 1 || !compartment.HasValue || compartment.Value < 0 ||
                !FamilyKnown(ipInterface) || String.IsNullOrEmpty(state))
            { result.Unknown++; continue; }
            if (index.Value == 1)
            {
                if (!LoopbackInterface(ipInterface) || state != "Connected") result.Unknown++;
                else if (!loopbacks.Add(compartment.Value + ":" + Text(At(ipInterface, "AddressFamily")))) result.Unknown++;
                continue;
            }
            if (state == "Connected") result.ConnectedIpInterfaces++;
            else if (state != "Disconnected") result.Unknown++;
        }
        if (loopbacks.Count == 0) result.Unknown++;

        int loopbackAddresses = 0, loopbackRoutes = 0;
        foreach (object address in Items(addresses))
        {
            int? index = Number(At(address, "InterfaceIndex"));
            int? compartment = Number(At(address, "CompartmentId"));
            if (!index.HasValue || index.Value < 1 || !compartment.HasValue || compartment.Value < 0 ||
                !FamilyKnown(address))
            { result.Unknown++; continue; }
            if (index.Value != 1) { result.NonLoopbackAddresses++; continue; }
            IPAddress parsed;
            if (!IPAddress.TryParse(Text(At(address, "Address")), out parsed) || !IPAddress.IsLoopback(parsed) ||
                (parsed.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6") !=
                    Text(At(address, "AddressFamily"))) result.Unknown++;
            else loopbackAddresses++;
        }
        foreach (object route in Items(routes))
        {
            int? index = Number(At(route, "InterfaceIndex"));
            int? compartment = Number(At(route, "CompartmentId"));
            if (!index.HasValue || index.Value < 1 || !compartment.HasValue || compartment.Value < 0 ||
                !FamilyKnown(route) ||
                String.IsNullOrEmpty(Text(At(route, "DestinationPrefix"))) ||
                String.IsNullOrEmpty(Text(At(route, "NextHop"))))
            { result.Unknown++; continue; }
            if (index.Value != 1) result.NonLoopbackRoutes++;
            else if (!loopbacks.Contains(compartment.Value + ":" + Text(At(route, "AddressFamily")))) result.Unknown++;
            else loopbackRoutes++;
        }
        if (loopbackAddresses == 0 || loopbackRoutes == 0) result.Unknown++;
        return result;
    }
}
