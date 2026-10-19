// REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.
// Experiment-only receiver. It is not linked into the ChildStream application.
using System;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal sealed class PortProbeOptions
{
    internal IPAddress Local, Lan;
    internal int Port, Seconds, MaxAttempts;
    internal ProtocolType Protocol;

    internal static PortProbeOptions Parse(string[] args)
    {
        if (args.Length != 15 || args[0] != "receive" || args[1] != "--reviewed-live-approval" ||
            args[2] != "YES" || args[3] != "--protocol" || args[5] != "--local" ||
            args[7] != "--lan" || args[9] != "--port" || args[11] != "--seconds" ||
            args[13] != "--max-attempts")
            throw new ArgumentException("Explicit receive arguments and separate live approval are required.");
        var o = new PortProbeOptions();
        if (args[4] == "TCP") o.Protocol = ProtocolType.Tcp;
        else if (args[4] == "UDP") o.Protocol = ProtocolType.Udp;
        else throw new ArgumentException("Protocol must be TCP or UDP.");
        if (!IPAddress.TryParse(args[6], out o.Local) || !IPAddress.TryParse(args[8], out o.Lan))
            throw new ArgumentException("Literal local and LAN addresses are required.");
        if (o.Local.AddressFamily != o.Lan.AddressFamily ||
            !(o.Local.Equals(IPAddress.Loopback) || o.Local.Equals(IPAddress.IPv6Loopback)) ||
            IPAddress.IsLoopback(o.Lan) || o.Lan.Equals(IPAddress.Any) || o.Lan.Equals(IPAddress.IPv6Any) ||
            o.Lan.IsIPv6Multicast || o.Lan.IsIPv6LinkLocal || o.Lan.IsIPv4MappedToIPv6 ||
            (o.Lan.AddressFamily == AddressFamily.InterNetwork && (o.Lan.GetAddressBytes()[0] >= 224 ||
             o.Lan.GetAddressBytes()[0] == 0)))
            throw new ArgumentException("Use an exact unicast LAN address and the same-family loopback address.");
        if (!Int32.TryParse(args[10], NumberStyles.None, CultureInfo.InvariantCulture, out o.Port) ||
            !Int32.TryParse(args[12], NumberStyles.None, CultureInfo.InvariantCulture, out o.Seconds) ||
            !Int32.TryParse(args[14], NumberStyles.None, CultureInfo.InvariantCulture, out o.MaxAttempts) ||
            o.Port < 1 || o.Port > 65535 || o.Seconds < 1 || o.Seconds > 120 ||
            o.MaxAttempts < 1 || o.MaxAttempts > 8)
            throw new ArgumentException("Port must be 1..65535, duration 1..120 seconds, attempts 1..8.");
        return o;
    }
}

internal interface IPortProbeRuntime
{
    void Run(PortProbeOptions options, Action<string> emit);
}

internal static class PortProbeVerdict
{
    // This only classifies supplied observations; it never gathers host evidence.
    internal static string ClassifyEnforcement(bool remoteSent, bool exactOwnedDrop,
        bool remoteReceived, bool localAttempted, bool localReceived, bool evidenceComplete)
    {
        if (remoteReceived || localAttempted && !localReceived) return "REJECTS TESTED RULE OR SETUP";
        if (!remoteSent || !evidenceComplete) return "INCONCLUSIVE";
        if (!localAttempted || !localReceived) return "INCONCLUSIVE";
        return exactOwnedDrop ? "SUPPORTS TESTED RULE" : "INCONCLUSIVE";
    }
    internal static string ClassifyCleanup(bool cleanupComplete)
    { return cleanupComplete ? "COMPLETE" : "INCOMPLETE"; }
}

internal static class PortProbeBudget
{
    internal static bool Continue(DateTime nowUtc, DateTime deadlineUtc, int attempts,
        int maximum, bool cancelled)
    { return !cancelled && attempts < maximum && nowUtc < deadlineUtc; }
}

internal sealed class SocketPortProbeRuntime : IPortProbeRuntime
{
    private static readonly byte[] Request = Encoding.ASCII.GetBytes("CS-PROBE-v1");
    private static readonly byte[] Ack = Encoding.ASCII.GetBytes("OK");
    private volatile bool cancelled;

    private static Socket Bound(PortProbeOptions o, IPAddress address)
    {
        var s = new Socket(address.AddressFamily,
            o.Protocol == ProtocolType.Tcp ? SocketType.Stream : SocketType.Dgram, o.Protocol);
        try {
            if (address.AddressFamily == AddressFamily.InterNetworkV6) s.SetSocketOption(
                SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            s.ExclusiveAddressUse = true;
            s.ReceiveBufferSize = 256;
            s.SendBufferSize = 256;
            s.Bind(new IPEndPoint(address, o.Port));
            if (o.Protocol == ProtocolType.Tcp) s.Listen(2);
            return s;
        } catch { s.Dispose(); throw; }
    }

    private static bool ExactMessage(byte[] data, int count)
    {
        if (count != Request.Length) return false;
        for (int i = 0; i < count; i++) if (data[i] != Request[i]) return false;
        return true;
    }

    private static void Receive(Socket listener, bool lan, ProtocolType protocol, Action<string> emit)
    {
        var data = new byte[32];
        EndPoint remote = listener.AddressFamily == AddressFamily.InterNetwork
            ? (EndPoint)new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
        int count = -1;
        bool valid = false;
        bool observed = false;
        bool oversized = false;
        if (protocol == ProtocolType.Tcp) {
            using (Socket peer = listener.Accept()) {
                observed = true;
                peer.ReceiveTimeout = 500;
                peer.SendTimeout = 500;
                remote = peer.RemoteEndPoint;
                try {
                    count = 0;
                    while (count < Request.Length) {
                        int part = peer.Receive(data, count, Request.Length - count, SocketFlags.None);
                        if (part == 0) break;
                        count += part;
                    }
                    valid = ExactMessage(data, count);
                    if (valid) peer.Send(Ack);
                } catch (SocketException) { }
            }
        } else {
            try {
                count = listener.ReceiveFrom(data, 0, data.Length, SocketFlags.None, ref remote);
                observed = true;
                valid = ExactMessage(data, count);
                if (valid) listener.SendTo(Ack, remote);
            } catch (SocketException ex) {
                if (ex.SocketErrorCode == SocketError.MessageSize) { observed = true; oversized = true; }
            }
        }
        // No arbitrary payload is printed or persisted. A received remote tuple is
        // needed to identify unintended exposure if the proposed rule fails.
        emit((observed ? "RECEIVED|" : "OBSERVATION_ERROR|") + DateTime.UtcNow.ToString("o") + "|" + (lan ? "LAN" : "LOCAL") +
            "|" + (oversized ? "UNKNOWN" : remote.ToString()) + "|" +
            (oversized ? "OVERSIZE" : valid ? "FIXED_MESSAGE" : "INVALID_MESSAGE"));
    }

    public void Run(PortProbeOptions o, Action<string> emit)
    {
        ConsoleCancelEventHandler cancel = (sender, e) => { e.Cancel = true; cancelled = true; };
        Console.CancelKeyPress += cancel;
        try {
            using (Socket local = Bound(o, o.Local))
            using (Socket lan = Bound(o, o.Lan)) {
                emit("READY|" + DateTime.UtcNow.ToString("o") + "|PID=" +
                    Process.GetCurrentProcess().Id + "|" + o.Protocol + "|" +
                    local.LocalEndPoint + "|" + lan.LocalEndPoint);
                DateTime deadline = DateTime.UtcNow.AddSeconds(o.Seconds);
                int attempts = 0;
                while (PortProbeBudget.Continue(DateTime.UtcNow, deadline, attempts,
                    o.MaxAttempts, cancelled)) {
                    Socket selected = null;
                    bool fromLan = false;
                    if (local.Poll(100000, SelectMode.SelectRead)) selected = local;
                    else if (lan.Poll(100000, SelectMode.SelectRead)) { selected = lan; fromLan = true; }
                    if (selected == null) continue;
                    Receive(selected, fromLan, o.Protocol, emit);
                    attempts++;
                }
                emit("STOPPED|" + DateTime.UtcNow.ToString("o") + "|ATTEMPTS=" + attempts);
            }
        } finally { Console.CancelKeyPress -= cancel; }
    }
}

internal static class PortContainmentProbeProgram
{
    internal const string Label = "REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED";
    internal static int Run(string[] args, IPortProbeRuntime runtime, Action<string> emit)
    {
        if (args.Length == 0 || args.Length == 1 && args[0] == "--help") {
            emit(Label);
            emit("Separate explicit authorization is required before receive. No default socket operation.");
            emit("receive --reviewed-live-approval YES --protocol TCP|UDP --local 127.0.0.1|::1 --lan ADDRESS --port PORT --seconds 1..120 --max-attempts 1..8");
            return 0;
        }
        try {
            PortProbeOptions options = PortProbeOptions.Parse(args);
            emit(Label);
            runtime.Run(options, emit);
            return 0;
        } catch (Exception ex) {
            emit("STOPPED|" + ex.GetType().Name + "|" + ex.Message);
            return 2;
        }
    }
    private static int Main(string[] args)
    { return Run(args, new SocketPortProbeRuntime(), Console.WriteLine); }
}
