// REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.
// No test constructs a real Socket or invokes a live receive/control mode.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal sealed class FakeProbeTime : IProbeTime
{
    internal long Now;
    public long Milliseconds { get { return Now; } }
    public string Utc { get { return "2026-10-18T00:00:00Z"; } }
    internal void Advance(long milliseconds) { Now += milliseconds; }
}

internal sealed class FakeProbeSocket : IProbeSocket
{
    internal bool Disposed, ThrowDispose;
    internal string Local = "127.0.0.1:3389", Remote = "192.0.2.20:40000";
    internal Func<int, bool> ReadPoll, WritePoll;
    internal Func<IProbeSocket> AcceptNext;
    internal Exception ReadError;
    internal ProbeDatagram Datagram;
    internal readonly Queue<byte[]> Reads = new Queue<byte[]>();
    internal readonly List<byte> Written = new List<byte>();
    public string LocalEndpoint { get { return Local; } }
    public string RemoteEndpoint { get { return Remote; } }
    public bool PollRead(int milliseconds)
    { return ReadPoll == null ? false : ReadPoll(milliseconds); }
    public bool PollWrite(int milliseconds)
    { return WritePoll == null ? true : WritePoll(milliseconds); }
    public IProbeSocket Accept()
    { return AcceptNext == null ? null : AcceptNext(); }
    public int Receive(byte[] bytes, int offset, int count)
    {
        if (ReadError != null) throw ReadError;
        if (Reads.Count == 0) return 0;
        byte[] next = Reads.Dequeue();
        int size = Math.Min(count, next.Length);
        Array.Copy(next, 0, bytes, offset, size);
        if (size < next.Length) {
            var remaining = new byte[next.Length - size];
            Array.Copy(next, size, remaining, 0, remaining.Length);
            var queued = Reads.ToArray(); Reads.Clear(); Reads.Enqueue(remaining);
            foreach (var item in queued) Reads.Enqueue(item);
        }
        return size;
    }
    public int Send(byte[] bytes, int offset, int count)
    { for (int i = 0; i < count; i++) Written.Add(bytes[offset + i]); return count; }
    public ProbeDatagram ReceiveDatagram(byte[] bytes)
    {
        if (Datagram == null) return null;
        var value = Datagram; Datagram = null;
        Array.Copy(Encoding.ASCII.GetBytes("CS-PROBE-v1"), bytes, 11);
        return value;
    }
    public int SendDatagram(byte[] bytes, EndPoint remote)
    { Written.AddRange(bytes); return bytes.Length; }
    public void Dispose() { Disposed = true; if (ThrowDispose) throw new IOException("synthetic disposal failure"); }
}

internal sealed class FakeProbeFactory : IProbeSocketFactory
{
    internal readonly Queue<FakeProbeSocket> Sockets = new Queue<FakeProbeSocket>();
    public IProbeSocket Bind(PortProbeOptions options, IPAddress address)
    { return Sockets.Dequeue(); }
}

internal sealed class FakeLocalChannel : ILocalTcpChannel
{
    internal bool Disposed, ThrowDispose;
    internal Func<int, bool> ConnectPoll, ReadPoll, WritePoll;
    internal readonly Queue<byte[]> Reads = new Queue<byte[]>();
    internal readonly List<byte> Written = new List<byte>();
    internal Exception ReadError;
    public void StartConnect(IPAddress local, int port) { }
    public bool ConnectReady(int milliseconds)
    { return ConnectPoll == null ? true : ConnectPoll(milliseconds); }
    public void FinishConnect() { }
    public bool PollRead(int milliseconds)
    { return ReadPoll == null ? true : ReadPoll(milliseconds); }
    public bool PollWrite(int milliseconds)
    { return WritePoll == null ? true : WritePoll(milliseconds); }
    public int Read(byte[] bytes, int offset, int count)
    {
        if (ReadError != null) throw ReadError;
        if (Reads.Count == 0) return 0;
        byte[] next = Reads.Dequeue();
        int size = Math.Min(count, next.Length);
        Array.Copy(next, 0, bytes, offset, size);
        return size;
    }
    public int Write(byte[] bytes, int offset, int count)
    { for (int i = 0; i < count; i++) Written.Add(bytes[offset + i]); return count; }
    public void Dispose() { Disposed = true; if (ThrowDispose) throw new IOException("synthetic disposal failure"); }
}

internal sealed class FakeLocalFactory : ILocalTcpFactory
{
    internal FakeLocalChannel Channel;
    public ILocalTcpChannel Create(AddressFamily family) { return Channel; }
}

internal sealed class FakePortProbeRuntime : IPortProbeRuntime
{
    internal int Calls;
    internal PortProbeOptions Last;
    public ProbeRunResult Run(PortProbeOptions options, Action<string> emit)
    {
        Calls++; Last = options; emit("FAKE_RUNTIME");
        return new ProbeRunResult { MeasurementComplete = true, ShutdownComplete = true };
    }
}
internal sealed class FakeLocalRuntime : ILocalTcpControlRuntime
{
    internal int Calls;
    public LocalControlResult Run(LocalTcpControlOptions options, Action<string> emit)
    { Calls++; return new LocalControlResult { AckValid = true, ShutdownComplete = true }; }
}

internal static class PortContainmentProbeTests
{
    private static int checks;
    private static void Check(bool good, string name)
    { checks++; if (!good) throw new Exception("Synthetic regression: " + name); }
    private static bool Has(IList<string> lines, string start)
    { foreach (string line in lines) if (line.StartsWith(start, StringComparison.Ordinal)) return true; return false; }
    private static int Count(IList<string> lines, string start)
    {
        int count = 0;
        foreach (string line in lines)
            if (line.StartsWith(start, StringComparison.Ordinal)) count++;
        return count;
    }
    private static bool Contains(IList<string> lines, string fragment)
    { foreach (string line in lines) if (line.Contains(fragment)) return true; return false; }
    private static string[] ReceiveCommand(string protocol, string local, string lan, string port,
        string seconds, string attempts)
    { return new[] { "receive", "--reviewed-live-approval", "YES", "--protocol", protocol,
        "--local", local, "--lan", lan, "--port", port, "--seconds", seconds,
        "--max-attempts", attempts }; }
    private static string[] ControlCommand(string local, string port, string seconds)
    { return new[] { "control-tcp", "--reviewed-live-approval", "YES", "--local", local,
        "--port", port, "--seconds", seconds }; }
    private static void Rejected(string[] command, string name)
    {
        var receiver = new FakePortProbeRuntime();
        var control = new FakeLocalRuntime();
        var output = new List<string>();
        Check(PortContainmentProbeProgram.Run(command, receiver, control, output.Add) == 2 &&
            receiver.Calls == 0 && control.Calls == 0, name + " does not invoke runtime");
    }
    private static PortProbeOptions Options(int seconds, int attempts)
    { return PortProbeOptions.Parse(ReceiveCommand("TCP", "127.0.0.1", "192.0.2.10",
        "3389", seconds.ToString(), attempts.ToString())); }
    private static LocalTcpControlOptions ControlOptions()
    { return LocalTcpControlOptions.Parse(ControlCommand("127.0.0.1", "3389", "1")); }
    private static FakeProbeSocket[] ReceiverSockets(FakeProbeFactory factory,
        FakeProbeTime time, Func<int, bool> peerPoll)
    {
        var peer = new FakeProbeSocket { ReadPoll = peerPoll };
        peer.Reads.Enqueue(Encoding.ASCII.GetBytes("CS-PROBE-v1"));
        var local = new FakeProbeSocket();
        bool first = true;
        local.ReadPoll = ms => { if (!first) return false; first = false; return true; };
        local.AcceptNext = () => peer;
        var lan = new FakeProbeSocket { Local = "192.0.2.10:3389" };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        return new[] { local, lan, peer };
    }

    private static void ReceiverLifecycle()
    {
        var clock = new FakeProbeTime();
        var factory = new FakeProbeFactory();
        FakeProbeSocket[] sockets = ReceiverSockets(factory, clock, ms => true);
        var lines = new List<string>();
        var runtime = new SocketPortProbeRuntime(factory, clock, () => false);
        ProbeRunResult result = runtime.Run(Options(1, 1), line => {
            lines.Add(line);
            if (line.StartsWith("STOPPED|")) Check(sockets[0].Disposed && sockets[1].Disposed &&
                sockets[2].Disposed, "STOPPED only after all owned socket disposal");
        });
        Check(result.MeasurementComplete && result.ShutdownComplete && result.Attempts == 1 &&
            result.StopReason == "ATTEMPT_CAP", "attempt cap terminates normal receiver");
        Check(Count(lines, "READY|") == 1 &&
            Contains(lines, "|Tcp|127.0.0.1:3389|192.0.2.10:3389") &&
            Has(lines, "RECEIVED|") &&
            Has(lines, "MESSAGE|2026-10-18T00:00:00Z|LOCAL|FIXED_MESSAGE_ACKED") &&
            Has(lines, "STOP_REQUESTED|") && Has(lines, "STOPPED|"),
            "production coordination preserves receipt and distinct stop statuses");
        Check(Encoding.ASCII.GetString(sockets[2].Written.ToArray()) == "OK",
            "fixed response remains two bytes");
    }
    private static void NearDeadlineAndSlowFragments()
    {
        var clock = new FakeProbeTime();
        var factory = new FakeProbeFactory();
        FakeProbeSocket[] sockets = ReceiverSockets(factory, clock, ms => {
            clock.Advance(10); return true;
        });
        sockets[0].ReadPoll = ms => { clock.Advance(995); return true; };
        var lines = new List<string>();
        var result = new SocketPortProbeRuntime(factory, clock, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE_ACTIVE_IO" && sockets[2].Disposed &&
            Has(lines, "RECEIVED|") && !Has(lines, "MESSAGE|"),
            "near-deadline request cannot extend lifetime; receipt survives");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        FakeProbeTime current = clock;
        sockets = ReceiverSockets(factory, current, ms => {
            current.Advance(600); return true;
        });
        sockets[2].Reads.Clear();
        sockets[2].Reads.Enqueue(Encoding.ASCII.GetBytes("C"));
        sockets[2].Reads.Enqueue(Encoding.ASCII.GetBytes("S-PROBE-v1"));
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE_ACTIVE_IO" && sockets[2].Written.Count == 0 &&
            Has(lines, "RECEIVED|"), "slow fragments share one elapsed budget and never get an ACK");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        current = clock;
        sockets = ReceiverSockets(factory, current, ms => true);
        sockets[2].WritePoll = ms => { current.Advance(1000); return false; };
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE_ACTIVE_IO" && sockets[2].Written.Count == 0 &&
            Has(lines, "RECEIVED|"), "TCP response transmission expiry remains incomplete");
    }
    private static void IdleDeadlineCases()
    {
        var clock = new FakeProbeTime(); var factory = new FakeProbeFactory();
        var local = new FakeProbeSocket(); var lan = new FakeProbeSocket();
        int lanPolls = 0;
        local.ReadPoll = ms => { clock.Advance(1000); return false; };
        lan.ReadPoll = ms => { lanPolls++; throw new Exception("LAN poll after deadline"); };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        var lines = new List<string>();
        var result = new SocketPortProbeRuntime(factory, clock, () => false)
            .Run(Options(1, 2), line => {
                lines.Add(line);
                if (line.StartsWith("STOPPED|"))
                    Check(local.Disposed && lan.Disposed, "idle STOPPED follows exact disposal");
            });
        Check(result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE" && result.Attempts == 0 &&
            lanPolls == 0 && !Has(lines, "MEASUREMENT_INCOMPLETE|") &&
            Has(lines, "STOPPED|"), "local false poll consumes budget; no LAN poll or active failure");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        local = new FakeProbeSocket(); lan = new FakeProbeSocket();
        FakeProbeTime current = clock;
        local.ReadPoll = ms => false;
        lan.ReadPoll = ms => { current.Advance(1000); return false; };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE" && result.Attempts == 0 &&
            !Has(lines, "MEASUREMENT_INCOMPLETE|"),
            "LAN false poll consumes budget; normal quiet observation expiry");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        current = clock;
        var sockets = ReceiverSockets(factory, current, ms => true);
        int localPolls = 0;
        sockets[0].ReadPoll = ms => {
            localPolls++;
            if (localPolls == 1) return true;
            current.Advance(1000); return false;
        };
        sockets[1].ReadPoll = ms => { throw new Exception("LAN poll after deadline"); };
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE" && result.Attempts == 1 &&
            Has(lines, "MESSAGE|2026-10-18T00:00:00Z|LOCAL|FIXED_MESSAGE_ACKED") &&
            !Has(lines, "RECEIVED|2026-10-18T00:00:00Z|LAN|") &&
            !Has(lines, "MEASUREMENT_INCOMPLETE|"),
            "completed local request followed by remote silence expires normally");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        current = clock;
        local = new FakeProbeSocket(); lan = new FakeProbeSocket();
        bool accepted = false;
        local.ReadPoll = ms => { current.Advance(1000); return true; };
        local.AcceptNext = () => { accepted = true; throw new Exception("Accepted after deadline"); };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE_PENDING_IO" && !accepted &&
            Has(lines, "PENDING_READABLE|") && !Has(lines, "RECEIVED|"),
            "readable-at-deadline is retained without accepting new work");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        current = clock;
        local = new FakeProbeSocket(); lan = new FakeProbeSocket();
        accepted = false;
        local.ReadPoll = ms => false;
        lan.ReadPoll = ms => { current.Advance(1000); return true; };
        lan.AcceptNext = () => { accepted = true; throw new Exception("LAN accepted after deadline"); };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE_PENDING_IO" && !accepted &&
            Contains(lines, "|LAN|NOT_ACCEPTED") && !Has(lines, "RECEIVED|"),
            "LAN readability at deadline is recorded without accepting new work");
    }
    private static void CancellationAndFailures()
    {
        var clock = new FakeProbeTime(); var factory = new FakeProbeFactory();
        bool cancelled = false;
        FakeProbeSocket[] sockets = ReceiverSockets(factory, clock, ms => {
            cancelled = true; return true;
        });
        var lines = new List<string>();
        var result = new SocketPortProbeRuntime(factory, clock, () => cancelled)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "CANCELLED_ACTIVE_IO" && Has(lines, "RECEIVED|") &&
            Has(lines, "STOPPED|"), "active read observes cancellation and disposes");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        sockets = ReceiverSockets(factory, clock, ms => true);
        sockets[1].ThrowDispose = true;
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, clock, () => false)
            .Run(Options(1, 1), lines.Add);
        Check(!result.ShutdownComplete && Has(lines, "SHUTDOWN_FAILED|") &&
            !Has(lines, "STOPPED|") && Has(lines, "RECEIVED|"),
            "dispose failure is separate from collected receipt");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        sockets = ReceiverSockets(factory, clock, ms => true);
        sockets[2].ReadError = new IOException("synthetic read failure");
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, clock, () => false)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            Has(lines, "MEASUREMENT_ERROR|") && Has(lines, "RECEIVED|") &&
            Has(lines, "STOPPED|"), "I/O failure does not erase receipt or imply cleanup failure");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        sockets = ReceiverSockets(factory, clock, ms => true);
        bool cancelDuringWrite = false;
        sockets[2].WritePoll = ms => { cancelDuringWrite = true; return true; };
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, clock, () => cancelDuringWrite)
            .Run(Options(1, 2), lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "CANCELLED_ACTIVE_IO" && sockets[2].Written.Count == 0 &&
            Has(lines, "RECEIVED|"), "active response write cannot evade cancellation");
    }
    private static void UdpLifecycle()
    {
        var clock = new FakeProbeTime(); var factory = new FakeProbeFactory();
        var local = new FakeProbeSocket();
        var lan = new FakeProbeSocket { Local = "192.0.2.10:3389" };
        bool first = true;
        local.ReadPoll = ms => { if (!first) return false; first = false; return true; };
        local.Datagram = new ProbeDatagram { Count = 11,
            Remote = new IPEndPoint(IPAddress.Loopback, 40000) };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        var options = PortProbeOptions.Parse(ReceiveCommand("UDP", "127.0.0.1",
            "192.0.2.10", "3389", "1", "1"));
        var lines = new List<string>();
        var result = new SocketPortProbeRuntime(factory, clock, () => false)
            .Run(options, lines.Add);
        Check(result.MeasurementComplete && result.ShutdownComplete && result.Attempts == 1 &&
            local.Disposed && lan.Disposed &&
            Encoding.ASCII.GetString(local.Written.ToArray()) == "OK" &&
            Has(lines, "MESSAGE|2026-10-18T00:00:00Z|LOCAL|FIXED_MESSAGE_ACKED"),
            "UDP fixed datagram and ACK share bounded receiver lifecycle");

        clock = new FakeProbeTime(); factory = new FakeProbeFactory();
        local = new FakeProbeSocket(); lan = new FakeProbeSocket();
        local.ReadPoll = ms => true;
        local.Datagram = new ProbeDatagram { Count = 11,
            Remote = new IPEndPoint(IPAddress.Loopback, 40000) };
        FakeProbeTime current = clock;
        local.WritePoll = ms => { current.Advance(1000); return false; };
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        lines = new List<string>();
        result = new SocketPortProbeRuntime(factory, current, () => false)
            .Run(options, lines.Add);
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "DEADLINE_ACTIVE_IO" && result.Attempts == 1 &&
            Has(lines, "RECEIVED|") && local.Written.Count == 0,
            "UDP response wait respects elapsed deadline and retains reception");
    }
    private static void IdleCancellation()
    {
        var clock = new FakeProbeTime(); var factory = new FakeProbeFactory();
        var local = new FakeProbeSocket(); var lan = new FakeProbeSocket();
        bool cancelled = false;
        factory.Sockets.Enqueue(local); factory.Sockets.Enqueue(lan);
        var lines = new List<string>();
        var result = new SocketPortProbeRuntime(factory, clock, () => cancelled)
            .Run(Options(1, 2), line => {
                lines.Add(line);
                if (line.StartsWith("READY|")) cancelled = true;
            });
        Check(!result.MeasurementComplete && result.ShutdownComplete &&
            result.StopReason == "CANCELLED" && local.Disposed && lan.Disposed &&
            Has(lines, "MEASUREMENT_INCOMPLETE|") && Has(lines, "STOPPED|"),
            "idle cancellation is incomplete but exact sockets are disposed");
    }
    private static LocalControlResult Control(FakeLocalChannel channel, FakeProbeTime time,
        Func<bool> cancelled, List<string> lines)
    { return new LocalTcpControlRuntime(new FakeLocalFactory { Channel = channel }, time, cancelled)
        .Run(ControlOptions(), lines.Add); }
    private static void LocalControlCases()
    {
        var lines = new List<string>(); var time = new FakeProbeTime();
        var channel = new FakeLocalChannel(); channel.Reads.Enqueue(Encoding.ASCII.GetBytes("OK"));
        var result = Control(channel, time, () => false, lines);
        Check(result.AckValid && result.ShutdownComplete && result.Measurement == "ACK_OK" &&
            Encoding.ASCII.GetString(channel.Written.ToArray()) == "CS-PROBE-v1" &&
            Has(lines, "CONTROL_STOPPED|"), "one-chunk exact ACK");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        channel.Reads.Enqueue(Encoding.ASCII.GetBytes("O"));
        channel.Reads.Enqueue(Encoding.ASCII.GetBytes("K"));
        result = Control(channel, time, () => false, lines);
        Check(result.AckValid && result.Measurement == "ACK_OK", "two-chunk ACK accumulated");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        channel.Reads.Enqueue(Encoding.ASCII.GetBytes("O"));
        result = Control(channel, time, () => false, lines);
        Check(!result.AckValid && result.Measurement == "PREMATURE_CLOSE" &&
            result.ShutdownComplete, "premature close is measurement failure");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        channel.Reads.Enqueue(Encoding.ASCII.GetBytes("NO"));
        result = Control(channel, time, () => false, lines);
        Check(!result.AckValid && result.Measurement == "MALFORMED_ACK", "wrong ACK rejected");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        FakeProbeTime current = time;
        channel.ConnectPoll = ms => { current.Advance(1000); return false; };
        result = Control(channel, current, () => false, lines);
        Check(!result.AckValid && result.Measurement == "TIMEOUT" && channel.Disposed,
            "connect uses total budget, not renewed wait");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        current = time;
        channel.ReadPoll = ms => { current.Advance(1000); return false; };
        result = Control(channel, current, () => false, lines);
        Check(!result.AckValid && result.Measurement == "TIMEOUT" && channel.Disposed,
            "fragmented read uses total budget");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        bool cancelled = false;
        channel.ReadPoll = ms => { cancelled = true; return true; };
        result = Control(channel, time, () => cancelled, lines);
        Check(!result.AckValid && result.Measurement == "CANCELLED" && channel.Disposed,
            "control cancellation observed during read");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        channel.Reads.Enqueue(Encoding.ASCII.GetBytes("OK")); channel.ThrowDispose = true;
        result = Control(channel, time, () => false, lines);
        Check(result.AckValid && !result.ShutdownComplete &&
            Has(lines, "CONTROL_SHUTDOWN_FAILED|") && !Has(lines, "CONTROL_STOPPED|"),
            "valid measurement does not conceal failed local-control cleanup");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        current = time;
        channel.WritePoll = ms => { current.Advance(1000); return false; };
        result = Control(channel, current, () => false, lines);
        Check(!result.AckValid && result.Measurement == "TIMEOUT" && channel.Disposed,
            "control write shares the connect/read elapsed budget");

        lines = new List<string>(); time = new FakeProbeTime(); channel = new FakeLocalChannel();
        channel.ReadError = new IOException("synthetic local read error");
        result = Control(channel, time, () => false, lines);
        Check(!result.AckValid && result.Measurement == "IO_ERROR:IOException" &&
            result.ShutdownComplete, "local I/O error is not a firewall verdict");
    }
    private static void Main()
    {
        var receiver = new FakePortProbeRuntime(); var control = new FakeLocalRuntime();
        var output = new List<string>();
        Check(PortContainmentProbeProgram.Run(new string[0], receiver, control, output.Add) == 0 &&
            receiver.Calls == 0 && control.Calls == 0 && output[0] == PortContainmentProbeProgram.Label,
            "default is no-socket help");
        output.Clear();
        Check(PortContainmentProbeProgram.Run(new[] { "--help" }, receiver, control, output.Add) == 0 &&
            receiver.Calls == 0 && control.Calls == 0, "help is no-socket");
        var v4 = ReceiveCommand("TCP", "127.0.0.1", "192.0.2.10", "3389", "30", "4");
        Check(PortContainmentProbeProgram.Run(v4, receiver, control, output.Add) == 0 &&
            receiver.Calls == 1 && receiver.Last.Port == 3389, "explicit v4 TCP parsed");
        var v6 = ReceiveCommand("UDP", "::1", "2001:db8::10", "3389", "60", "8");
        Check(PortContainmentProbeProgram.Run(v6, receiver, control, output.Add) == 0 &&
            receiver.Last.Protocol == ProtocolType.Udp, "explicit v6 UDP parsed");
        Check(PortContainmentProbeProgram.Run(ControlCommand("::1", "3389", "3"),
            receiver, control, output.Add) == 0 && control.Calls == 1,
            "fixed loopback control parsed without production socket");
        v4[2] = "NO"; Rejected(v4, "missing approval marker");
        Rejected(ReceiveCommand("TCP", "127.0.0.1", "127.0.0.1", "3389", "30", "4"), "loopback as LAN");
        Rejected(ReceiveCommand("TCP", "127.0.0.1", "0.0.0.0", "3389", "30", "4"), "wildcard LAN");
        Rejected(ReceiveCommand("TCP", "127.0.0.1", "::ffff:192.0.2.10", "3389", "30", "4"), "mapped address");
        Rejected(ReceiveCommand("UDP", "::1", "fe80::1", "3389", "30", "4"), "unscoped IPv6");
        Rejected(ReceiveCommand("TCP", "127.0.0.1", "192.0.2.10", "0", "30", "4"), "bad port");
        Rejected(ReceiveCommand("TCP", "127.0.0.1", "192.0.2.10", "3389", "121", "4"), "duration bound");
        Rejected(ReceiveCommand("UDP", "127.0.0.1", "192.0.2.10", "3389", "30", "9"), "attempt bound");
        Rejected(ControlCommand("192.0.2.10", "3389", "3"), "remote TCP control refused");
        Rejected(ControlCommand("127.0.0.1", "3389", "6"), "control duration bound");
        ReceiverLifecycle(); NearDeadlineAndSlowFragments(); IdleDeadlineCases();
        CancellationAndFailures();
        UdpLifecycle(); IdleCancellation(); LocalControlCases();
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, false, true, true, true) ==
            "SUPPORTS TESTED RULE", "complete matching drop and local control");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, true, true, true, true) ==
            "REJECTS TESTED RULE OR SETUP", "unexpected remote reception");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, false, false, false, false) ==
            "INCONCLUSIVE", "no attempted local measurement is not rejection");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, false, true, false, true) ==
            "INCONCLUSIVE", "failed local client is not proof of firewall rejection");
        Check(PortProbeVerdict.ClassifyCleanup(false) == "INCOMPLETE",
            "cleanup independent from enforcement");
        Console.WriteLine("Port containment synthetic checks passed: " + checks);
    }
}
