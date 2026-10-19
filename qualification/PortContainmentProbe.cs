// REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.
// Experiment-only receiver. It is not linked into the ChildStream application.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
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
            throw new ArgumentException("Use an exact unicast LAN address and same-family loopback address.");
        if (!Int32.TryParse(args[10], NumberStyles.None, CultureInfo.InvariantCulture, out o.Port) ||
            !Int32.TryParse(args[12], NumberStyles.None, CultureInfo.InvariantCulture, out o.Seconds) ||
            !Int32.TryParse(args[14], NumberStyles.None, CultureInfo.InvariantCulture, out o.MaxAttempts) ||
            o.Port < 1 || o.Port > 65535 || o.Seconds < 1 || o.Seconds > 120 ||
            o.MaxAttempts < 1 || o.MaxAttempts > 8)
            throw new ArgumentException("Port must be 1..65535, duration 1..120 seconds, attempts 1..8.");
        return o;
    }
}

internal sealed class ProbeRunResult
{
    internal bool MeasurementComplete, ShutdownComplete;
    internal string StopReason;
    internal int Attempts;
}

internal interface IPortProbeRuntime
{ ProbeRunResult Run(PortProbeOptions options, Action<string> emit); }

internal interface IProbeTime
{
    long Milliseconds { get; } // monotonic elapsed time, never wall-clock time
    string Utc { get; }        // receipt label only
}

internal sealed class StopwatchProbeTime : IProbeTime
{
    private readonly Stopwatch watch = Stopwatch.StartNew();
    public long Milliseconds { get { return watch.ElapsedMilliseconds; } }
    public string Utc { get { return DateTime.UtcNow.ToString("o"); } }
}

internal sealed class ProbeBudget
{
    private readonly IProbeTime time;
    private readonly Func<bool> cancelled;
    private readonly long deadline;
    internal const int MaximumIoSliceMs = 50;
    internal ProbeBudget(IProbeTime time, Func<bool> cancelled, int seconds)
    {
        this.time = time; this.cancelled = cancelled;
        deadline = checked(time.Milliseconds + seconds * 1000L);
    }
    internal int Slice()
    {
        if (cancelled()) throw new OperationCanceledException("Probe cancellation requested.");
        long remaining = deadline - time.Milliseconds;
        if (remaining <= 0) throw new TimeoutException("Probe elapsed-time budget exhausted.");
        return (int)Math.Min(MaximumIoSliceMs, remaining);
    }
    internal string StopCondition()
    {
        if (cancelled()) return "CANCELLED";
        return time.Milliseconds >= deadline ? "DEADLINE" : null;
    }
}

internal sealed class ProbeDatagram
{
    internal int Count;
    internal EndPoint Remote;
    internal bool Oversize;
}

// The seam is the socket itself: the same receive/send/lifetime loop runs in
// production and synthetic tests. No test constructs a real Socket.
internal interface IProbeSocket : IDisposable
{
    string LocalEndpoint { get; }
    string RemoteEndpoint { get; }
    bool PollRead(int milliseconds);
    bool PollWrite(int milliseconds);
    IProbeSocket Accept(); // null for a nonblocking race
    int Receive(byte[] bytes, int offset, int count); // -1 for would-block
    int Send(byte[] bytes, int offset, int count); // -1 for would-block
    ProbeDatagram ReceiveDatagram(byte[] bytes); // null for would-block
    int SendDatagram(byte[] bytes, EndPoint remote); // -1 for would-block
}

internal interface IProbeSocketFactory
{ IProbeSocket Bind(PortProbeOptions options, IPAddress address); }

internal sealed class NativeProbeSocket : IProbeSocket
{
    private readonly Socket socket;
    internal NativeProbeSocket(Socket socket) { this.socket = socket; }
    public string LocalEndpoint { get { return socket.LocalEndPoint.ToString(); } }
    public string RemoteEndpoint { get { return socket.RemoteEndPoint.ToString(); } }
    public bool PollRead(int milliseconds)
    { return socket.Poll(milliseconds * 1000, SelectMode.SelectRead); }
    public bool PollWrite(int milliseconds)
    { return socket.Poll(milliseconds * 1000, SelectMode.SelectWrite); }
    private static bool WouldBlock(SocketException ex)
    { return ex.SocketErrorCode == SocketError.WouldBlock || ex.SocketErrorCode == SocketError.IOPending; }
    public IProbeSocket Accept()
    {
        try {
            Socket peer = socket.Accept();
            try { peer.Blocking = false; return new NativeProbeSocket(peer); }
            catch { peer.Dispose(); throw; }
        }
        catch (SocketException ex) { if (WouldBlock(ex)) return null; throw; }
    }
    public int Receive(byte[] bytes, int offset, int count)
    {
        try { return socket.Receive(bytes, offset, count, SocketFlags.None); }
        catch (SocketException ex) { if (WouldBlock(ex)) return -1; throw; }
    }
    public int Send(byte[] bytes, int offset, int count)
    {
        try { return socket.Send(bytes, offset, count, SocketFlags.None); }
        catch (SocketException ex) { if (WouldBlock(ex)) return -1; throw; }
    }
    public ProbeDatagram ReceiveDatagram(byte[] bytes)
    {
        EndPoint remote = socket.AddressFamily == AddressFamily.InterNetwork
            ? (EndPoint)new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
        try { return new ProbeDatagram {
            Count = socket.ReceiveFrom(bytes, 0, bytes.Length, SocketFlags.None, ref remote), Remote = remote }; }
        catch (SocketException ex) {
            if (WouldBlock(ex)) return null;
            if (ex.SocketErrorCode == SocketError.MessageSize)
                return new ProbeDatagram { Count = 0, Remote = null, Oversize = true };
            throw;
        }
    }
    public int SendDatagram(byte[] bytes, EndPoint remote)
    {
        try { return socket.SendTo(bytes, remote); }
        catch (SocketException ex) { if (WouldBlock(ex)) return -1; throw; }
    }
    public void Dispose() { socket.Dispose(); }
}

internal sealed class NativeProbeSocketFactory : IProbeSocketFactory
{
    public IProbeSocket Bind(PortProbeOptions options, IPAddress address)
    {
        var socket = new Socket(address.AddressFamily,
            options.Protocol == ProtocolType.Tcp ? SocketType.Stream : SocketType.Dgram,
            options.Protocol);
        try {
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            socket.ExclusiveAddressUse = true;
            socket.ReceiveBufferSize = 256;
            socket.SendBufferSize = 256;
            socket.Bind(new IPEndPoint(address, options.Port));
            if (options.Protocol == ProtocolType.Tcp) socket.Listen(2);
            socket.Blocking = false;
            return new NativeProbeSocket(socket);
        } catch { socket.Dispose(); throw; }
    }
}

internal sealed class SocketPortProbeRuntime : IPortProbeRuntime
{
    private static readonly byte[] Request = Encoding.ASCII.GetBytes("CS-PROBE-v1");
    private static readonly byte[] Ack = Encoding.ASCII.GetBytes("OK");
    private readonly IProbeSocketFactory factory;
    private readonly IProbeTime time;
    private readonly Func<bool> cancelled;
    internal SocketPortProbeRuntime(IProbeSocketFactory factory, IProbeTime time, Func<bool> cancelled)
    { this.factory = factory; this.time = time; this.cancelled = cancelled; }

    private static bool ExactMessage(byte[] data, int count)
    {
        if (count != Request.Length) return false;
        for (int i = 0; i < count; i++) if (data[i] != Request[i]) return false;
        return true;
    }
    private static void DisposeOwned(ref IProbeSocket owned, IList<string> errors)
    {
        IProbeSocket current = owned; owned = null;
        if (current == null) return;
        try { current.Dispose(); }
        catch (Exception ex) { errors.Add(ex.GetType().Name); }
    }
    private void HandleTcp(IProbeSocket peer, bool lan, ProbeBudget budget, Action<string> emit)
    {
        string side = lan ? "LAN" : "LOCAL";
        emit("RECEIVED|" + time.Utc + "|" + side + "|" + peer.RemoteEndpoint + "|TCP_CONNECTED");
        var data = new byte[Request.Length];
        int count = 0;
        while (count < data.Length) {
            if (!peer.PollRead(budget.Slice())) continue;
            budget.Slice(); // cancellation and deadline after active wait
            int next = peer.Receive(data, count, data.Length - count);
            if (next < 0) continue;
            if (next == 0) {
                emit("MESSAGE|" + time.Utc + "|" + side + "|PREMATURE_CLOSE");
                return;
            }
            count += next;
        }
        if (!ExactMessage(data, count)) {
            emit("MESSAGE|" + time.Utc + "|" + side + "|INVALID_MESSAGE");
            return;
        }
        int sent = 0;
        while (sent < Ack.Length) {
            if (!peer.PollWrite(budget.Slice())) continue;
            budget.Slice();
            int next = peer.Send(Ack, sent, Ack.Length - sent);
            if (next < 0) continue;
            if (next == 0) throw new IOException("Accepted socket closed before fixed ACK.");
            sent += next;
        }
        emit("MESSAGE|" + time.Utc + "|" + side + "|FIXED_MESSAGE_ACKED");
    }
    private void HandleUdp(IProbeSocket listener, bool lan, ProbeBudget budget,
        Action<string> emit, Action onReceived)
    {
        var data = new byte[32];
        ProbeDatagram received = listener.ReceiveDatagram(data);
        if (received == null) return;
        onReceived();
        string side = lan ? "LAN" : "LOCAL";
        emit("RECEIVED|" + time.Utc + "|" + side + "|" +
            (received.Remote == null ? "UNKNOWN" : received.Remote.ToString()) + "|" +
            (received.Oversize ? "OVERSIZE" : "UDP_DATAGRAM"));
        if (received.Oversize || !ExactMessage(data, received.Count)) {
            emit("MESSAGE|" + time.Utc + "|" + side + "|INVALID_MESSAGE");
            return;
        }
        while (true) {
            if (!listener.PollWrite(budget.Slice())) continue;
            budget.Slice();
            int sent = listener.SendDatagram(Ack, received.Remote);
            if (sent < 0) continue;
            if (sent != Ack.Length) throw new IOException("Fixed UDP ACK was not sent completely.");
            break;
        }
        emit("MESSAGE|" + time.Utc + "|" + side + "|FIXED_MESSAGE_ACKED");
    }

    public ProbeRunResult Run(PortProbeOptions options, Action<string> emit)
    {
        var result = new ProbeRunResult { MeasurementComplete = true };
        var cleanupErrors = new List<string>();
        IProbeSocket local = null, lan = null, peer = null;
        var budget = new ProbeBudget(time, cancelled, options.Seconds);
        try {
            local = factory.Bind(options, options.Local);
            budget.Slice();
            lan = factory.Bind(options, options.Lan);
            budget.Slice();
            emit("READY|" + time.Utc + "|PID=" + Process.GetCurrentProcess().Id +
                "|" + options.Protocol + "|" + local.LocalEndpoint + "|" + lan.LocalEndpoint);
            while (result.Attempts < options.MaxAttempts) {
                string stop = budget.StopCondition();
                if (stop != null) {
                    result.StopReason = stop;
                    if (stop == "CANCELLED") {
                        result.MeasurementComplete = false;
                        emit("MEASUREMENT_INCOMPLETE|" + time.Utc + "|CANCELLED");
                    }
                    break;
                }
                IProbeSocket selected = null;
                bool fromLan = false;
                if (local.PollRead(budget.Slice())) selected = local;
                else if (lan.PollRead(budget.Slice())) { selected = lan; fromLan = true; }
                if (selected == null) continue;
                budget.Slice(); // do not accept or read after cancellation/deadline
                if (options.Protocol == ProtocolType.Tcp) {
                    peer = selected.Accept();
                    if (peer == null) continue;
                    result.Attempts++;
                    try { HandleTcp(peer, fromLan, budget, emit); }
                    finally { DisposeOwned(ref peer, cleanupErrors); }
                } else {
                    HandleUdp(selected, fromLan, budget, emit, () => result.Attempts++);
                }
                if (cleanupErrors.Count != 0) throw new IOException("Accepted socket disposal failed.");
            }
            if (result.StopReason == null) result.StopReason = "ATTEMPT_CAP";
        } catch (OperationCanceledException) {
            result.StopReason = "CANCELLED_ACTIVE_IO";
            result.MeasurementComplete = false;
            emit("MEASUREMENT_INCOMPLETE|" + time.Utc + "|CANCELLED_ACTIVE_IO");
        } catch (TimeoutException) {
            result.StopReason = "DEADLINE_ACTIVE_IO";
            result.MeasurementComplete = false;
            emit("MEASUREMENT_INCOMPLETE|" + time.Utc + "|DEADLINE_ACTIVE_IO");
        } catch (Exception ex) {
            result.StopReason = "IO_ERROR";
            result.MeasurementComplete = false;
            emit("MEASUREMENT_ERROR|" + time.Utc + "|" + ex.GetType().Name);
        } finally {
            emit("STOP_REQUESTED|" + time.Utc + "|" + result.StopReason);
            DisposeOwned(ref peer, cleanupErrors);
            DisposeOwned(ref lan, cleanupErrors);
            DisposeOwned(ref local, cleanupErrors);
            result.ShutdownComplete = cleanupErrors.Count == 0;
            emit((result.ShutdownComplete ? "STOPPED|" : "SHUTDOWN_FAILED|") + time.Utc +
                "|REASON=" + result.StopReason + "|ATTEMPTS=" + result.Attempts +
                "|MEASUREMENT=" + (result.MeasurementComplete ? "COMPLETE" : "INCOMPLETE") +
                (result.ShutdownComplete ? "" : "|DISPOSE_ERRORS=" + String.Join(",", cleanupErrors)));
        }
        return result;
    }
}

internal static class PortProbeVerdict
{
    // Classifies supplied evidence only. Cleanup remains a separate result.
    internal static string ClassifyEnforcement(bool remoteSent, bool exactOwnedDrop,
        bool remoteReceived, bool localAttempted, bool localReceived, bool evidenceComplete)
    {
        if (remoteReceived) return "REJECTS TESTED RULE OR SETUP";
        if (!remoteSent || !evidenceComplete || !localAttempted || !localReceived) return "INCONCLUSIVE";
        return exactOwnedDrop ? "SUPPORTS TESTED RULE" : "INCONCLUSIVE";
    }
    internal static string ClassifyCleanup(bool cleanupComplete)
    { return cleanupComplete ? "COMPLETE" : "INCOMPLETE"; }
}

internal static class PortContainmentProbeProgram
{
    internal const string Label = "REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED";
    internal static int Run(string[] args, IPortProbeRuntime runtime,
        ILocalTcpControlRuntime control, Action<string> emit)
    {
        if (args.Length == 0 || args.Length == 1 && args[0] == "--help") {
            emit(Label);
            emit("Separate explicit authorization is required before any socket operation.");
            emit("receive --reviewed-live-approval YES --protocol TCP|UDP --local 127.0.0.1|::1 --lan ADDRESS --port PORT --seconds 1..120 --max-attempts 1..8");
            emit("control-tcp --reviewed-live-approval YES --local 127.0.0.1|::1 --port PORT --seconds 1..5");
            return 0;
        }
        try {
            emit(Label);
            if (args[0] == "control-tcp") {
                LocalTcpControlOptions controlOptions = LocalTcpControlOptions.Parse(args);
                LocalControlResult controlResult = control.Run(controlOptions, emit);
                return controlResult.AckValid && controlResult.ShutdownComplete ? 0 : 2;
            }
            PortProbeOptions options = PortProbeOptions.Parse(args);
            ProbeRunResult result = runtime.Run(options, emit);
            return result.MeasurementComplete && result.ShutdownComplete ? 0 : 2;
        } catch (Exception ex) {
            emit("FAILED|" + ex.GetType().Name + "|" + ex.Message);
            return 2;
        }
    }
    private sealed class CancelFlag { internal volatile bool Requested; }
    private static int Main(string[] args)
    {
        var cancel = new CancelFlag();
        ConsoleCancelEventHandler handler = (sender, e) => { e.Cancel = true; cancel.Requested = true; };
        Console.CancelKeyPress += handler;
        try {
            return Run(args,
                new SocketPortProbeRuntime(new NativeProbeSocketFactory(), new StopwatchProbeTime(),
                    () => cancel.Requested),
                new LocalTcpControlRuntime(new NativeLocalTcpFactory(), new StopwatchProbeTime(),
                    () => cancel.Requested), Console.WriteLine);
        } finally { Console.CancelKeyPress -= handler; }
    }
}
