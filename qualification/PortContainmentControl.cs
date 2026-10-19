// REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.
// Fixed local TCP control only; arbitrary remote addresses and payloads are refused.
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

internal sealed class LocalTcpControlOptions
{
    internal IPAddress Local;
    internal int Port, Seconds;
    internal static LocalTcpControlOptions Parse(string[] args)
    {
        if (args.Length != 9 || args[0] != "control-tcp" ||
            args[1] != "--reviewed-live-approval" || args[2] != "YES" ||
            args[3] != "--local" || args[5] != "--port" || args[7] != "--seconds")
            throw new ArgumentException("Fixed local TCP control needs explicit arguments and separate approval.");
        var o = new LocalTcpControlOptions();
        if (!IPAddress.TryParse(args[4], out o.Local) ||
            !(o.Local.Equals(IPAddress.Loopback) || o.Local.Equals(IPAddress.IPv6Loopback)) ||
            !Int32.TryParse(args[6], NumberStyles.None, CultureInfo.InvariantCulture, out o.Port) ||
            !Int32.TryParse(args[8], NumberStyles.None, CultureInfo.InvariantCulture, out o.Seconds) ||
            o.Port < 1 || o.Port > 65535 || o.Seconds < 1 || o.Seconds > 5)
            throw new ArgumentException("Use 127.0.0.1 or ::1, port 1..65535, and 1..5 seconds.");
        return o;
    }
}

internal sealed class LocalControlResult
{
    internal bool AckValid, ShutdownComplete;
    internal string Measurement;
}

internal interface ILocalTcpControlRuntime
{ LocalControlResult Run(LocalTcpControlOptions options, Action<string> emit); }

internal interface ILocalTcpChannel : IDisposable
{
    void StartConnect(IPAddress local, int port);
    bool ConnectReady(int milliseconds);
    void FinishConnect();
    bool PollRead(int milliseconds);
    bool PollWrite(int milliseconds);
    int Read(byte[] bytes, int offset, int count); // -1 means would-block
    int Write(byte[] bytes, int offset, int count); // -1 means would-block
}

internal interface ILocalTcpFactory
{ ILocalTcpChannel Create(AddressFamily family); }

internal sealed class NativeLocalTcpChannel : ILocalTcpChannel
{
    private readonly Socket socket;
    private IAsyncResult pending;
    private WaitHandle connectWait;
    internal NativeLocalTcpChannel(AddressFamily family)
    { socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp); }
    public void StartConnect(IPAddress local, int port)
    {
        pending = socket.BeginConnect(new IPEndPoint(local, port), null, null);
        connectWait = pending.AsyncWaitHandle;
    }
    public bool ConnectReady(int milliseconds)
    { return connectWait.WaitOne(milliseconds); }
    public void FinishConnect()
    { socket.EndConnect(pending); socket.Blocking = false; }
    public bool PollRead(int milliseconds)
    { return socket.Poll(milliseconds * 1000, SelectMode.SelectRead); }
    public bool PollWrite(int milliseconds)
    { return socket.Poll(milliseconds * 1000, SelectMode.SelectWrite); }
    private static bool WouldBlock(SocketException ex)
    { return ex.SocketErrorCode == SocketError.WouldBlock || ex.SocketErrorCode == SocketError.IOPending; }
    public int Read(byte[] bytes, int offset, int count)
    {
        try { return socket.Receive(bytes, offset, count, SocketFlags.None); }
        catch (SocketException ex) { if (WouldBlock(ex)) return -1; throw; }
    }
    public int Write(byte[] bytes, int offset, int count)
    {
        try { return socket.Send(bytes, offset, count, SocketFlags.None); }
        catch (SocketException ex) { if (WouldBlock(ex)) return -1; throw; }
    }
    public void Dispose()
    {
        try { socket.Dispose(); }
        finally { if (connectWait != null) connectWait.Close(); }
    }
}

internal sealed class NativeLocalTcpFactory : ILocalTcpFactory
{
    public ILocalTcpChannel Create(AddressFamily family)
    { return new NativeLocalTcpChannel(family); }
}

internal sealed class LocalTcpControlRuntime : ILocalTcpControlRuntime
{
    private static readonly byte[] Request = Encoding.ASCII.GetBytes("CS-PROBE-v1");
    private static readonly byte[] Ack = Encoding.ASCII.GetBytes("OK");
    private readonly ILocalTcpFactory factory;
    private readonly IProbeTime time;
    private readonly Func<bool> cancelled;
    internal LocalTcpControlRuntime(ILocalTcpFactory factory, IProbeTime time, Func<bool> cancelled)
    { this.factory = factory; this.time = time; this.cancelled = cancelled; }

    public LocalControlResult Run(LocalTcpControlOptions options, Action<string> emit)
    {
        var result = new LocalControlResult { Measurement = "INCOMPLETE" };
        var budget = new ProbeBudget(time, cancelled, options.Seconds);
        ILocalTcpChannel channel = null;
        try {
            channel = factory.Create(options.Local.AddressFamily);
            budget.Slice();
            channel.StartConnect(options.Local, options.Port);
            while (!channel.ConnectReady(budget.Slice())) { }
            budget.Slice();
            channel.FinishConnect();
            int sent = 0;
            while (sent < Request.Length) {
                if (!channel.PollWrite(budget.Slice())) continue;
                budget.Slice();
                int next = channel.Write(Request, sent, Request.Length - sent);
                if (next < 0) continue;
                if (next == 0) throw new IOException("Local request closed during write.");
                sent += next;
            }
            var response = new byte[Ack.Length];
            int received = 0;
            while (received < response.Length) {
                if (!channel.PollRead(budget.Slice())) continue;
                budget.Slice();
                int next = channel.Read(response, received, response.Length - received);
                if (next < 0) continue;
                if (next == 0) throw new EndOfStreamException("Local ACK closed before two bytes.");
                received += next;
            }
            result.AckValid = response[0] == Ack[0] && response[1] == Ack[1];
            result.Measurement = result.AckValid ? "ACK_OK" : "MALFORMED_ACK";
        } catch (EndOfStreamException) { result.Measurement = "PREMATURE_CLOSE"; }
          catch (OperationCanceledException) { result.Measurement = "CANCELLED"; }
          catch (TimeoutException) { result.Measurement = "TIMEOUT"; }
          catch (Exception ex) { result.Measurement = "IO_ERROR:" + ex.GetType().Name; }
        finally {
            emit("CONTROL_STOP_REQUESTED|" + time.Utc + "|" + result.Measurement);
            string disposalError = null;
            if (channel != null) {
                try { channel.Dispose(); }
                catch (Exception ex) { disposalError = ex.GetType().Name; }
            }
            result.ShutdownComplete = disposalError == null;
            emit((result.ShutdownComplete ? "CONTROL_STOPPED|" : "CONTROL_SHUTDOWN_FAILED|") +
                time.Utc + "|MEASUREMENT=" + result.Measurement +
                (disposalError == null ? "" : "|DISPOSE_ERROR=" + disposalError));
        }
        return result;
    }
}
