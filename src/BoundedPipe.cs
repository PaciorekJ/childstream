using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Threading;

internal sealed class SetupOutcomeUnknownException : IOException
{ internal SetupOutcomeUnknownException(string message) : base(message) { } }

// PipeStream does not support Stream.ReadTimeout/WriteTimeout on .NET Framework.
// Every pending I/O belongs to this wrapper: expiry closes the owned handle so
// neither a helper nor a test peer can remain blocked on an orphaned operation.
internal sealed class BoundedPipe : Stream
{
    private readonly PipeStream pipe;
    private readonly CancellationToken cancellation;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private long deadlineMilliseconds;
    private bool disposed;
    internal BoundedPipe(PipeStream pipe, int deadlineMs, CancellationToken cancellation = default(CancellationToken))
    {
        if (pipe == null || !pipe.IsConnected) throw new InvalidOperationException("A connected owned pipe is required.");
        this.pipe = pipe; this.cancellation = cancellation; ResetDeadline(deadlineMs);
    }
    internal void ResetDeadline(int milliseconds)
    {
        if (milliseconds < 1 || milliseconds > 240000) throw new ArgumentOutOfRangeException("milliseconds");
        deadlineMilliseconds = clock.ElapsedMilliseconds + milliseconds;
    }
    private int Remaining()
    {
        long left = deadlineMilliseconds - clock.ElapsedMilliseconds;
        if (left <= 0) { Dispose(); throw new TimeoutException("ChildStream pipe deadline expired; dispatched outcome may be uncertain."); }
        return (int)Math.Min(left, Int32.MaxValue);
    }
    private void Wait(IAsyncResult pending)
    {
        int remaining = Remaining();
        int completed = WaitHandle.WaitAny(new[] { pending.AsyncWaitHandle, cancellation.WaitHandle }, remaining);
        if (completed == 0) return;
        Dispose();
        if (completed == 1) throw new SetupOutcomeUnknownException("Setup pipe was cancelled after I/O dispatch; outcome is uncertain.");
        throw new TimeoutException("ChildStream pipe deadline expired; owned handle was closed; dispatched outcome may be uncertain.");
    }
    public override int Read(byte[] buffer, int offset, int count)
    {
        if (disposed) throw new ObjectDisposedException("BoundedPipe");
        cancellation.ThrowIfCancellationRequested();
        IAsyncResult pending = pipe.BeginRead(buffer, offset, count, null, null);
        Wait(pending); return pipe.EndRead(pending);
    }
    public override void Write(byte[] buffer, int offset, int count)
    {
        if (disposed) throw new ObjectDisposedException("BoundedPipe");
        cancellation.ThrowIfCancellationRequested();
        IAsyncResult pending = pipe.BeginWrite(buffer, offset, count, null, null);
        Wait(pending); pipe.EndWrite(pending);
    }
    // Each BeginWrite/EndWrite has already completed its bounded write. A
    // synchronous PipeStream.Flush could wait outside the deadline.
    public override void Flush() { if (disposed) throw new ObjectDisposedException("BoundedPipe"); }
    protected override void Dispose(bool disposing)
    {
        if (disposing && !disposed) { disposed = true; pipe.Dispose(); }
        base.Dispose(disposing);
    }
    public override bool CanRead { get { return !disposed && pipe.CanRead; } }
    public override bool CanWrite { get { return !disposed && pipe.CanWrite; } }
    public override bool CanSeek { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }
    internal static void WaitForConnection(NamedPipeServerStream server, int milliseconds,
        CancellationToken cancellation = default(CancellationToken))
    {
        cancellation.ThrowIfCancellationRequested();
        IAsyncResult pending = server.BeginWaitForConnection(null, null);
        int completed = WaitHandle.WaitAny(new[] { pending.AsyncWaitHandle, cancellation.WaitHandle }, milliseconds);
        if (completed != 0)
        {
            server.Dispose();
            if (completed == 1) throw new OperationCanceledException("Setup pipe was cancelled before any request was dispatched.");
            throw new TimeoutException("Setup pipe peer did not connect; no request was dispatched.");
        }
        server.EndWaitForConnection(pending);
    }
}
