using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

internal static class SetupPipeTests
{
    private static int checks;
    private static void Check(bool yes, string what) { checks++; if (!yes) throw new Exception(what); }
    private static void Reject<T>(Action action, string what) where T : Exception
    {
        bool caught = false;
        try { action(); } catch (T) { caught = true; }
        Check(caught, what);
    }
    private static string Name() { return "ChildStream-TestPipe-" + Guid.NewGuid().ToString("N"); }
    private static NamedPipeServerStream Server(string name)
    { return new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous, 4096, 4096); }
    private static NamedPipeClientStream Client(string name)
    { return new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous); }
    public static int Main()
    {
        string name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            // The framework failure that used to prevent production setup.
            Reject<InvalidOperationException>(() => server.ReadTimeout = 1000,
                "PipeStream cannot use inherited Stream timeouts");
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            using (var read = new BoundedPipe(server, 1000))
            using (var write = new BoundedPipe(client, 1000))
            {
                var request = new SetupRequest { Operation = SetupOperation.PlanConnected };
                SetupWire.SendRequest(write, request);
                Check(SetupWire.ReadRequest(read).Operation == SetupOperation.PlanConnected,
                    "actual named pipe carries typed setup request");
                SetupWire.SendResult(read, true, "Plan " + new string('a', 64));
                Check(SetupWire.ReadResult(write).Contains(new string('a', 64)),
                    "actual named pipe carries framed setup result");
            }
        }
        using (var server = Server(Name()))
            Reject<TimeoutException>(() => BoundedPipe.WaitForConnection(server, 50),
                "no peer times out and tears down the server before dispatch");
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            var delayed = Task.Run(() => { Thread.Sleep(80); client.Connect(5000); });
            BoundedPipe.WaitForConnection(server, 2000);
            delayed.Wait();
            Check(server.IsConnected && client.IsConnected, "delayed peer connects before bounded deadline");
        }
        using (var server = Server(Name()))
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            Reject<OperationCanceledException>(() => BoundedPipe.WaitForConnection(server, 5000, cancelled.Token),
                "preconnection cancellation is known before dispatch");
        }
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            using (var cancelled = new CancellationTokenSource())
            using (var bounded = new BoundedPipe(server, 1000, cancelled.Token))
            {
                cancelled.Cancel();
                Reject<OperationCanceledException>(() => SetupWire.SendRequest(bounded,
                    new SetupRequest { Operation = SetupOperation.PlanConnected }),
                    "cancelled request never starts an I/O write");
            }
        }
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            using (var bounded = new BoundedPipe(server, 60))
                Reject<TimeoutException>(() => SetupWire.ReadRequest(bounded),
                    "stalled request read closes the owned pipe");
        }
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            client.WriteByte((byte)SetupOperation.PrepareFeature);
            using (var bounded = new BoundedPipe(server, 60))
                Reject<TimeoutException>(() => SetupWire.ReadRequest(bounded),
                    "partial request frame cannot wait indefinitely");
        }
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            client.WriteByte((byte)SetupOperation.PlanConnected);
            client.WriteByte(255);
            using (var bounded = new BoundedPipe(server, 1000))
                Reject<InvalidDataException>(() => SetupWire.ReadRequest(bounded),
                    "oversized request is rejected before allocation");
        }
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            client.Dispose();
            using (var bounded = new BoundedPipe(server, 1000))
                Reject<EndOfStreamException>(() => SetupWire.ReadRequest(bounded),
                    "closed peer is an incomplete request, never approval");
        }
        name = Name();
        using (var server = Server(name))
        using (var client = Client(name))
        {
            client.Connect(5000);
            BoundedPipe.WaitForConnection(server, 5000);
            using (var bounded = new BoundedPipe(server, 60))
                Reject<TimeoutException>(() => bounded.Write(new byte[8 * 1024 * 1024], 0, 8 * 1024 * 1024),
                    "stalled write closes the owned pipe");
        }
        Console.WriteLine("Actual ChildStream named-pipe deadline assertions passed: " + checks);
        return 0;
    }
}
