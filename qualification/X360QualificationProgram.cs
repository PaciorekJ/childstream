using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal sealed class X360RunRecord
{
    public string Schema = "ChildStream.X360Qualification.v1";
    public string Origin = "NATIVE-ORIGIN-UNQUALIFIED";
    public string Source = X360KitBuild.SourceSha;
    public string ViGEmClient = "8d71f6740ffff4671cdadbca255ce528e3cd3fef";
    public string Run, Pipe, OwnerSid, FeederImageSha256;
    public int FeederPid, ParentSession, ChildSession;
    public long FeederStartTicks, ParentLogon, ChildLogon;
    public uint Serial;
    public uint Slot;
    public string State = "CreatedHeld";
    public string[] Nodes;
    public List<X360PhaseRecord> Phases = new List<X360PhaseRecord>();
    public List<X360PriorRecord> Prior = new List<X360PriorRecord>();
    public string Error;
}
internal sealed class X360PhaseRecord
{
    public ushort Buttons;
    public long StartTick, EndTick;
}
internal sealed class X360PriorRecord
{
    public string Node, Kind;
    public uint Value;
}

internal sealed class ExistingTarget : IKitTarget
{
    public bool Attached { get { return true; } }
    public uint CreateNeutral() { throw new InvalidOperationException("Only the live feeder may create a target."); }
    public void Submit(ushort buttons) { throw new InvalidOperationException("Assignment helper cannot submit reports."); }
    public void Remove() { throw new InvalidOperationException("Assignment helper cannot remove a target."); }
}

internal sealed class KitPeerSnapshot
{
    internal int Pid, ProcessSession, TokenSession;
    internal long StartTicks;
    internal string Sid, ImageSha256;
    internal bool Elevated;
}
internal enum KitPeerRole { Feeder, Assignment, ParentObserver, ChildObserver }
internal static class KitPeerAdmission
{
    internal static void Require(KitPeerSnapshot peer, X360RunRecord run, string ownImageHash, KitPeerRole role)
    {
        if (peer == null || run == null || String.IsNullOrWhiteSpace(ownImageHash) ||
            !String.Equals(peer.ImageSha256, ownImageHash, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(run.FeederImageSha256, ownImageHash, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(peer.Sid, run.OwnerSid, StringComparison.OrdinalIgnoreCase) ||
            peer.ProcessSession != peer.TokenSession)
            throw new InvalidOperationException("Peer image, account, or token session differs from this exact kit executable.");
        int expectedSession = role == KitPeerRole.Feeder || role == KitPeerRole.ChildObserver ?
            run.ChildSession : run.ParentSession;
        bool expectedElevation = role == KitPeerRole.Assignment;
        if (peer.ProcessSession != expectedSession || peer.Elevated != expectedElevation ||
            (role == KitPeerRole.Feeder && (peer.Pid != run.FeederPid || peer.StartTicks != run.FeederStartTicks)) ||
            peer.Pid <= 0 || peer.StartTicks <= 0)
            throw new InvalidOperationException("Peer role, process, or session generation differs.");
    }
}
internal static class KitObserverAdmission
{
    internal static void RequireReady(string message, string run, string role,
        long firstSampleTick, long receivedTick, long frequency)
    {
        if (message != "READY " + run + " " + role || firstSampleTick <= 0 ||
            receivedTick < firstSampleTick || frequency <= 0 ||
            receivedTick - firstSampleTick > frequency)
            throw new InvalidOperationException("Observer first sample is missing, stale, or for another run/role.");
    }
}

internal static class X360QualificationProgram
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder image, ref uint chars);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out uint value, uint bytes, out uint required);
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 65536 };
    private static string Root { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ChildStream", "X360Qualification"); } }
    private static string PathFor(Guid run) { return Path.Combine(Root, run.ToString("N") + ".json"); }
    private static string CurrentSid { get { return WindowsIdentity.GetCurrent().User.Value; } }
    private static string ImageHash(string path)
    { using (var stream = File.OpenRead(path)) using (var sha = SHA256.Create())
        return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant(); }
    private static string OwnImage()
    { using (var p = Process.GetCurrentProcess()) return p.MainModule.FileName; }
    private static KitIdentity ToIdentity(X360RunRecord r)
    { return new KitIdentity { Run = Guid.ParseExact(r.Run, "N"), FeederPid = r.FeederPid,
        FeederStartTicks = r.FeederStartTicks, ParentSession = r.ParentSession,
        ChildSession = r.ChildSession, ParentLogon = r.ParentLogon, ChildLogon = r.ChildLogon,
        Serial = r.Serial }; }
    private static void Save(X360RunRecord r)
    {
        Guid run = Guid.ParseExact(r.Run, "N");
        if (!Directory.Exists(Root))
        {
            var sid = WindowsIdentity.GetCurrent().User;
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(sid);
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(Root, acl);
        }
        string path = PathFor(run), body = Json.Serialize(r);
        // Both sides update this one-shot record in strict handshake order.
        // Never let a feeder status update erase the helper's durable originals.
        if (File.Exists(path) && (r.Prior == null || r.Prior.Count == 0))
        {
            var previous = Load(run);
            if (previous.Prior != null && previous.Prior.Count != 0) r.Prior = previous.Prior;
            body = Json.Serialize(r);
        }
        if (Encoding.UTF8.GetByteCount(body) > 16384) throw new InvalidOperationException("Run record exceeds limit.");
        var fileAcl = new FileSecurity();
        var owner = WindowsIdentity.GetCurrent().User;
        fileAcl.SetAccessRuleProtection(true, false);
        fileAcl.SetOwner(owner);
        fileAcl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var file = new FileStream(temporary, FileMode.CreateNew, FileSystemRights.Write, FileShare.None,
            4096, FileOptions.WriteThrough, fileAcl))
        { var bytes = Encoding.UTF8.GetBytes(body); file.Write(bytes, 0, bytes.Length); file.Flush(true); }
        if (File.Exists(path)) File.Replace(temporary, path, null);
        else File.Move(temporary, path);
    }
    private static X360RunRecord Load(Guid run)
    {
        var file = new FileInfo(PathFor(run));
        if (!file.Exists || file.Length > 16384) throw new InvalidOperationException("Bounded private run record unavailable.");
        X360RunRecord r = Json.Deserialize<X360RunRecord>(File.ReadAllText(file.FullName, Encoding.UTF8));
        if (r == null || r.Schema != "ChildStream.X360Qualification.v1" || r.Origin != "NATIVE-ORIGIN-UNQUALIFIED" ||
            r.Source != X360KitBuild.SourceSha ||
            r.ViGEmClient != "8d71f6740ffff4671cdadbca255ce528e3cd3fef" ||
            r.Run != run.ToString("N") || r.OwnerSid != CurrentSid ||
            r.Pipe != "ChildStream-X360-" + r.Run) throw new InvalidOperationException("Run record identity invalid.");
        return r;
    }
    internal static void Send(BinaryWriter w, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value ?? "");
        if (bytes.Length > 4096) throw new InvalidOperationException("Pipe message exceeds limit.");
        w.Write(bytes.Length); w.Write(bytes); w.Flush();
    }
    internal static string Receive(BinaryReader r)
    {
        int len = r.ReadInt32();
        if (len < 0 || len > 4096) throw new InvalidOperationException("Pipe message length invalid.");
        byte[] bytes = r.ReadBytes(len);
        if (bytes.Length != len) throw new EndOfStreamException();
        return Encoding.UTF8.GetString(bytes);
    }
    private static KitPeerSnapshot SnapshotPeer(uint peerPid)
    {
        using (var p = Process.GetProcessById((int)peerPid))
        {
            IntPtr handle = OpenProcess(0x1000, false, peerPid); // PROCESS_QUERY_LIMITED_INFORMATION
            if (handle == IntPtr.Zero) throw new InvalidOperationException("Peer process identity inaccessible.");
            try
            {
                var image = new StringBuilder(1024); uint chars = (uint)image.Capacity;
                if (!QueryFullProcessImageName(handle, 0, image, ref chars))
                    throw new InvalidOperationException("Peer image identity unavailable.");
                IntPtr token;
                if (!OpenProcessToken(handle, 0x0008, out token))
                    throw new InvalidOperationException("Peer token identity unavailable.");
                try
                {
                    uint tokenSession, elevation, required;
                    if (!GetTokenInformation(token, 12, out tokenSession, 4, out required) || required != 4 ||
                        !GetTokenInformation(token, 20, out elevation, 4, out required) || required != 4)
                        throw new InvalidOperationException("Peer token session or elevation unavailable.");
                    using (var identity = new WindowsIdentity(token))
                        return new KitPeerSnapshot { Pid = (int)peerPid,
                            StartTicks = p.StartTime.ToUniversalTime().Ticks, ProcessSession = p.SessionId,
                            TokenSession = (int)tokenSession, Elevated = elevation != 0,
                            Sid = identity.User.Value, ImageSha256 = ImageHash(image.ToString()) };
                }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(handle); }
        }
    }
    private static void CheckPeer(uint peerPid, X360RunRecord r, KitPeerRole role)
    {
        KitPeerAdmission.Require(SnapshotPeer(peerPid), r, ImageHash(OwnImage()), role);
        var world = new WindowsKitWorld();
        if (!world.ProcessMatches(r.FeederPid, r.FeederStartTicks) ||
            !world.GenerationMatches(r.ParentSession, r.ParentLogon) ||
            !world.GenerationMatches(r.ChildSession, r.ChildLogon))
            throw new InvalidOperationException("Peer WTS generation changed.");
    }
    private static void CheckContext(X360RunRecord r, bool feeder)
    {
        var world = new WindowsKitWorld();
        if (Process.GetCurrentProcess().SessionId != (feeder ? r.ChildSession : r.ParentSession) ||
            !world.ProcessMatches(r.FeederPid, r.FeederStartTicks) ||
            !world.GenerationMatches(r.ParentSession, r.ParentLogon) ||
            !world.GenerationMatches(r.ChildSession, r.ChildLogon) ||
            (!feeder && !world.ParentChildMatches(r.ParentSession, r.ChildSession)))
            throw new InvalidOperationException("Exact process or WTS generation is not current.");
    }
    private static string ObserverPipe(X360RunRecord r, string role)
    { return r.Pipe + "-" + role; }
    private sealed class ObserverLease : IDisposable
    {
        internal NamedPipeServerStream Pipe;
        internal KitPeerSnapshot Peer;
        internal long ReadyTick;
        public void Dispose() { if (Pipe != null) Pipe.Dispose(); }
    }
    private static ObserverLease AwaitObserver(X360RunRecord r, string role)
    {
        var sid = WindowsIdentity.GetCurrent().User;
        var acl = new PipeSecurity(); acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        var lease = new ObserverLease { Pipe = new NamedPipeServerStream(ObserverPipe(r, role),
            PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, acl) };
        try
        {
            var wait = lease.Pipe.BeginWaitForConnection(null, null);
            if (!wait.AsyncWaitHandle.WaitOne(TimeSpan.FromMinutes(2)))
                throw new TimeoutException("Required " + role + " observer did not connect.");
            lease.Pipe.EndWaitForConnection(wait);
            uint pid;
            if (!GetNamedPipeClientProcessId(lease.Pipe.SafePipeHandle.DangerousGetHandle(), out pid))
                throw new InvalidOperationException("Observer process identity unavailable.");
            CheckPeer(pid, r, role == "child" ? KitPeerRole.ChildObserver : KitPeerRole.ParentObserver);
            lease.Peer = SnapshotPeer(pid);
            // The observer sends READY only after its first native sample.
            using (var watchdog = new System.Threading.Timer(_ => { try { lease.Pipe.Dispose(); } catch { } },
                null, TimeSpan.FromSeconds(30), Timeout.InfiniteTimeSpan))
            using (var input = new BinaryReader(lease.Pipe, Encoding.UTF8, true))
            {
                string message = Receive(input);
                long firstSampleTick = input.ReadInt64();
                KitObserverAdmission.RequireReady(message, r.Run, role, firstSampleTick,
                    Stopwatch.GetTimestamp(), Stopwatch.Frequency);
            }
            lease.ReadyTick = Stopwatch.GetTimestamp();
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }
    private static void RequireObserverStillRunning(ObserverLease lease, X360RunRecord r, string role)
    {
        if (lease == null || !lease.Pipe.IsConnected ||
            !new WindowsKitWorld().ProcessMatches(lease.Peer.Pid, lease.Peer.StartTicks))
            throw new InvalidOperationException(role + " observer no longer connected.");
        CheckPeer((uint)lease.Peer.Pid, r, role == "child" ? KitPeerRole.ChildObserver : KitPeerRole.ParentObserver);
    }
    private static int Feeder(string[] args)
    {
        if (args.Length != 5) return 2;
        int parent, child; long parentLogon, childLogon;
        if (!Int32.TryParse(args[1], out parent) || !Int64.TryParse(args[2], out parentLogon) ||
            !Int32.TryParse(args[3], out child) || !Int64.TryParse(args[4], out childLogon)) return 2;
        using (var self = Process.GetCurrentProcess())
        {
            var r = new X360RunRecord { Run = Guid.NewGuid().ToString("N"), OwnerSid = CurrentSid,
                FeederPid = self.Id, FeederStartTicks = self.StartTime.ToUniversalTime().Ticks,
                ParentSession = parent, ParentLogon = parentLogon, ChildSession = child, ChildLogon = childLogon,
                FeederImageSha256 = ImageHash(OwnImage()) };
            r.Pipe = "ChildStream-X360-" + r.Run;
            CheckContext(r, true);
            var world = new WindowsKitWorld();
            using (var target = new PinnedViGEmX360())
            {
                var run = new X360Qualification(target, world, ToIdentity(r));
                try
                {
                    run.Create(); r.Serial = run.Identity.Serial; r.Slot = target.UserIndex();
                    var sid = WindowsIdentity.GetCurrent().User;
                    var acl = new PipeSecurity(); acl.SetAccessRuleProtection(true, false);
                    acl.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
                    using (var pipe = new NamedPipeServerStream(r.Pipe, PipeDirection.InOut, 1,
                        PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, acl))
                    {
                        Save(r);
                        Console.WriteLine("NEUTRAL TARGET HELD; run " + r.Run + "; no feeder report submitted.");
                        var wait = pipe.BeginWaitForConnection(null, null);
                        if (!wait.AsyncWaitHandle.WaitOne(TimeSpan.FromMinutes(5)))
                            throw new TimeoutException("Assignment helper did not connect in five minutes.");
                        pipe.EndWaitForConnection(wait);
                        uint peer;
                        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out peer))
                            throw new InvalidOperationException("Helper PID unavailable.");
                        CheckPeer(peer, r, KitPeerRole.Assignment);
                        // BinaryReader on named pipes does not support ReadTimeout reliably.
                        // Closing this one-shot pipe bounds any stalled handshake.
                        using (var watchdog = new System.Threading.Timer(_ => { try { pipe.Dispose(); } catch { } },
                            null, TimeSpan.FromMinutes(10), Timeout.InfiniteTimeSpan))
                        {
                        using (var input = new BinaryReader(pipe, Encoding.UTF8, true))
                        using (var output = new BinaryWriter(pipe, Encoding.UTF8, true))
                        {
                            if (Receive(input) != r.Run) throw new InvalidOperationException("Run handshake mismatch.");
                            Send(output, r.Run); output.Write(r.Serial);
                            var oldIds = run.BeforeSnapshot.Where(n => n.Present && n.HardwareIds != null &&
                                n.HardwareIds.Any(h => h.StartsWith("USB\\VID_045E&PID_028E", StringComparison.OrdinalIgnoreCase)))
                                .Select(n => n.Id).ToArray();
                            if (oldIds.Length > 32) throw new InvalidOperationException("Too many preexisting X360 identities.");
                            output.Write(oldIds.Length);
                            foreach (string id in oldIds) Send(output, id);
                            output.Flush();
                            string assignedMessage = Receive(input);
                            if (assignedMessage == "ABORT")
                            {
                                run.Stop(); r.State = "RemovedPendingPropertyRecovery"; Save(r);
                                Send(output, "REMOVED");
                                return 4;
                            }
                            if (assignedMessage != "ASSIGNED") throw new InvalidOperationException("Assignment not acknowledged.");
                            int count = input.ReadInt32();
                            if (count < 1 || count > 8) throw new InvalidOperationException("Assigned node count invalid.");
                            var nodes = new string[count];
                            for (int i = 0; i < count; i++) nodes[i] = Receive(input);
                            CheckContext(r, true);
                            run.AcceptExternalAssignment(nodes, Guid.ParseExact(r.Run, "N"));
                            r.Nodes = nodes; r.State = "AssignedHeld"; Save(r);
                            Send(output, "ASSIGNED-ACK");
                            string decision = Receive(input);
                            if (decision == "ABORT")
                            {
                                run.Stop(); r.State = "RemovedPendingPropertyRecovery"; Save(r);
                                Send(output, "REMOVED");
                                return 4;
                            }
                            if (decision != "ARM") throw new InvalidOperationException("No explicit arm received.");
                            CheckContext(r, true);
                            using (var challengeDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(4)))
                                run.PulseAfterExternalArm(Guid.ParseExact(r.Run, "N"), true,
                                    new MonotonicKitClock(), challengeDeadline.Token);
                            r.Phases = run.Phases.Select(p => new X360PhaseRecord
                                { Buttons = p.Buttons, StartTick = p.StartTick, EndTick = p.EndTick }).ToList();
                            r.State = "Pulsed"; Save(r);
                            Send(output, "PULSED");
                            run.Stop(); r.State = "RemovedPendingPropertyRecovery"; Save(r);
                            Send(output, "REMOVED");
                        }
                        }
                    }
                    return 0;
                }
                catch (Exception ex)
                {
                    r.Phases = run.Phases.Select(p => new X360PhaseRecord
                        { Buttons = p.Buttons, StartTick = p.StartTick, EndTick = p.EndTick }).ToList();
                    r.Error = ex.GetType().Name + ": " + ex.Message;
                    r.State = "StoppedOrRecoveryRequired";
                    try { run.Stop(); } catch (Exception cleanup) { r.Error += "; removal: " + cleanup.Message; }
                    try { Save(r); } catch { }
                    Console.Error.WriteLine(r.Error);
                    return 3;
                }
            }
        }
    }
    private static int Assign(string[] args)
    {
        if (args.Length != 2) return 2;
        Guid runId;
        if (!Guid.TryParseExact(args[1], "N", out runId)) return 2;
        var r = Load(runId);
        if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Operator must launch a separately approved elevated console; no automatic UAC.");
        CheckContext(r, false);
        using (var pipe = new NamedPipeClientStream(".", r.Pipe, PipeDirection.InOut, PipeOptions.None))
        {
            pipe.Connect(10000);
            uint peer;
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out peer))
                throw new InvalidOperationException("Feeder pipe PID unavailable.");
            CheckPeer(peer, r, KitPeerRole.Feeder);
            using (var watchdog = new System.Threading.Timer(_ => { try { pipe.Dispose(); } catch { } },
                null, TimeSpan.FromMinutes(10), Timeout.InfiniteTimeSpan))
            {
            using (var input = new BinaryReader(pipe, Encoding.UTF8, true))
            using (var output = new BinaryWriter(pipe, Encoding.UTF8, true))
            {
                Send(output, r.Run);
                if (Receive(input) != r.Run) throw new InvalidOperationException("Feeder run challenge mismatch.");
                uint serial = input.ReadUInt32();
                int oldCount = input.ReadInt32();
                if (oldCount < 0 || oldCount > 32) throw new InvalidOperationException("Baseline count invalid.");
                var baseline = new KitNode[oldCount];
                for (int i = 0; i < oldCount; i++) baseline[i] = new KitNode { Id = Receive(input), Present = true };
                r.Serial = serial;
                var world = new WindowsKitWorld();
                var assignment = new X360Qualification(new ExistingTarget(), world, ToIdentity(r));
                assignment.BeginExisting(baseline, serial);
                Console.WriteLine("Waiting for parent-pre observer's first sample before native assignment.");
                using (var parentPre = AwaitObserver(r, "parent-pre"))
                {
                long assignmentStart = Stopwatch.GetTimestamp();
                if (parentPre.ReadyTick >= assignmentStart)
                    throw new InvalidOperationException("Pre-assignment observation order invalid.");
                string[] nodes = null;
                bool armSent = false;
                try
                {
                nodes = assignment.Assign((node, prior) =>
                {
                    if (r.Prior.Any(p => String.Equals(p.Node, node, StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidOperationException("Duplicate prior property identity.");
                    r.Prior.Add(new X360PriorRecord { Node = node, Kind = prior.Kind.ToString(), Value = prior.Value });
                    r.State = "AssignmentInProgressHeld";
                    Save(r); // Durable original state before each native write.
                });
                r.Nodes = nodes; r.State = "AssignedHeld"; Save(r);
                Send(output, "ASSIGNED"); output.Write(nodes.Length);
                foreach (string node in nodes) Send(output, node);
                output.Flush();
                if (Receive(input) != "ASSIGNED-ACK") throw new InvalidOperationException("Feeder rejected assignment acknowledgment.");
                Console.WriteLine("Exact nodes assigned and read back. Start parent-fresh and child observers now; reports remain held.");
                using (var parentFresh = AwaitObserver(r, "parent-fresh"))
                using (var childObserver = AwaitObserver(r, "child"))
                {
                if (parentFresh.ReadyTick <= assignmentStart || childObserver.ReadyTick <= assignmentStart)
                    throw new InvalidOperationException("Post-assignment observation order invalid.");
                Console.WriteLine("Type ARM " + r.Run + " within two minutes to submit four reports; otherwise close this window.");
                var line = new StringBuilder(); var deadline = DateTime.UtcNow.AddMinutes(2);
                while (DateTime.UtcNow < deadline)
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Enter) break;
                        if (key.Key == ConsoleKey.Backspace) { if (line.Length > 0) line.Length--; }
                        else if (!Char.IsControl(key.KeyChar) && line.Length < 80) line.Append(key.KeyChar);
                    }
                    Thread.Sleep(50);
                }
                if (line.ToString() != "ARM " + r.Run) throw new InvalidOperationException("Explicit bounded arm was not given.");
                CheckContext(r, false);
                RequireObserverStillRunning(parentPre, r, "parent-pre");
                RequireObserverStillRunning(parentFresh, r, "parent-fresh");
                RequireObserverStillRunning(childObserver, r, "child");
                if (Stopwatch.GetTimestamp() - Math.Max(parentFresh.ReadyTick, childObserver.ReadyTick) >
                    Stopwatch.Frequency * 120)
                    throw new TimeoutException("Observer readiness expired before arm.");
                var now = KitAttribution.Resolve(baseline, world.Nodes(), serial);
                if (!nodes.SequenceEqual(now, StringComparer.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Target graph changed before arm.");
                foreach (string node in nodes)
                {
                    DeviceProperty p = world.ReadProperty(node);
                    if (p.Kind != PropertyKind.UInt32 || p.Value != r.ChildSession)
                        throw new InvalidOperationException("Assignment changed before arm.");
                }
                Send(output, "ARM");
                armSent = true;
                if (Receive(input) != "PULSED" || Receive(input) != "REMOVED")
                    throw new InvalidOperationException("Feeder did not confirm exact report and removal sequence.");
                r.State = "RemovedPendingPropertyRecovery"; Save(r);
                foreach (string node in nodes)
                {
                    DeviceProperty prior;
                    if (!assignment.Prior.TryGetValue(node, out prior))
                        throw new InvalidOperationException("Original property record unavailable.");
                    world.RestoreAbsentTargetProperty(node, (uint)r.ChildSession, prior);
                }
                r.State = "RemovedAndPropertyRestored"; Save(r);
                Console.WriteLine("Target removed and exact non-present property states restored. Enforcement remains unqualified.");
                return 0;
                }
                }
                catch (Exception original)
                {
                    if (armSent) throw;
                    try
                    {
                        Send(output, "ABORT");
                        if (Receive(input) != "REMOVED") throw new InvalidOperationException("Feeder removal unconfirmed.");
                        foreach (string node in assignment.Prior.Keys)
                        {
                            DeviceProperty prior;
                            if (!assignment.Prior.TryGetValue(node, out prior))
                                throw new InvalidOperationException("Original property unavailable after abort.");
                            world.RestoreAbsentTargetProperty(node, (uint)r.ChildSession, prior);
                        }
                        r.State = "RemovedAndPropertyRestoredAfterAbort"; Save(r);
                    }
                    catch (Exception recovery)
                    {
                        throw new InvalidOperationException("Observer/arm failed; exact property recovery is incomplete: " +
                            original.Message + "; " + recovery.Message, recovery);
                    }
                    throw;
                }
                }
            }
            }
        }
    }
    private static int Observe(string[] args)
    {
        if (args.Length != 4) return 2;
        int seconds; Guid runId;
        if (!Guid.TryParseExact(args[2], "N", out runId) ||
            !Int32.TryParse(args[3], out seconds) || seconds < 1 || seconds > 600 ||
            (args[1] != "parent-pre" && args[1] != "parent-fresh" && args[1] != "child")) return 2;
        X360RunRecord run = Load(runId);
        int session = args[1] == "child" ? run.ChildSession : run.ParentSession;
        long logon = args[1] == "child" ? run.ChildLogon : run.ParentLogon;
        if (run.Slot > 3 || !new WindowsKitWorld().ProcessMatches(run.FeederPid, run.FeederStartTicks))
            throw new InvalidOperationException("Owned X360 index or feeder no longer current.");
        if (Process.GetCurrentProcess().SessionId != session || !new WindowsKitWorld().GenerationMatches(session, logon))
            throw new InvalidOperationException("Observer exact WTS generation mismatch.");
        var xinput = new WindowsXInputSlotReader();
        string role = args[1]; var end = Stopwatch.GetTimestamp() + Stopwatch.Frequency * seconds;
        Console.WriteLine("NATIVE-ORIGIN-UNQUALIFIED XInput " + role + " polling owned target index " + run.Slot + ".");
        using (var readiness = new NamedPipeClientStream(".", ObserverPipe(run, role), PipeDirection.InOut, PipeOptions.None))
        {
        readiness.Connect(120000);
        uint helperPid;
        if (!GetNamedPipeServerProcessId(readiness.SafePipeHandle.DangerousGetHandle(), out helperPid))
            throw new InvalidOperationException("Observer helper identity unavailable.");
        CheckPeer(helperPid, run, KitPeerRole.Assignment);
        var sampler = new KitSequenceSampler();
        long firstTick = Stopwatch.GetTimestamp();
        ControllerSlotState first = xinput.Read(run.Slot);
        sampler.Sample(firstTick, first.Buttons, first.Error, Stopwatch.Frequency);
        using (var ready = new BinaryWriter(readiness, Encoding.UTF8, true))
        { Send(ready, "READY " + run.Run + " " + role); ready.Write(firstTick); ready.Flush(); }
        Thread.Sleep(50);
        uint previousPacket = UInt32.MaxValue; uint previousError = UInt32.MaxValue;
        while (Stopwatch.GetTimestamp() < end)
        {
            long tick = Stopwatch.GetTimestamp();
            ControllerSlotState state = xinput.Read(run.Slot);
            sampler.Sample(tick, state.Buttons, state.Error, Stopwatch.Frequency);
            if (state.Packet != previousPacket || state.Error != previousError)
            {
                Console.WriteLine(Json.Serialize(new { schema = "ChildStream.X360Observation.v1", origin = "NATIVE-ORIGIN-UNQUALIFIED",
                    run = run.Run, role = role, session = session, logon = logon, tick = tick, slot = run.Slot, error = state.Error,
                    packet = state.Packet, buttonA = (state.Buttons & 0x1000) != 0,
                    buttonB = (state.Buttons & 0x2000) != 0 }));
            }
            previousPacket = state.Packet; previousError = state.Error;
            Thread.Sleep(50);
        }
        Console.WriteLine(Json.Serialize(new { schema = "ChildStream.X360ObservationSummary.v1",
            origin = "NATIVE-ORIGIN-UNQUALIFIED", run = run.Run, role = role,
            complete = sampler.Complete, sequenceSeen = sampler.SequenceSeen }));
        }
        return 0;
    }
    private static int FocusObserve(string[] args)
    {
        if (args.Length != 3) return 2;
        Guid runId; int seconds;
        if (!Guid.TryParseExact(args[1], "N", out runId) || !Int32.TryParse(args[2], out seconds) ||
            seconds < 1 || seconds > 600) return 2;
        X360RunRecord r = Load(runId);
        if (Process.GetCurrentProcess().SessionId != r.ParentSession ||
            !new WindowsKitWorld().GenerationMatches(r.ParentSession, r.ParentLogon))
            throw new InvalidOperationException("Kit-owned parent focus window is outside exact parent generation.");
        using (var window = new Form { Text = "ChildStream X360 focus observer — review only",
            Width = 580, Height = 160, KeyPreview = true })
        using (var close = new System.Windows.Forms.Timer { Interval = seconds * 1000 })
        {
            var label = new Label { Text = "Focus this kit-owned window during the bounded pulse. Only navigation key codes in this window are recorded.",
                Dock = DockStyle.Fill, AutoSize = false };
            window.Controls.Add(label);
            window.KeyDown += (sender, e) =>
            {
                if (e.KeyCode != Keys.Up && e.KeyCode != Keys.Down && e.KeyCode != Keys.Left &&
                    e.KeyCode != Keys.Right && e.KeyCode != Keys.Enter && e.KeyCode != Keys.Escape &&
                    e.KeyCode != Keys.Tab && e.KeyCode != Keys.Space) return;
                Console.WriteLine(Json.Serialize(new { schema = "ChildStream.X360Focus.v1", origin = "NATIVE-ORIGIN-UNQUALIFIED",
                    run = r.Run, session = r.ParentSession, logon = r.ParentLogon,
                    tick = Stopwatch.GetTimestamp(), keyCode = e.KeyCode.ToString() }));
            };
            close.Tick += (sender, e) => window.Close();
            close.Start(); Application.Run(window);
        }
        return 0;
    }
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test") { X360QualificationTests.Run(); return 0; }
        if (args.Length == 0 || (args.Length == 1 && args[0] == "--help"))
        {
            Console.WriteLine("REVIEW-ONLY QUALIFICATION KIT — LIVE EXECUTION NOT AUTHORIZED");
            Console.WriteLine("--self-test uses substituted effects. Live modes require later separate authorization.");
            Console.WriteLine("Future modes: --feeder PARENT_ID PARENT_LOGON CHILD_ID CHILD_LOGON; --assign RUN_ID;");
            Console.WriteLine("--observe parent-pre|parent-fresh|child RUN_ID SECONDS (only owned X360 index)");
            Console.WriteLine("--focus RUN_ID SECONDS (bounded kit-owned parent window only)");
            Console.WriteLine("Interrupted property residue requires separately reviewed recovery; no standalone clear command is enabled.");
            return 0;
        }
        try
        {
            if (args[0] == "--feeder") return Feeder(args);
            if (args[0] == "--assign") return Assign(args);
            if (args[0] == "--observe") return Observe(args);
            if (args[0] == "--focus") return FocusObserve(args);
            return 2;
        }
        catch (Exception e) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 3; }
    }
}
