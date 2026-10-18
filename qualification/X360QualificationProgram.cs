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
    public List<X360PriorRecord> Prior = new List<X360PriorRecord>();
    public string Error;
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
    private static void Send(BinaryWriter w, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value ?? "");
        if (bytes.Length > 4096) throw new InvalidOperationException("Pipe message exceeds limit.");
        w.Write(bytes.Length); w.Write(bytes); w.Flush();
    }
    private static string Receive(BinaryReader r)
    {
        int len = r.ReadInt32();
        if (len < 0 || len > 4096) throw new InvalidOperationException("Pipe message length invalid.");
        byte[] bytes = r.ReadBytes(len);
        if (bytes.Length != len) throw new EndOfStreamException();
        return Encoding.UTF8.GetString(bytes);
    }
    private static void CheckPeer(uint peerPid, X360RunRecord r, bool feeder)
    {
        using (var p = Process.GetProcessById((int)peerPid))
        {
            if (feeder && ((int)peerPid != r.FeederPid ||
                p.StartTime.ToUniversalTime().Ticks != r.FeederStartTicks || p.SessionId != r.ChildSession))
                throw new InvalidOperationException("Pipe feeder process identity changed.");
            IntPtr handle = OpenProcess(0x1000, false, peerPid); // PROCESS_QUERY_LIMITED_INFORMATION
            if (handle == IntPtr.Zero) throw new InvalidOperationException("Peer image identity inaccessible.");
            string path;
            try
            {
                var image = new StringBuilder(1024); uint chars = (uint)image.Capacity;
                if (!QueryFullProcessImageName(handle, 0, image, ref chars))
                    throw new InvalidOperationException("Peer image identity unavailable.");
                path = image.ToString();
            }
            finally { CloseHandle(handle); }
            if (!String.Equals(ImageHash(path), r.FeederImageSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Peer executable differs from pinned run executable.");
        }
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
                        CheckPeer(peer, r, false);
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
                            if (Receive(input) != "ASSIGNED") throw new InvalidOperationException("Assignment not acknowledged.");
                            int count = input.ReadInt32();
                            if (count < 1 || count > 8) throw new InvalidOperationException("Assigned node count invalid.");
                            var nodes = new string[count];
                            for (int i = 0; i < count; i++) nodes[i] = Receive(input);
                            CheckContext(r, true);
                            run.AcceptExternalAssignment(nodes, Guid.ParseExact(r.Run, "N"));
                            r.Nodes = nodes; r.State = "AssignedHeld"; Save(r);
                            Send(output, "ASSIGNED-ACK");
                            if (Receive(input) != "ARM") throw new InvalidOperationException("No explicit arm received.");
                            CheckContext(r, true);
                            run.PulseAfterExternalArm(Guid.ParseExact(r.Run, "N"));
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
            CheckPeer(peer, r, true);
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
                string[] nodes = assignment.Assign((node, prior) =>
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
                Console.WriteLine("Exact nodes assigned and read back. Reports remain held.");
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
        string role = args[1]; var end = DateTime.UtcNow.AddSeconds(seconds);
        Console.WriteLine("NATIVE-ORIGIN-UNQUALIFIED XInput " + role + " polling owned target index " + run.Slot + ".");
        uint previousPacket = UInt32.MaxValue; uint previousError = UInt32.MaxValue;
        while (DateTime.UtcNow < end)
        {
            long tick = Stopwatch.GetTimestamp();
            ControllerSlotState state = xinput.Read(run.Slot);
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
        return 0;
    }
    private static int Recover(string[] args)
    {
        if (args.Length != 2) return 2;
        Guid runId;
        if (!Guid.TryParseExact(args[1], "N", out runId)) return 2;
        X360RunRecord r = Load(runId);
        if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Separately approved elevated recovery is required; no automatic UAC.");
        if (r.Prior == null || r.Prior.Count == 0 || r.Prior.Count > 8 ||
            r.Prior.Any(p => p == null || String.IsNullOrWhiteSpace(p.Node) ||
                (p.Kind != "Absent" && p.Kind != "UInt32")) ||
            r.Prior.Select(p => p.Node).Distinct(StringComparer.OrdinalIgnoreCase).Count() != r.Prior.Count)
            throw new InvalidOperationException("Original-property record is incomplete or ambiguous.");
        // A live feeder might recreate or still submit a report. Wait for its
        // exact process to exit; never clear an assignment on a present target.
        if (new WindowsKitWorld().ProcessMatches(r.FeederPid, r.FeederStartTicks))
            throw new InvalidOperationException("Exact feeder remains live; recovery cannot clear a restriction.");
        var world = new WindowsKitWorld();
        foreach (var prior in r.Prior)
        {
            world.RestoreAbsentTargetProperty(prior.Node, (uint)r.ChildSession,
                new DeviceProperty { Kind = (PropertyKind)Enum.Parse(typeof(PropertyKind), prior.Kind), Value = prior.Value });
            r.State = "RecoveryInProgress"; Save(r);
        }
        r.State = "RemovedAndPropertyRestored"; Save(r);
        Console.WriteLine("Recorded non-present target properties reconciled; no device-session enforcement claim.");
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
            Console.WriteLine("--recover RUN_ID requires separately approved elevated recovery after exact feeder exit.");
            return 0;
        }
        try
        {
            if (args[0] == "--feeder") return Feeder(args);
            if (args[0] == "--assign") return Assign(args);
            if (args[0] == "--observe") return Observe(args);
            if (args[0] == "--recover") return Recover(args);
            if (args[0] == "--focus") return FocusObserve(args);
            return 2;
        }
        catch (Exception e) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 3; }
    }
}
