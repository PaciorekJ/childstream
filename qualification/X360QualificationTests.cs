using System;
using System.Collections.Generic;
using System.Linq;

internal static class X360QualificationTests
{
    private sealed class Target : IKitTarget
    {
        internal uint Serial = 1;
        internal readonly List<ushort> Reports = new List<ushort>();
        internal int Creates, Removes;
        internal bool ThrowRemove;
        public bool Attached { get; private set; }
        public uint CreateNeutral() { Creates++; Attached = true; return Serial; }
        public void Submit(ushort buttons) { if (!Attached) throw new Exception("removed target"); Reports.Add(buttons); }
        public void Remove() { if (!Attached) throw new Exception("unrelated removal");
            if (ThrowRemove) throw new InvalidOperationException("native removal failed");
            Attached = false; Removes++; }
    }
    private sealed class World : IKitWorld
    {
        internal bool ProcessOkay = true, GenerationOkay = true, BadReadback, ThrowWrite;
        internal int Writes;
        internal KitNode[] Before = new KitNode[0], After;
        internal readonly Dictionary<string, DeviceProperty> Properties =
            new Dictionary<string, DeviceProperty>(StringComparer.OrdinalIgnoreCase);
        public KitNode[] Nodes() { return Writes == -1 ? Before : After; }
        public DeviceProperty ReadProperty(string id)
        {
            DeviceProperty p;
            if (!Properties.TryGetValue(id, out p)) return new DeviceProperty { Kind = PropertyKind.Absent };
            return BadReadback && Writes > 0 ? new DeviceProperty { Kind = PropertyKind.UInt32, Value = 99 } : p;
        }
        public void SetProperty(string id, uint value)
        {
            Writes++;
            if (ThrowWrite) throw new InvalidOperationException("native write failed");
            Properties[id] = new DeviceProperty { Kind = PropertyKind.UInt32, Value = value };
        }
        public bool ProcessMatches(int pid, long ticks) { return ProcessOkay && pid == 42 && ticks == 1000; }
        public bool GenerationMatches(int id, long logon)
        { return GenerationOkay && ((id == 1 && logon == 10) || (id == 2 && logon == 20)); }
    }
    private const string Bus = "NEFARIUS\\VIGEMBUS\\GEN1";
    private const string Node = "USB\\VID_045E&PID_028E\\01";
    private static KitNode Root() { return new KitNode { Id = "HTREE\\ROOT\\0", Present = true, HardwareIds = new string[0] }; }
    private static KitNode BusNode() { return new KitNode { Id = Bus, Parent = "HTREE\\ROOT\\0", Service = "ViGEmBus", Present = true,
        HardwareIds = new[] { "Nefarius\\ViGEmBus\\Gen1" } }; }
    private static KitNode Pad(string id, string parent)
    { return new KitNode { Id = id, Parent = parent, Present = true,
        HardwareIds = new[] { "USB\\VID_045E&PID_028E" }, Service = "xusb22" }; }
    private static KitIdentity Identity() { return new KitIdentity { Run = Guid.NewGuid(), FeederPid = 42,
        FeederStartTicks = 1000, ParentSession = 1, ParentLogon = 10, ChildSession = 2, ChildLogon = 20 }; }
    private static int checks;
    private static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    private static void Reject(Action action, string why)
    { bool rejected = false; try { action(); } catch (InvalidOperationException) { rejected = true; } Check(rejected, why); }
    private static X360Qualification New(out Target target, out World world)
    {
        target = new Target(); world = new World();
        world.Before = new[] { Root(), BusNode() };
        world.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        return new X360Qualification(target, world, Identity());
    }
    internal static int Run()
    {
        Target t; World w; var q = New(out t, out w);
        // The fake inventory returns After at creation, but the core's before
        // capture must be independently controlled by the fake in this test.
        w.After = w.Before; q.Create();
        Check(t.Creates == 1 && t.Reports.Count == 0, "creation must hold reports");
        Reject(() => q.Pulse(), "no assignment must mean zero reports");
        w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        var nodes = q.Assign();
        Check(nodes.Length == 1 && nodes[0] == Node && w.Writes == 1, "exact node assigned");
        Reject(() => q.Pulse(), "no explicit arm must mean zero reports");
        Reject(() => q.Arm(Guid.NewGuid()), "wrong run arm rejected");
        q.Arm(q.Identity.Run); q.Pulse();
        Check(t.Reports.SequenceEqual(new ushort[] { 0x1000, 0x2000, 0x1000, 0 }), "bounded reports only");
        q.ReconnectSameTarget();
        Check(t.Creates == 1 && t.Reports.Count == 4, "same target reconnect does not duplicate or pulse");
        Reject(() => q.Pulse(), "cannot replay the same challenge");
        var yes = new KitObservation { Complete = true, TargetAttributed = true, SequenceSeen = true };
        var no = new KitObservation { Complete = true, TargetAttributed = true };
        Check(q.Evaluate(yes, no, no).Verdict == KitVerdict.SyntheticPass, "modeled positive path remains synthetic");
        Check(q.Evaluate(yes, new KitObservation { Complete = true, TargetAttributed = true, SequenceSeen = true }, no).Verdict == KitVerdict.Fail,
            "parent reception fails");
        Check(q.Evaluate(yes, new KitObservation { Complete = true, TargetAttributed = true, TranslatedAction = true }, no).Verdict == KitVerdict.Fail,
            "translated parent action fails");
        Check(q.Evaluate(no, no, no).Verdict == KitVerdict.Inconclusive, "absent child pulse inconclusive");
        Check(q.Evaluate(yes, no, new KitObservation { Error = "observer died" }).Verdict == KitVerdict.Inconclusive,
            "observer error inconclusive");
        q.Stop(); Check(t.Removes == 1 && !t.Attached, "only own target removed after gate closed");
        Check(w.Properties[Node].Value == 2, "teardown retains restriction pending verified recovery");

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        w.ProcessOkay = false; Reject(() => q.Assign(), "wrong feeder rejected"); Check(w.Writes == 0 && t.Reports.Count == 0, "wrong feeder zero writes/reports");
        w.ProcessOkay = true; q.Identity.FeederStartTicks++; Reject(() => q.Assign(), "stale process creation time rejected");
        q.Identity.FeederStartTicks--; w.GenerationOkay = false; Reject(() => q.Assign(), "new child logon generation rejected");
        w.GenerationOkay = true; w.After = new[] { Root(), BusNode(), Pad(Node, Bus), Pad("USB\\VID_045E&PID_028E\\01", Bus) };
        Reject(() => q.Assign(), "duplicate identity rejected");
        w.After = new[] { Root(), BusNode(), Pad(Node, "HTREE\\ROOT\\0") };
        Reject(() => q.Assign(), "wrong bus ancestry rejected");
        w.After = new[] { Root(), BusNode(), Pad("USB\\VID_045E&PID_028E\\02", Bus) };
        Reject(() => q.Assign(), "reused or mismatched serial rejected");
        w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        w.Properties[Node] = new DeviceProperty { Kind = PropertyKind.WrongType };
        Reject(() => q.Assign(), "wrong property type rejected");
        w.Properties[Node] = new DeviceProperty { Kind = PropertyKind.UInt32, Value = 1 };
        Reject(() => q.Assign(), "conflicting prior session rejected");
        w.Properties[Node] = new DeviceProperty { Kind = PropertyKind.ReadError, NativeError = 5 };
        Reject(() => q.Assign(), "property read error rejected");
        w.Properties[Node] = new DeviceProperty { Kind = PropertyKind.Absent };
        w.ThrowWrite = true; Reject(() => q.Assign(), "native write failure rejected"); Check(t.Reports.Count == 0, "failed write held gate");
        w.ThrowWrite = false; w.BadReadback = true; Reject(() => q.Assign(), "wrong readback rejected");
        Check(t.Reports.Count == 0, "partial assignment held gate"); q.Stop();

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        q.Assign(); w.After = new[] { Root(), BusNode(), Pad("USB\\VID_045E&PID_028E\\02", Bus) };
        Reject(() => q.Arm(q.Identity.Run), "target recreation cannot inherit admission");
        Check(t.Reports.Count == 0, "recreation zero reports"); q.Stop();

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        Reject(() => q.Assign((node, prior) => { throw new InvalidOperationException("journal unavailable"); }),
            "journal failure before property write rejects");
        Check(w.Writes == 0 && t.Reports.Count == 0, "undurable prior state gives zero writes and reports");
        var recorded = new List<string>();
        q.Assign((node, prior) => { Check(prior.Kind == PropertyKind.Absent, "typed absent recorded"); recorded.Add(node); });
        Check(recorded.SequenceEqual(new[] { Node }) && w.Writes == 1, "prior state recorded before exact write");
        t.ThrowRemove = true;
        Reject(() => q.Stop(), "removal failure remains explicit");
        Check(t.Attached && t.Reports.Count == 0, "failed removal retains restriction and reports held");
        t.ThrowRemove = false; q.Stop(); Check(!t.Attached, "exact-owned removal may be retried");

        Check(WindowsKitWorld.DecodePropertyResult(false, 1168, 0, 0, null).Kind == PropertyKind.Absent,
            "native ERROR_NOT_FOUND means absent, not zero");
        Check(WindowsKitWorld.DecodePropertyResult(false, 5, 0, 0, null).Kind == PropertyKind.ReadError,
            "native access error is not absent");
        Check(WindowsKitWorld.DecodePropertyResult(true, 0, 6, 4, new byte[4]).Kind == PropertyKind.WrongType,
            "wrong native DEVPROP type rejected");
        Check(WindowsKitWorld.DecodePropertyResult(true, 0, 7, 8, new byte[8]).Kind == PropertyKind.WrongType,
            "wrong native DEVPROP size rejected");
        Check(WindowsKitWorld.DecodePropertyResult(true, 0, 7, 4, BitConverter.GetBytes((uint)2)).Value == 2,
            "native UINT32 is preserved exactly");

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        q.AcceptExternalAssignment(new[] { Node }, q.Identity.Run);
        Reject(() => q.PulseAfterExternalArm(q.Identity.Run), "feeder rejects missing property readback");
        Check(t.Reports.Count == 0, "missing external assignment gives zero reports");
        w.Properties[Node] = new DeviceProperty { Kind = PropertyKind.UInt32, Value = 2 };
        q.PulseAfterExternalArm(q.Identity.Run);
        Check(t.Reports.SequenceEqual(new ushort[] { 0x1000, 0x2000, 0x1000, 0 }),
            "exact external assignment releases only bounded pulse");
        q.Stop();
        Console.WriteLine("REVIEW-ONLY SYNTHETIC X360 qualification assertions passed: " + checks);
        return checks;
    }
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test") { Run(); return 0; }
        Console.WriteLine("REVIEW-ONLY QUALIFICATION KIT — LIVE EXECUTION NOT AUTHORIZED");
        Console.WriteLine("--self-test runs substituted effects only. Default and --help touch no Windows device or session API.");
        return args.Length == 0 || (args.Length == 1 && args[0] == "--help") ? 0 : 2;
    }
}
