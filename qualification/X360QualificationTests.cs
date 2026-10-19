using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

internal static class X360QualificationTests
{
    private sealed class Target : IKitTarget
    {
        internal uint Serial = 1;
        internal readonly List<ushort> Reports = new List<ushort>();
        internal int Creates, Removes;
        internal bool ThrowRemove;
        internal ushort Current;
        internal int CurrentRaw, RemovedFlag;
        public bool Attached { get; private set; }
        public uint CreateNeutral() { Creates++; Attached = true; Interlocked.Exchange(ref RemovedFlag, 0); return Serial; }
        public void Submit(ushort buttons) { if (!Attached) throw new Exception("removed target");
            Current = buttons; Interlocked.Exchange(ref CurrentRaw, buttons); Reports.Add(buttons); }
        public void Remove() { if (!Attached) throw new Exception("unrelated removal");
            if (ThrowRemove) throw new InvalidOperationException("native removal failed");
            Attached = false; Interlocked.Exchange(ref RemovedFlag, 1); Removes++; }
    }
    private sealed class TargetReader : IControllerSlotReader
    {
        internal Target Target;
        internal bool ParentDisconnected;
        private int reads;
        public ControllerSlotState Read(uint slot)
        {
            int packet = Interlocked.Increment(ref reads);
            return ParentDisconnected || Thread.VolatileRead(ref Target.RemovedFlag) != 0 ?
                new ControllerSlotState { Error = 1167 } :
                new ControllerSlotState { Error = 0, Packet = (uint)packet,
                    Buttons = (ushort)Thread.VolatileRead(ref Target.CurrentRaw) };
        }
    }
    private sealed class ObserverFixture : IDisposable
    {
        private readonly AnonymousPipeServerStream commands;
        private readonly AnonymousPipeClientStream observerInput;
        private readonly AnonymousPipeServerStream responses;
        private readonly AnonymousPipeClientStream helperInput;
        private readonly BinaryWriter writer;
        private readonly BinaryReader reader;
        internal readonly Task<X360ObserverOutcome> Result;
        internal ObserverFixture(X360RunRecord run, string role, IControllerSlotReader slotReader, int seconds = 8)
        {
            commands = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None);
            observerInput = new AnonymousPipeClientStream(PipeDirection.In, commands.ClientSafePipeHandle);
            responses = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None);
            helperInput = new AnonymousPipeClientStream(PipeDirection.In, responses.ClientSafePipeHandle);
            writer = new BinaryWriter(commands, Encoding.UTF8, true);
            reader = new BinaryReader(helperInput, Encoding.UTF8, true);
            Result = Task.Factory.StartNew(() => X360QualificationProgram.ObserveCoordinated(
                observerInput, responses, slotReader, run, role, seconds, null));
        }
        internal string Read()
        {
            var work = Task.Factory.StartNew(() => X360QualificationProgram.Receive(reader));
            if (!work.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Synthetic observer response deadline.");
            return work.Result;
        }
        internal string Command(X360RunRecord run, string role, string command)
        {
            return KitObserverProtocol.Command(reader, writer, run, role, command, 3000, Dispose);
        }
        public void Dispose()
        {
            writer.Dispose(); reader.Dispose(); commands.Dispose(); observerInput.Dispose();
            responses.Dispose(); helperInput.Dispose();
        }
    }
    private sealed class Clock : IKitClock
    {
        internal long Now = 1000;
        internal Target Target;
        internal KitSequenceSampler Sampler;
        internal long StartSamplingAt = 0;
        internal int SampleEvery = 1, Steps;
        internal CancellationTokenSource CancelAfterFirstStep;
        internal bool Overshoot;
        public long Ticks { get { return Now; } }
        public long Frequency { get { return 1000; } }
        public void WaitUntil(long end, CancellationToken cancel)
        {
            while (Now < end)
            {
                cancel.ThrowIfCancellationRequested();
                Now = Math.Min(Now + 50, end);
                Steps++;
                if (CancelAfterFirstStep != null && Steps == 1) CancelAfterFirstStep.Cancel();
                if (Sampler != null && Now >= StartSamplingAt && Steps % SampleEvery == 0)
                    Sampler.Sample(Now, Target.Current, 0, Frequency);
            }
            if (Overshoot) Now += 200;
        }
    }
    private static Clock SampleClock(Target t)
    { return new Clock { Target = t, Sampler = new KitSequenceSampler() }; }
    private static byte[] NativeBytes(params string[] strings)
    { return Encoding.Unicode.GetBytes(String.Join("\0", strings) + (strings.Length == 1 ? "\0" : "\0\0")); }
    private static KitNode NativeBus()
    {
        byte[] service = NativeBytes("ViGEmBus");
        byte[] ids = NativeBytes("Nefarius\\ViGEmBus\\Gen1", "Nefarius\\ViGEmBus\\Gen1Alt");
        return new KitNode { Id = Bus, Parent = "HTREE\\ROOT\\0", Present = true,
            Service = WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 1, service, (uint)service.Length)[0],
            HardwareIds = WindowsKitWorld.DecodeRegistryStrings(1, true, 0, 7, ids, (uint)ids.Length) };
    }
    private static KitNode NativePad()
    {
        byte[] service = NativeBytes("xusb22");
        byte[] ids = NativeBytes("USB\\VID_045E&PID_028E", "USB\\Class_FF");
        return new KitNode { Id = Node, Parent = Bus, Present = true,
            Service = WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 1, service, (uint)service.Length)[0],
            HardwareIds = WindowsKitWorld.DecodeRegistryStrings(1, true, 0, 7, ids, (uint)ids.Length) };
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
    private static void CheckFixtureReady(string message, JavaScriptSerializer json,
        X360RunRecord run, string role)
    {
        var ready = json.Deserialize<X360ObserverReadyRecord>(message);
        // The pipe exercises the real observer/reader path. The synthetic admission
        // clock is pinned to receipt just after the second sample so CI thread-pool
        // scheduling cannot turn this into a nondeterministic stale-message test.
        // Stale and wrong-role records are tested separately below.
        KitObserverAdmission.RequireReady(ready, run.Run, role, run.Slot,
            ready.SecondTick + Stopwatch.Frequency / 10, Stopwatch.Frequency);
    }
    private static void CheckFixtureArm(string message, JavaScriptSerializer json,
        X360RunRecord run, string role)
    {
        var arm = json.Deserialize<X360ObserverArmRecord>(message);
        KitObserverAdmission.RequireArm(arm, run.Run, role, run.Slot,
            arm.Tick + Stopwatch.Frequency / 10, Stopwatch.Frequency);
    }
    private static void ConnectedFinalizationRegression()
    {
        Target target; World world;
        var qualification = New(out target, out world);
        world.After = world.Before; qualification.Create();
        world.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        var run = new X360RunRecord { Run = qualification.Identity.Run.ToString("N"),
            OwnerSid = "synthetic-owner", FeederImageSha256 = "synthetic-executable",
            FeederPid = 42, FeederStartTicks = 1000, ParentSession = 1, ParentLogon = 10,
            ChildSession = 2, ChildLogon = 20, Serial = qualification.Identity.Serial, Slot = 1 };
        run.Pipe = "ChildStream-X360-" + run.Run;
        string temporary = Path.Combine(Environment.CurrentDirectory, "tests", ".artifacts",
            "x360-qualification", "selftest-" + Guid.NewGuid().ToString("N"));
        var json = new JavaScriptSerializer();
        try
        {
            X360QualificationProgram.SaveAt(run, temporary, false);
            X360RunRecord helper = X360QualificationProgram.ReadAt(qualification.Identity.Run, temporary);
            using (var parentPre = new ObserverFixture(run, "parent-pre", new TargetReader
                { Target = target, ParentDisconnected = true }))
            {
                CheckFixtureReady(parentPre.Read(), json, run, "parent-pre");
                Check(parentPre.Command(run, "parent-pre", "ASSIGNMENT") ==
                    "ACK ASSIGNMENT " + run.Run + " parent-pre", "parent-pre phase acknowledged before assignment");
                qualification.Assign();
                using (var parentFresh = new ObserverFixture(run, "parent-fresh", new TargetReader
                    { Target = target, ParentDisconnected = true }))
                using (var child = new ObserverFixture(run, "child", new TargetReader { Target = target }))
                {
                    CheckFixtureReady(parentFresh.Read(), json, run, "parent-fresh");
                    CheckFixtureReady(child.Read(), json, run, "child");
                    qualification.Arm(qualification.Identity.Run);
                    foreach (var observer in new[] { new { Fixture = parentPre, Role = "parent-pre" },
                        new { Fixture = parentFresh, Role = "parent-fresh" },
                        new { Fixture = child, Role = "child" } })
                    {
                        CheckFixtureArm(observer.Fixture.Command(run, observer.Role, "START"),
                            json, run, observer.Role);
                    }
                    qualification.Pulse(new MonotonicKitClock(), CancellationToken.None);
                    run.Phases = qualification.Phases.Select(p => new X360PhaseRecord { Buttons = p.Buttons,
                        StartTick = p.StartTick, EndTick = p.EndTick, ActualEndTick = p.ActualEndTick,
                        Completed = p.Completed }).ToList();
                    KitPhaseAdmission.Require(new X360PhaseEnvelope { Run = run.Run, Phases = run.Phases },
                        run.Run, Stopwatch.Frequency);
                    Reject(() => KitPhaseAdmission.Require(new X360PhaseEnvelope
                        { Run = "wrong-run", Phases = run.Phases }, run.Run, Stopwatch.Frequency),
                        "wrong-run feeder timeline cannot be finalized");
                    X360QualificationProgram.SaveAt(run, temporary, false);
                    helper.Observations = KitObservationFinalization.Collect(helper,
                        (role, command) => (role == "parent-pre" ? parentPre :
                            role == "parent-fresh" ? parentFresh : child).Command(run, role, command),
                        json, Stopwatch.GetTimestamp,
                        record => { helper.Observations.Add(record);
                            X360QualificationProgram.SaveAt(helper, temporary, false); });
                    Check(helper.Observations.Single(o => o.Role == "child").Complete &&
                        helper.Observations.Single(o => o.Role == "child").SequenceSeen,
                        "real IPC child observer samples completed A/B/A/neutral window");
                    Check(helper.Observations.Where(o => o.Role != "child").All(o => o.Complete &&
                        !o.SequenceSeen && o.NotConnected > 0),
                        "documented parent not-connected state is scoped challenge evidence");
                    Check(KitObservationFinalization.Classify(helper, true).Verdict == KitVerdict.SyntheticPass &&
                        KitObservationFinalization.Classify(helper, false).Verdict == KitVerdict.Inconclusive,
                        "attributed synthetic route is scoped; executable slot alone is never isolation pass");
                    X360QualificationProgram.SaveAt(helper, temporary, false);
                    var frozen = helper.Observations.Select(o => o.ChallengeSamples + ":" +
                        o.SequenceSeen + ":" + o.Complete).ToArray();
                    int completedObservers = 0;
                    bool restored = false;
                    bool clean = KitPostChallengeCleanup.Run(helper,
                        () => { qualification.Stop(); run.TargetCleanup = "Removed";
                            X360QualificationProgram.SaveAt(run, temporary, false); },
                        role => {
                            var fixture = role == "parent-pre" ? parentPre :
                                role == "parent-fresh" ? parentFresh : child;
                            if (fixture.Command(run, role, "TEARDOWN") !=
                                "ACK TEARDOWN " + run.Run + " " + role ||
                                !fixture.Result.Wait(TimeSpan.FromSeconds(3)))
                                throw new TimeoutException("Observer did not complete teardown.");
                            completedObservers++;
                        },
                        () => { if (target.Attached) throw new InvalidOperationException("Target still present.");
                            restored = true; },
                        () => X360QualificationProgram.SaveAt(helper, temporary, false), null);
                    Check(clean && restored && completedObservers == 3 &&
                        target.Creates == 1 && target.Removes == 1 &&
                        target.Reports.SequenceEqual(new ushort[] { 0x1000, 0x2000, 0x1000, 0 }) &&
                        helper.ObserverTeardown.All(status => status.Status == "Exited"),
                        "production coordinator adds no target or report and completes all three observer teardowns and recovery");
                    Check(child.Result.Wait(TimeSpan.FromSeconds(3)) &&
                        child.Result.Result.TeardownNotConnected > 0 &&
                        child.Result.Result.Challenge.Complete,
                        "expected post-removal disappearance does not invalidate child challenge coverage");
                    var final = X360QualificationProgram.ReadAt(qualification.Identity.Run, temporary);
                    Check(final.Phases.Count == 4 && final.Phases.All(p => p.Completed) &&
                        final.Observations.Count == 3 && final.TargetCleanup == "Removed" &&
                        final.PropertyCleanup == "Restored" &&
                        final.ObserverTeardown.Count == 3 &&
                        final.Observations.Select(o => o.ChallengeSamples + ":" +
                            o.SequenceSeen + ":" + o.Complete).SequenceEqual(frozen),
                        "feeder phases and frozen challenge evidence survive coordinated removal, observer exit, and restoration");
                }
            }
        }
        finally
        {
            string expectedRoot = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory,
                "tests", ".artifacts", "x360-qualification"));
            if (Path.GetDirectoryName(Path.GetFullPath(temporary)) != expectedRoot)
                throw new InvalidOperationException("Self-test temporary directory escaped its owned root.");
            if (Directory.Exists(temporary)) Directory.Delete(temporary, true);
        }
    }
    private static X360ObservationRecord WindowRecord(string run, string role, uint slot,
        long[] ticks, ushort[] buttons, uint[] errors, bool gapAfter)
    {
        var window = new KitObserverWindow(role == "child", false);
        window.StartChallenge(ticks[0]);
        for (int i = 0; i < ticks.Length; i++) window.Sample(ticks[i], buttons[i], errors[i], 1000);
        if (gapAfter) window.Sample(ticks[ticks.Length - 1] + 250, 0, 0, 1000);
        window.FinalizeChallenge(ticks[ticks.Length - 1] + (gapAfter ? 300 : 50));
        var result = KitObserverAdmission.Finalize(run, role, slot, window);
        window.Teardown(); window.Sample(result.ChallengeEnd + 50, 0, 1167, 1000);
        return result;
    }
    private static void WithholdObserverAck(X360RunRecord run, string role)
    {
        using (var commandOut = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None))
        using (var commandIn = new AnonymousPipeClientStream(PipeDirection.In, commandOut.ClientSafePipeHandle))
        using (var responseOut = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None))
        using (var responseIn = new AnonymousPipeClientStream(PipeDirection.In, responseOut.ClientSafePipeHandle))
        using (var input = new BinaryReader(responseIn, Encoding.UTF8, true))
        using (var output = new BinaryWriter(commandOut, Encoding.UTF8, true))
            KitObserverProtocol.Command(input, output, run, role, "TEARDOWN", 200,
                responseOut.Dispose);
    }
    private static void PostChallengeCleanupRegressions()
    {
        var run = new X360RunRecord { Run = Guid.NewGuid().ToString("N"),
            OwnerSid = "synthetic-owner", FeederImageSha256 = "synthetic-executable",
            FeederPid = 42, FeederStartTicks = 1000, ParentSession = 1, ParentLogon = 10,
            ChildSession = 2, ChildLogon = 20, Serial = 1, Slot = 1 };
        run.Pipe = "ChildStream-X360-" + run.Run;
        run.Observations.Add(WindowRecord(run.Run, "child", 1,
            new long[] { 1000, 1050, 1100, 1150 },
            new ushort[] { 0x1000, 0x2000, 0x1000, 0 }, new uint[4], false));
        string root = Path.Combine(Environment.CurrentDirectory, "tests", ".artifacts",
            "x360-qualification", "selftest-cleanup-" + Guid.NewGuid().ToString("N"));
        try
        {
            X360QualificationProgram.SaveAt(run, root, false);
            var order = new List<string>();
            bool complete = KitPostChallengeCleanup.Run(run,
                () => order.Add("target"),
                role => { order.Add(role); if (role == "parent-fresh")
                    WithholdObserverAck(run, role); },
                () => order.Add("properties"),
                () => X360QualificationProgram.SaveAt(run, root, false), null);
            var saved = X360QualificationProgram.ReadAt(Guid.ParseExact(run.Run, "N"), root);
            Check(!complete && order.SequenceEqual(new[] { "target", "parent-pre",
                "parent-fresh", "child", "properties" }) &&
                saved.ObserverTeardown.Select(x => x.Status).SequenceEqual(new[] {
                    "Exited", "Incomplete", "Exited" }) &&
                saved.TargetCleanup == "Removed" && saved.PropertyCleanup == "Restored" &&
                saved.Observations.Count == 1 && saved.Observations[0].SequenceSeen &&
                saved.Error.Contains("observer parent-fresh") && !saved.Error.Contains("properties:"),
                "withheld observer ACK is bounded/incomplete while other observers and exact recovery finish");
            Reject(() => X360QualificationProgram.SaveAt(new X360RunRecord {
                Run = run.Run, Pipe = run.Pipe, OwnerSid = run.OwnerSid,
                FeederImageSha256 = run.FeederImageSha256, FeederPid = run.FeederPid,
                FeederStartTicks = run.FeederStartTicks, ParentSession = run.ParentSession,
                ParentLogon = run.ParentLogon, ChildSession = run.ChildSession,
                ChildLogon = run.ChildLogon, Serial = run.Serial, Slot = run.Slot,
                ObserverTeardown = new List<X360ObserverTeardownRecord> {
                    new X360ObserverTeardownRecord { Role = "child", Status = "Exited" } }
            }, root, false), "wrong-order observer teardown cannot replace exact record");

            run = new X360RunRecord { Run = Guid.NewGuid().ToString("N"),
                OwnerSid = "synthetic-owner", FeederImageSha256 = "synthetic-executable",
                FeederPid = 42, FeederStartTicks = 1000, ParentSession = 1, ParentLogon = 10,
                ChildSession = 2, ChildLogon = 20, Serial = 1, Slot = 1 };
            run.Pipe = "ChildStream-X360-" + run.Run;
            bool propertiesInvoked = false; int observerCalls = 0;
            complete = KitPostChallengeCleanup.Run(run,
                () => { throw new EndOfStreamException("feeder exited before REMOVED"); },
                role => observerCalls++,
                () => propertiesInvoked = true,
                () => X360QualificationProgram.SaveAt(run, root, false), null);
            Check(!complete && run.TargetCleanup == "RemovalFailed" &&
                run.PropertyCleanup == "NotStarted" && observerCalls == 3 &&
                !propertiesInvoked && run.Error.Contains("target:") &&
                !run.Error.Contains("properties:"),
                "feeder loss leaves target uncertain, completes observer shutdown, and defers property writes");
            var world = new World { ProcessOkay = false };
            KitPeerAdmission.RequireCurrent(world, run, false);
            Reject(() => KitPeerAdmission.RequireCurrent(world, run, true),
                "ordinary peer phases still require live exact feeder");
            world.GenerationOkay = false;
            Reject(() => KitPeerAdmission.RequireCurrent(world, run, false),
                "post-removal observer completion still requires exact WTS generations");

            run = new X360RunRecord { Run = Guid.NewGuid().ToString("N"),
                OwnerSid = "synthetic-owner", FeederImageSha256 = "synthetic-executable",
                FeederPid = 42, FeederStartTicks = 1000, ParentSession = 1, ParentLogon = 10,
                ChildSession = 2, ChildLogon = 20, Serial = 1, Slot = 1 };
            run.Pipe = "ChildStream-X360-" + run.Run;
            complete = KitPostChallengeCleanup.Run(run, () => { }, role => { },
                () => { throw new InvalidOperationException("exact property readback failed"); },
                () => X360QualificationProgram.SaveAt(run, root, false), null);
            Check(!complete && run.TargetCleanup == "Removed" &&
                run.ObserverTeardown.All(x => x.Status == "Exited") &&
                run.PropertyCleanup == "RecoveryFailed" && run.Error.Contains("properties:") &&
                !run.Error.Contains("observer "),
                "property restoration failure remains distinct from feeder and observer completion");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
    private static void NegativeFinalizationRegressions()
    {
        string id = Guid.NewGuid().ToString("N");
        var run = new X360RunRecord { Run = id, Pipe = "ChildStream-X360-" + id,
            OwnerSid = "synthetic-owner", FeederImageSha256 = "synthetic-executable", Slot = 1,
            FeederPid = 42, FeederStartTicks = 1000, ParentSession = 1, ParentLogon = 10,
            ChildSession = 2, ChildLogon = 20, Serial = 1 };
        var child = WindowRecord(id, "child", 1,
            new long[] { 1000, 1050, 1100, 1150 },
            new ushort[] { 0x1000, 0x2000, 0x1000, 0 }, new uint[4], false);
        var parent = WindowRecord(id, "parent-pre", 1,
            new long[] { 1000, 1050, 1100, 1150 }, new ushort[4],
            new uint[] { 1167, 1167, 1167, 1167 }, false);
        var fresh = WindowRecord(id, "parent-fresh", 1,
            new long[] { 1000, 1050, 1100, 1150 }, new ushort[4],
            new uint[] { 1167, 1167, 1167, 1167 }, false);
        run.Observations = new List<X360ObservationRecord> { parent, fresh, child };
        Check(KitObservationFinalization.Classify(run, true).Verdict == KitVerdict.SyntheticPass &&
            KitObservationFinalization.Classify(run, false).Verdict == KitVerdict.Inconclusive,
            "parent not-connected plus positive child is scoped, never universal or self-attributed");
        child.Slot = 2;
        Reject(() => KitObserverAdmission.RequireFinal(child, id, "child", 1, 2000),
            "wrong target slot finalization rejected");
        Check(KitObservationFinalization.Classify(run, true).Verdict == KitVerdict.Inconclusive,
            "wrong target cannot manufacture success");
        child.Slot = 1;
        child.SequenceSeen = false; child.ConnectedDuringChallenge = false;
        Check(KitObservationFinalization.Classify(run, true).Verdict == KitVerdict.Inconclusive,
            "missing child reception remains inconclusive");
        child.SequenceSeen = true; child.ConnectedDuringChallenge = true;
        child.Complete = false;
        Check(KitObservationFinalization.Classify(run, true).Verdict == KitVerdict.Inconclusive,
            "challenge-window gap remains inconclusive");
        child.Complete = true;
        var parentReport = WindowRecord(id, "parent-pre", 1,
            new long[] { 1000, 1050, 1100, 1150 },
            new ushort[] { 0x1000, 0x2000, 0x1000, 0 }, new uint[4], true);
        run.Observations[0] = parentReport;
        Check(parentReport.SequenceSeen && !parentReport.Complete &&
            KitObservationFinalization.Classify(run, true).Verdict == KitVerdict.Fail,
            "confirmed parent report survives later gap and expected teardown disappearance");
        bool failedObserver = false;
        try
        {
            KitObservationFinalization.Collect(run, (role, command) => {
                if (role == "child") throw new InvalidOperationException("observer exited");
                return new JavaScriptSerializer().Serialize(role == "parent-pre" ? parentReport : fresh);
            }, new JavaScriptSerializer(), () => 2000);
        }
        catch (InvalidOperationException) { failedObserver = true; }
        Check(failedObserver, "failed required observer prevents completed finalization");
        string incompleteRoot = Path.Combine(Environment.CurrentDirectory, "tests", ".artifacts",
            "x360-qualification", "selftest-incomplete-" + Guid.NewGuid().ToString("N"));
        try
        {
            run.Observations = new List<X360ObservationRecord>();
            X360QualificationProgram.SaveAt(run, incompleteRoot, false);
            failedObserver = false;
            try
            {
                KitObservationFinalization.Collect(run, (role, command) => {
                    if (role == "child") throw new InvalidOperationException("observer exited");
                    return new JavaScriptSerializer().Serialize(role == "parent-pre" ? parentReport : fresh);
                }, new JavaScriptSerializer(), () => 2000,
                record => { run.Observations.Add(record);
                    X360QualificationProgram.SaveAt(run, incompleteRoot, false); });
            }
            catch (InvalidOperationException) { failedObserver = true; }
            var incomplete = X360QualificationProgram.ReadAt(Guid.ParseExact(id, "N"), incompleteRoot);
            Check(failedObserver && incomplete.Observations.Count == 2 &&
                incomplete.Observations[0].SequenceSeen &&
                KitObservationFinalization.Classify(incomplete, true).Verdict == KitVerdict.Fail &&
                KitObservationFinalization.Classify(incomplete, false).Verdict == KitVerdict.Inconclusive,
                "failed later observer retains attributable parent failure evidence without an unverified-slot pass");
            incomplete.Observations[0].Run = "different-run";
            Reject(() => X360QualificationProgram.SaveAt(incomplete, incompleteRoot, false),
                "wrong-run diagnostic observation cannot replace persisted evidence");
        }
        finally { if (Directory.Exists(incompleteRoot)) Directory.Delete(incompleteRoot, true); }
        Reject(() => KitObserverAdmission.RequireLive(false, true, true), "exited observer rejected before arm");
        Reject(() => KitObserverAdmission.RequireLive(true, false, true), "stale observer PID rejected before arm");
        Reject(() => KitObserverAdmission.RequireLive(true, true, false), "stale observer generation rejected before arm");
        Reject(() => KitObserverAdmission.RequireArm(null, id, "child", 1, 1100, 1000),
            "missing child arm sample blocks reports");
        var bad = new X360ObserverReadyRecord { Run = id, Role = "child", Slot = 1,
            FirstTick = 1000, SecondTick = 1050, FirstError = 1167, SecondError = 1167 };
        Reject(() => KitObserverAdmission.RequireReady(bad, id, "child", 1, 1100, 1000),
            "not-connected child cannot arm on process presence alone");
        var deadlineTarget = new Target(); deadlineTarget.CreateNeutral();
        using (var neverArmed = new ObserverFixture(run, "parent-fresh", new TargetReader
            { Target = deadlineTarget, ParentDisconnected = true }, 1))
        {
            KitObserverAdmission.RequireReady(new JavaScriptSerializer().Deserialize<X360ObserverReadyRecord>(
                neverArmed.Read()), id, "parent-fresh", 1, Stopwatch.GetTimestamp(), Stopwatch.Frequency);
            bool expired = false;
            try { neverArmed.Result.Wait(TimeSpan.FromSeconds(3)); }
            catch (AggregateException e)
            { expired = e.InnerException is InvalidOperationException; }
            Check(expired && deadlineTarget.Reports.Count == 0,
                "missing phase command reaches bounded observer deadline with zero reports");
        }
        deadlineTarget.Remove();

        Target target; World world; var qualification = New(out target, out world);
        world.After = world.Before; qualification.Create();
        world.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        qualification.Assign(); qualification.Arm(qualification.Identity.Run);
        using (var cancel = new CancellationTokenSource())
        {
            var clock = SampleClock(target); clock.CancelAfterFirstStep = cancel;
            try { qualification.Pulse(clock, cancel.Token); } catch (OperationCanceledException) { }
        }
        var partial = qualification.Phases.Select(p => new X360PhaseRecord { Buttons = p.Buttons,
            StartTick = p.StartTick, EndTick = p.EndTick, ActualEndTick = p.ActualEndTick,
            Completed = p.Completed }).ToList();
        qualification.Stop();
        Check(partial.Count == 1 && !partial[0].Completed && partial[0].ActualEndTick < partial[0].EndTick,
            "cancellation preserves partial monotonic phase boundary");
        string temporary = Path.Combine(Environment.CurrentDirectory, "tests", ".artifacts",
            "x360-qualification", "selftest-partial-" + Guid.NewGuid().ToString("N"));
        try
        {
            run.Run = qualification.Identity.Run.ToString("N"); run.Pipe = "ChildStream-X360-" + run.Run;
            run.Observations.Clear(); run.Phases = partial; run.TargetCleanup = "Removed";
            X360QualificationProgram.SaveAt(run, temporary, false);
            var stale = X360QualificationProgram.ReadAt(qualification.Identity.Run, temporary);
            stale.Phases = new List<X360PhaseRecord>(); stale.PropertyCleanup = "RecoveryFailed";
            X360QualificationProgram.SaveAt(stale, temporary, false);
            var saved = X360QualificationProgram.ReadAt(qualification.Identity.Run, temporary);
            Check(saved.Phases.Count == 1 && !saved.Phases[0].Completed &&
                saved.TargetCleanup == "Removed" && saved.PropertyCleanup == "RecoveryFailed",
                "partial feeder timeline and distinct property recovery status survive stale helper save");
            var conflict = X360QualificationProgram.ReadAt(qualification.Identity.Run, temporary);
            conflict.Phases[0].Buttons = 0x2000;
            Reject(() => X360QualificationProgram.SaveAt(conflict, temporary, false),
                "conflicting phase evidence rejected");
        }
        finally { if (Directory.Exists(temporary)) Directory.Delete(temporary, true); }
    }
    internal static int Run()
    {
        Target t; World w; var q = New(out t, out w);
        // The fake inventory returns After at creation, but the core's before
        // capture must be independently controlled by the fake in this test.
        w.After = w.Before; q.Create();
        Check(t.Creates == 1 && t.Reports.Count == 0, "creation must hold reports");
        Reject(() => q.Pulse(SampleClock(t), CancellationToken.None), "no assignment must mean zero reports");
        w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        var nodes = q.Assign();
        Check(nodes.Length == 1 && nodes[0] == Node && w.Writes == 1, "exact node assigned");
        Reject(() => q.Pulse(SampleClock(t), CancellationToken.None), "no explicit arm must mean zero reports");
        Reject(() => q.Arm(Guid.NewGuid()), "wrong run arm rejected");
        var clock = SampleClock(t);
        q.Arm(q.Identity.Run); q.Pulse(clock, CancellationToken.None);
        Check(t.Reports.SequenceEqual(new ushort[] { 0x1000, 0x2000, 0x1000, 0 }), "bounded reports only");
        Check(clock.Sampler.SequenceSeen && q.Phases.Count == 4 &&
            q.Phases.All(p => p.EndTick - p.StartTick == 400), "sampled timed challenge including neutral dwell");
        q.ReconnectSameTarget();
        Check(t.Creates == 1 && t.Reports.Count == 4, "same target reconnect does not duplicate or pulse");
        Reject(() => q.Pulse(SampleClock(t), CancellationToken.None), "cannot replay the same challenge");
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
        q.Assign(); q.Arm(q.Identity.Run);
        clock = SampleClock(t); clock.StartSamplingAt = 1500; q.Pulse(clock, CancellationToken.None);
        Check(!clock.Sampler.SequenceSeen, "late observer misses first challenge phase"); q.Stop();

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        q.Assign(); q.Arm(q.Identity.Run);
        clock = SampleClock(t); clock.SampleEvery = 4; q.Pulse(clock, CancellationToken.None);
        Check(!clock.Sampler.Complete,
            "200 ms skipped sampling is inconclusive even if values recur"); q.Stop();
        var parentEvidence = new KitSequenceSampler();
        parentEvidence.Sample(1000, 0x1000, 0, 1000);
        parentEvidence.Sample(1050, 0x2000, 0, 1000);
        parentEvidence.Sample(1100, 0x1000, 0, 1000);
        parentEvidence.Sample(1150, 0, 0, 1000);
        parentEvidence.Sample(1400, 0, 0, 1000);
        Check(parentEvidence.SequenceSeen && !parentEvidence.Complete,
            "later coverage loss cannot erase observed parent report sequence");

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        q.Assign(); q.Arm(q.Identity.Run);
        using (var cancel = new CancellationTokenSource())
        {
            clock = SampleClock(t); clock.CancelAfterFirstStep = cancel;
            bool cancelled = false;
            try { q.Pulse(clock, cancel.Token); } catch (OperationCanceledException) { cancelled = true; }
            Check(cancelled && t.Reports.Count == 1 && q.Evaluate(null, null, null).Verdict == KitVerdict.Inconclusive,
                "cancelled challenge remains partial and inconclusive");
        }
        q.Stop();

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        q.Assign(); q.Arm(q.Identity.Run);
        clock = SampleClock(t); clock.Overshoot = true;
        bool timedOut = false;
        try { q.Pulse(clock, CancellationToken.None); } catch (TimeoutException) { timedOut = true; }
        Check(timedOut && t.Reports.Count == 1, "late phase deadline aborts after bounded first report"); q.Stop();

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

        var import = (DllImportAttribute)typeof(WindowsKitWorld).GetMethod("SetupDiGetDeviceRegistryProperty",
            BindingFlags.Static | BindingFlags.NonPublic).GetCustomAttributes(typeof(DllImportAttribute), false)[0];
        Check(import.EntryPoint == "SetupDiGetDeviceRegistryPropertyW" && import.CharSet == CharSet.Unicode &&
            import.ExactSpelling && import.SetLastError, "declared registry import is exact Unicode W ABI");
        byte[] sz = NativeBytes("ViGEmBus"), multi = NativeBytes("USB\\VID_045E&PID_028E", "USB\\Class_FF");
        Check(WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 1, sz, (uint)sz.Length).Single() == "ViGEmBus",
            "native REG_SZ service decoded");
        Check(WindowsKitWorld.DecodeRegistryStrings(1, true, 0, 7, multi, (uint)multi.Length).Length == 2,
            "native REG_MULTI_SZ hardware IDs decoded");
        Check(KitAttribution.Resolve(new[] { Root(), NativeBus() },
            new[] { Root(), NativeBus(), NativePad() }, 1).Single() == Node,
            "native-shaped Unicode registry bytes reach exact target attribution");
        Reject(() => WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 7, sz, (uint)sz.Length), "wrong REG type rejected");
        Reject(() => WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 1, sz, (uint)sz.Length - 1), "odd length rejected");
        Reject(() => WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 1, sz, 2), "insufficient data rejected");
        Reject(() => WindowsKitWorld.DecodeRegistryStrings(4, true, 0, 1, sz, (uint)sz.Length + 2), "oversize rejected");
        Reject(() => WindowsKitWorld.DecodeRegistryStrings(1, true, 0, 7, multi, (uint)multi.Length - 2), "missing double terminator rejected");
        Check(RejectAny(() => WindowsKitWorld.DecodeRegistryStrings(4, false, 13, 1, sz, (uint)sz.Length)),
            "failed native registry read rejected, not absent");

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        var run = new X360RunRecord { Run = q.Identity.Run.ToString("N"), OwnerSid = "owner", FeederPid = 42,
            FeederStartTicks = 1000, ParentSession = 1, ChildSession = 2, FeederImageSha256 = "attacker" };
        var peer = new KitPeerSnapshot { Pid = 42, StartTicks = 1000, ProcessSession = 2, TokenSession = 2,
            Sid = "owner", ImageSha256 = "attacker", Elevated = false };
        Reject(() => KitPeerAdmission.Require(peer, run, "independent-kit", KitPeerRole.Feeder),
            "record and peer agreement on wrong image cannot admit writes");
        Check(w.Writes == 0 && t.Reports.Count == 0, "forged record has zero writes/reports");
        run.FeederImageSha256 = "independent-kit"; peer.ImageSha256 = "independent-kit";
        peer.Elevated = true;
        Reject(() => KitPeerAdmission.Require(peer, run, "independent-kit", KitPeerRole.Feeder), "wrong feeder role rejected");
        peer.Elevated = false; peer.TokenSession = 1;
        Reject(() => KitPeerAdmission.Require(peer, run, "independent-kit", KitPeerRole.Feeder), "wrong token session rejected");
        peer.TokenSession = 2; peer.StartTicks++;
        Reject(() => KitPeerAdmission.Require(peer, run, "independent-kit", KitPeerRole.Feeder), "stale feeder process rejected");
        Check(w.Writes == 0 && t.Reports.Count == 0, "all peer denials precede effects"); q.Stop();

        using (var server = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None))
        using (var client = new AnonymousPipeClientStream(PipeDirection.In, server.ClientSafePipeHandle))
        {
            using (var writer = new BinaryWriter(server, Encoding.UTF8, true))
            using (var reader = new BinaryReader(client, Encoding.UTF8, true))
            {
                var json = new JavaScriptSerializer();
                var ready = new X360ObserverReadyRecord { Run = "run", Role = "parent-pre", Slot = 1,
                    FirstTick = 1000, SecondTick = 1050, FirstError = 1167, SecondError = 1167 };
                X360QualificationProgram.Send(writer, json.Serialize(ready));
                KitObserverAdmission.RequireReady(json.Deserialize<X360ObserverReadyRecord>(
                    X360QualificationProgram.Receive(reader)), "run", "parent-pre", 1, 1100, 1000);
                Check(true, "real harmless pipe carried bounded two-sample readiness");
            }
        }
        var badReady = new X360ObserverReadyRecord { Run = "other", Role = "parent-pre", Slot = 1,
            FirstTick = 1000, SecondTick = 1050, FirstError = 0, SecondError = 0 };
        Reject(() => KitObserverAdmission.RequireReady(badReady, "run", "parent-pre", 1, 1100, 1000),
            "wrong run readiness rejected");
        badReady.Run = "run"; badReady.Role = "child";
        Reject(() => KitObserverAdmission.RequireReady(badReady, "run", "parent-pre", 1, 1100, 1000),
            "wrong role readiness rejected");
        badReady.Role = "parent-pre";
        Reject(() => KitObserverAdmission.RequireReady(badReady, "run", "parent-pre", 1, 2500, 1000),
            "late observer readiness rejected");

        q = New(out t, out w); w.After = w.Before; q.Create(); w.After = new[] { Root(), BusNode(), Pad(Node, Bus) };
        q.AcceptExternalAssignment(new[] { Node }, q.Identity.Run);
        Reject(() => q.PulseAfterExternalArm(q.Identity.Run, true, SampleClock(t), CancellationToken.None), "feeder rejects missing property readback");
        Check(t.Reports.Count == 0, "missing external assignment gives zero reports");
        w.Properties[Node] = new DeviceProperty { Kind = PropertyKind.UInt32, Value = 2 };
        Reject(() => q.PulseAfterExternalArm(q.Identity.Run, false, SampleClock(t), CancellationToken.None), "unready observers hold reports");
        q.PulseAfterExternalArm(q.Identity.Run, true, SampleClock(t), CancellationToken.None);
        Check(t.Reports.SequenceEqual(new ushort[] { 0x1000, 0x2000, 0x1000, 0 }),
            "exact external assignment releases only bounded pulse");
        q.Stop();
        ConnectedFinalizationRegression();
        PostChallengeCleanupRegressions();
        NegativeFinalizationRegressions();
        Console.WriteLine("REVIEW-ONLY SYNTHETIC X360 qualification assertions passed: " + checks);
        return checks;
    }
    private static bool RejectAny(Action action)
    { try { action(); return false; } catch (System.ComponentModel.Win32Exception) { return true; } }
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test") { Run(); return 0; }
        Console.WriteLine("REVIEW-ONLY QUALIFICATION KIT — LIVE EXECUTION NOT AUTHORIZED");
        Console.WriteLine("--self-test runs substituted effects only. Default and --help touch no Windows device or session API.");
        return args.Length == 0 || (args.Length == 1 && args[0] == "--help") ? 0 : 2;
    }
}
