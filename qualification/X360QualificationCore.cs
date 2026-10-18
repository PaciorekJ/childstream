using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

// Review-only qualification logic. No production assembly references this file.
internal enum KitVerdict { SyntheticPass, Fail, Inconclusive }
internal enum PropertyKind { Absent, UInt32, WrongType, ReadError }
internal sealed class DeviceProperty
{
    internal PropertyKind Kind;
    internal uint Value;
    internal int NativeError;
}
internal sealed class KitIdentity
{
    internal Guid Run;
    internal int FeederPid;
    internal long FeederStartTicks;
    internal int ParentSession, ChildSession;
    internal long ParentLogon, ChildLogon;
    internal uint Serial;
    internal string TargetInstance;
}
internal sealed class KitNode
{
    internal string Id, Parent, Service;
    internal string[] HardwareIds;
    internal bool Present;
}
internal sealed class KitObservation
{
    internal bool Complete, TargetAttributed, SequenceSeen, TranslatedAction;
    internal string Error;
}
internal sealed class KitResult
{
    internal KitVerdict Verdict;
    internal string Reason;
    internal static KitResult Inconclusive(string reason)
    { return new KitResult { Verdict = KitVerdict.Inconclusive, Reason = reason }; }
}
internal interface IKitTarget
{
    uint CreateNeutral();
    void Submit(ushort buttons);
    void Remove();
    bool Attached { get; }
}
internal interface IKitWorld
{
    KitNode[] Nodes();
    DeviceProperty ReadProperty(string instance);
    void SetProperty(string instance, uint value);
    bool ProcessMatches(int pid, long startTicks);
    bool GenerationMatches(int session, long logon);
}

internal interface IKitClock
{
    long Ticks { get; }
    long Frequency { get; }
    void WaitUntil(long tick, CancellationToken cancellation);
}
internal sealed class MonotonicKitClock : IKitClock
{
    public long Ticks { get { return Stopwatch.GetTimestamp(); } }
    public long Frequency { get { return Stopwatch.Frequency; } }
    public void WaitUntil(long tick, CancellationToken cancellation)
    {
        while (Ticks < tick)
        {
            cancellation.ThrowIfCancellationRequested();
            Thread.Sleep(5);
        }
    }
}
internal sealed class KitChallengePhase
{
    internal ushort Buttons;
    internal long StartTick, EndTick;
}
internal sealed class KitSequenceSampler
{
    private static readonly ushort[] Expected = { 0x1000, 0x2000, 0x1000, 0 };
    private int next;
    private long previous = -1;
    internal bool Complete { get; private set; }
    internal KitSequenceSampler() { Complete = true; }
    internal bool SequenceSeen { get { return Complete && next == Expected.Length; } }
    internal void Sample(long tick, ushort buttons, uint error, long frequency)
    {
        if (frequency <= 0 || tick < 0 || (previous >= 0 &&
            (tick <= previous || tick - previous > frequency * 150 / 1000))) Complete = false;
        previous = tick;
        if (error != 0) { Complete = false; return; }
        if (next < Expected.Length && buttons == Expected[next]) next++;
        else if (next > 0 && buttons != Expected[next - 1]) Complete = false;
    }
}

internal static class KitAttribution
{
    internal static string[] Resolve(KitNode[] before, KitNode[] after, uint serial)
    {
        if (before == null || after == null || serial == 0 || serial > 255)
            throw new InvalidOperationException("Incomplete target attribution.");
        var old = new HashSet<string>(before.Where(n => n.Present).Select(n => n.Id), StringComparer.OrdinalIgnoreCase);
        var present = after.Where(n => n.Present && !String.IsNullOrWhiteSpace(n.Id)).ToArray();
        if (present.Select(n => n.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != present.Length)
            throw new InvalidOperationException("Duplicate PnP identity.");
        // The pinned ViGEmClient returns a bus serial. The source driver formats its
        // target PDO instance component as two decimal digits; the full PnP graph
        // and bus service must corroborate it. VID/PID or serial alone never suffice.
        string suffix = "\\" + serial.ToString("D2");
        var candidates = present.Where(n => !old.Contains(n.Id) &&
            n.Id.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) &&
            n.HardwareIds != null && n.HardwareIds.Any(h =>
                h.StartsWith("USB\\VID_045E&PID_028E", StringComparison.OrdinalIgnoreCase))).ToArray();
        if (candidates.Length != 1) throw new InvalidOperationException("X360 target is not uniquely new and attributed.");
        var byId = present.ToDictionary(n => n.Id, StringComparer.OrdinalIgnoreCase);
        var target = candidates[0];
        string parent = target.Parent;
        bool bus = false;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!String.IsNullOrEmpty(parent) && visited.Add(parent))
        {
            KitNode node;
            if (!byId.TryGetValue(parent, out node)) break;
            if (String.Equals(node.Service, "ViGEmBus", StringComparison.OrdinalIgnoreCase) &&
                node.HardwareIds != null && node.HardwareIds.Any(h =>
                    String.Equals(h, "Nefarius\\ViGEmBus\\Gen1", StringComparison.OrdinalIgnoreCase)))
            { bus = true; break; }
            parent = node.Parent;
        }
        if (!bus) throw new InvalidOperationException("Target has no verified ViGEmBus ancestor.");
        // Associate the exact PDO and every present descendant. The current X360
        // graph must be recorded; a new or ambiguous descendant is a stop, not an
        // implicit claim that the parent property covers it.
        var result = new List<string> { target.Id };
        var queue = new Queue<string>(); queue.Enqueue(target.Id);
        while (queue.Count > 0)
        {
            string p = queue.Dequeue();
            foreach (var child in present.Where(n => String.Equals(n.Parent, p, StringComparison.OrdinalIgnoreCase)))
            {
                if (!result.Contains(child.Id, StringComparer.OrdinalIgnoreCase))
                { result.Add(child.Id); queue.Enqueue(child.Id); }
            }
        }
        if (result.Count > 8) throw new InvalidOperationException("Unexpectedly broad target subtree.");
        return result.ToArray();
    }
}

internal sealed class X360Qualification
{
    private readonly IKitTarget target;
    private readonly IKitWorld world;
    private KitNode[] before;
    private string[] nodes;
    private bool created, assigned, armed, stopped;
    internal readonly KitIdentity Identity;
    internal readonly Dictionary<string, DeviceProperty> Prior = new Dictionary<string, DeviceProperty>(StringComparer.OrdinalIgnoreCase);
    internal int SubmittedCount { get; private set; }
    internal readonly List<KitChallengePhase> Phases = new List<KitChallengePhase>();
    internal KitNode[] BeforeSnapshot { get { return before; } }
    internal X360Qualification(IKitTarget target, IKitWorld world, KitIdentity identity)
    { this.target = target; this.world = world; Identity = identity; }
    internal void Create()
    {
        if (created || stopped) throw new InvalidOperationException("Run already used.");
        CheckIdentity();
        before = world.Nodes();
        Identity.Serial = target.CreateNeutral();
        created = true;
        if (!target.Attached || Identity.Serial == 0) throw new InvalidOperationException("Neutral target creation failed.");
    }
    // The elevated one-shot tool imports only a live feeder's bounded PnP
    // baseline, corroborated by the named-pipe server PID and start time.
    internal void BeginExisting(KitNode[] baseline, uint serial)
    {
        if (created || stopped || !target.Attached || baseline == null || serial == 0)
            throw new InvalidOperationException("Existing feeder state invalid.");
        CheckIdentity(); before = baseline; Identity.Serial = serial; created = true;
    }
    internal string[] Assign(Action<string, DeviceProperty> beforeWrite = null)
    {
        if (!created || assigned || stopped || armed) throw new InvalidOperationException("Assignment state invalid.");
        CheckIdentity();
        nodes = KitAttribution.Resolve(before, world.Nodes(), Identity.Serial);
        Identity.TargetInstance = nodes[0];
        foreach (string node in nodes)
        {
            DeviceProperty p = world.ReadProperty(node);
            if (p == null || p.Kind == PropertyKind.ReadError || p.Kind == PropertyKind.WrongType ||
                (p.Kind == PropertyKind.UInt32 && p.Value != Identity.ChildSession))
                throw new InvalidOperationException("Original device-session property conflicts or is unreadable.");
            Prior[node] = p;
        }
        foreach (string node in nodes)
        {
            CheckIdentity();
            if (beforeWrite != null) beforeWrite(node, Prior[node]);
            world.SetProperty(node, (uint)Identity.ChildSession);
            DeviceProperty readback = world.ReadProperty(node);
            if (readback == null || readback.Kind != PropertyKind.UInt32 || readback.Value != Identity.ChildSession)
                throw new InvalidOperationException("Assignment readback failed; report gate remains held.");
        }
        assigned = true;
        return nodes;
    }
    internal void Arm(Guid exactRun)
    {
        if (!assigned || stopped || armed || exactRun != Identity.Run || nodes == null)
            throw new InvalidOperationException("Explicit arm requires the exact admitted run.");
        CheckIdentity();
        var current = KitAttribution.Resolve(before, world.Nodes(), Identity.Serial);
        if (!nodes.SequenceEqual(current, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Target graph drifted before arming.");
        foreach (string node in nodes)
        {
            DeviceProperty p = world.ReadProperty(node);
            if (p == null || p.Kind != PropertyKind.UInt32 || p.Value != Identity.ChildSession)
                throw new InvalidOperationException("Assignment drifted before arming.");
        }
        armed = true;
    }
    // Feeder side of an authenticated, live one-shot helper channel. The helper
    // itself performs exact SetupAPI readback immediately before sending ARM.
    // This is a proposed experiment handshake, not enforcement proof.
    internal void AcceptExternalAssignment(string[] verifiedNodes, Guid exactRun)
    {
        if (!created || assigned || stopped || exactRun != Identity.Run || verifiedNodes == null)
            throw new InvalidOperationException("Assignment acknowledgment invalid.");
        CheckIdentity();
        var graph = KitAttribution.Resolve(before, world.Nodes(), Identity.Serial);
        if (!graph.SequenceEqual(verifiedNodes, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Assignment node graph disagrees with feeder.");
        nodes = graph; Identity.TargetInstance = graph[0]; assigned = true;
    }
    internal void PulseAfterExternalArm(Guid exactRun, bool observersReady, IKitClock clock, CancellationToken cancellation)
    {
        if (!assigned || stopped || armed || exactRun != Identity.Run || !observersReady)
            throw new InvalidOperationException("One-shot arm invalid.");
        CheckIdentity();
        var graph = KitAttribution.Resolve(before, world.Nodes(), Identity.Serial);
        if (!nodes.SequenceEqual(graph, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Target changed after assignment.");
        foreach (string node in nodes)
        {
            DeviceProperty p = world.ReadProperty(node);
            if (p == null || p.Kind != PropertyKind.UInt32 || p.Value != Identity.ChildSession)
                throw new InvalidOperationException("Assignment changed before feeder report release.");
        }
        armed = true; Pulse(clock, cancellation);
    }
    internal void Pulse(IKitClock clock, CancellationToken cancellation)
    {
        if (!armed || stopped || SubmittedCount != 0 || clock == null || clock.Frequency <= 0)
            throw new InvalidOperationException("Reports are held.");
        CheckIdentity();
        // Eight 50 ms observer opportunities per state, including final neutral.
        // A late wakeup fails the experiment; it never substitutes success.
        long start = clock.Ticks;
        long dwell = checked(clock.Frequency * 400 / 1000);
        long tolerance = checked(clock.Frequency * 150 / 1000);
        if (dwell <= 0) throw new InvalidOperationException("Clock resolution is insufficient.");
        foreach (ushort buttons in new ushort[] { 0x1000, 0x2000, 0x1000, 0 })
        {
            cancellation.ThrowIfCancellationRequested();
            CheckIdentity();
            long phaseStart = clock.Ticks;
            long priorEnd = SubmittedCount == 0 ? start : Phases[Phases.Count - 1].EndTick;
            if (phaseStart > checked(priorEnd + tolerance))
                throw new TimeoutException("Challenge phase began too late for complete observation.");
            target.Submit(buttons); SubmittedCount++;
            long end = checked(phaseStart + dwell);
            var phase = new KitChallengePhase { Buttons = buttons, StartTick = phaseStart, EndTick = end };
            Phases.Add(phase);
            clock.WaitUntil(end, cancellation);
            if (clock.Ticks > end + tolerance)
                throw new TimeoutException("Challenge sampling window exceeded deadline.");
        }
    }
    internal void ReconnectSameTarget()
    {
        if (!assigned || stopped || !target.Attached) throw new InvalidOperationException("Target was not retained.");
        CheckIdentity();
        if (KitAttribution.Resolve(before, world.Nodes(), Identity.Serial)[0] != Identity.TargetInstance)
            throw new InvalidOperationException("Reconnect target changed.");
    }
    internal KitResult Evaluate(KitObservation child, KitObservation oldParent, KitObservation newParent)
    {
        if (child == null || oldParent == null || newParent == null || SubmittedCount != 4)
            return KitResult.Inconclusive("Challenge or observation incomplete.");
        if (oldParent.TranslatedAction || newParent.TranslatedAction || oldParent.SequenceSeen || newParent.SequenceSeen)
            return new KitResult { Verdict = KitVerdict.Fail, Reason = "Parent received a report or translated action." };
        if (!child.Complete || !oldParent.Complete || !newParent.Complete ||
            !child.TargetAttributed || !child.SequenceSeen || !oldParent.TargetAttributed || !newParent.TargetAttributed ||
            !String.IsNullOrEmpty(child.Error) || !String.IsNullOrEmpty(oldParent.Error) || !String.IsNullOrEmpty(newParent.Error))
            return KitResult.Inconclusive("Positive child or required parent coverage missing.");
        return new KitResult { Verdict = KitVerdict.SyntheticPass, Reason = "Modeled XInput observations only; no physical enforcement claim." };
    }
    internal void Stop()
    {
        armed = false; stopped = true;
        if (created && target.Attached) target.Remove();
        // Never clear a property here. A separate, exact-owned recovery step may
        // restore it only after the target is absent and identity is rechecked.
    }
    private void CheckIdentity()
    {
        if (Identity.Run == Guid.Empty || Identity.FeederPid <= 0 || Identity.FeederStartTicks <= 0 ||
            Identity.ParentSession <= 0 || Identity.ChildSession <= 0 ||
            Identity.ParentSession == Identity.ChildSession || Identity.ParentLogon <= 0 || Identity.ChildLogon <= 0 ||
            !world.ProcessMatches(Identity.FeederPid, Identity.FeederStartTicks) ||
            !world.GenerationMatches(Identity.ParentSession, Identity.ParentLogon) ||
            !world.GenerationMatches(Identity.ChildSession, Identity.ChildLogon))
            throw new InvalidOperationException("Feeder or session generation changed.");
    }
}
