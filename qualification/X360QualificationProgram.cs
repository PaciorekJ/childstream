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
using System.Threading.Tasks;
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
    public string TargetCleanup = "Present"; // feeder-owned
    public string PropertyCleanup = "NotStarted"; // helper-owned
    public List<X360ObserverTeardownRecord> ObserverTeardown = new List<X360ObserverTeardownRecord>(); // helper-owned
    public string[] Nodes;
    public List<X360PhaseRecord> Phases = new List<X360PhaseRecord>();
    public List<X360ObservationRecord> Observations = new List<X360ObservationRecord>();
    public List<X360PriorRecord> Prior = new List<X360PriorRecord>();
    public string Error;
}
internal sealed class X360PhaseRecord
{
    public ushort Buttons;
    public long StartTick, EndTick, ActualEndTick;
    public bool Completed;
}
internal sealed class X360PhaseEnvelope
{
    public string Run;
    public List<X360PhaseRecord> Phases;
}
internal sealed class X360ObservationRecord
{
    public string Run, Role;
    public uint Slot;
    public long ChallengeStart, ChallengeEnd;
    public int ChallengeSamples, NotConnected, OtherErrors;
    public bool Complete, SequenceSeen, ConnectedDuringChallenge;
    public string Attribution = "PinnedClientSlotOnly";
}
internal sealed class X360ObserverTeardownRecord
{
    public string Role, Status, Error;
}
internal sealed class X360ObserverReadyRecord
{
    public string Run, Role;
    public uint Slot, FirstError, SecondError;
    public long FirstTick, SecondTick;
}
internal sealed class X360ObserverArmRecord
{
    public string Run, Role;
    public uint Slot, Error;
    public long Tick;
}
internal sealed class X360ObserverOutcome
{
    internal X360ObservationRecord Challenge;
    internal int TeardownNotConnected, TeardownOtherErrors;
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
    internal static void RequireCurrent(IKitWorld world, X360RunRecord run, bool requireFeederLive)
    {
        if (world == null || run == null ||
            (requireFeederLive && !world.ProcessMatches(run.FeederPid, run.FeederStartTicks)) ||
            !world.GenerationMatches(run.ParentSession, run.ParentLogon) ||
            !world.GenerationMatches(run.ChildSession, run.ChildLogon))
            throw new InvalidOperationException("Peer WTS generation or required feeder identity changed.");
    }
}
internal static class KitObserverProtocol
{
    internal static string Command(BinaryReader input, BinaryWriter output,
        X360RunRecord run, string role, string command, int timeoutMs, Action abort)
    {
        if (input == null || output == null || run == null || abort == null ||
            timeoutMs < 1 || timeoutMs > 3000)
            throw new InvalidOperationException("Bounded observer command context invalid.");
        X360QualificationProgram.Send(output, command + " " + run.Run + " " + role);
        var response = Task.Factory.StartNew(() => X360QualificationProgram.Receive(input));
        if (!response.Wait(TimeSpan.FromMilliseconds(timeoutMs)))
        { abort(); throw new TimeoutException(role + " did not acknowledge " + command + "."); }
        return response.Result;
    }
}
internal static class KitObserverAdmission
{
    internal static void RequireLive(bool connected, bool processCurrent, bool generationsCurrent)
    {
        if (!connected || !processCurrent || !generationsCurrent)
            throw new InvalidOperationException("Required observer exited or changed identity before arm.");
    }
    internal static void RequireReady(X360ObserverReadyRecord ready, string run, string role,
        uint slot, long receivedTick, long frequency)
    {
        bool child = role == "child";
        if (ready == null || ready.Run != run || ready.Role != role || ready.Slot != slot ||
            ready.FirstTick <= 0 || ready.SecondTick <= ready.FirstTick || frequency <= 0 ||
            ready.SecondTick - ready.FirstTick > frequency * 150 / 1000 ||
            receivedTick < ready.SecondTick || receivedTick - ready.SecondTick > frequency ||
            ready.FirstError != ready.SecondError ||
            (child ? ready.SecondError != 0 : ready.SecondError != 0 && ready.SecondError != 1167))
            throw new InvalidOperationException("Observer lacks two fresh, valid samples for its exact role and slot.");
    }
    internal static void RequireArm(X360ObserverArmRecord arm, string run, string role,
        uint slot, long receivedTick, long frequency)
    {
        if (arm == null || arm.Run != run || arm.Role != role || arm.Slot != slot ||
            arm.Tick <= 0 || receivedTick < arm.Tick || receivedTick - arm.Tick > frequency ||
            (role == "child" ? arm.Error != 0 : arm.Error != 0 && arm.Error != 1167))
            throw new InvalidOperationException("Observer was not sampling the required slot when armed.");
    }
    internal static X360ObservationRecord Finalize(string run, string role, uint slot, KitObserverWindow window)
    {
        if (window == null || window.Phase != KitMeasurementPhase.Finalization)
            throw new InvalidOperationException("Observation was not finalized before target teardown.");
        return new X360ObservationRecord { Run = run, Role = role, Slot = slot,
            ChallengeStart = window.ChallengeStart, ChallengeEnd = window.ChallengeEnd,
            ChallengeSamples = window.Challenge.Samples, NotConnected = window.Challenge.NotConnected,
            OtherErrors = window.Challenge.OtherErrors, Complete = window.Challenge.Complete,
            SequenceSeen = window.Challenge.SequenceSeen,
            ConnectedDuringChallenge = window.ConnectedDuringChallenge };
    }
    internal static void RequireFinal(X360ObservationRecord record, string run, string role, uint slot,
        long receivedTick)
    {
        if (record == null || record.Run != run || record.Role != role || record.Slot != slot ||
            record.Attribution != "PinnedClientSlotOnly" || record.ChallengeStart <= 0 ||
            record.ChallengeEnd <= record.ChallengeStart || record.ChallengeEnd > receivedTick ||
            record.ChallengeSamples <= 0 || record.ChallengeSamples > 200 ||
            record.NotConnected < 0 || record.OtherErrors < 0 ||
            record.NotConnected + record.OtherErrors > record.ChallengeSamples)
            throw new InvalidOperationException("Final observation identity, window, or count invalid.");
    }
}
internal static class KitPhaseAdmission
{
    private static readonly ushort[] Expected = { 0x1000, 0x2000, 0x1000, 0 };
    internal static void Require(X360PhaseEnvelope envelope, string run, long frequency)
    {
        if (envelope == null || envelope.Run != run || envelope.Phases == null ||
            envelope.Phases.Count < 1 || envelope.Phases.Count > 4 || frequency <= 0)
            throw new InvalidOperationException("Challenge timeline has wrong run or count.");
        long prior = -1;
        for (int i = 0; i < envelope.Phases.Count; i++)
        {
            var p = envelope.Phases[i];
            if (p == null || p.Buttons != Expected[i] || p.StartTick <= prior ||
                p.EndTick <= p.StartTick || p.EndTick - p.StartTick != frequency * 400 / 1000 ||
                p.ActualEndTick < p.StartTick || p.ActualEndTick > p.EndTick + frequency * 150 / 1000 ||
                (p.Completed && p.ActualEndTick < p.EndTick) ||
                (!p.Completed && i != envelope.Phases.Count - 1))
                throw new InvalidOperationException("Challenge timeline is incomplete, conflicting, or malformed.");
            prior = p.ActualEndTick;
        }
    }
}
internal static class KitObservationFinalization
{
    internal static List<X360ObservationRecord> Collect(X360RunRecord run,
        Func<string, string, string> command, JavaScriptSerializer json, Func<long> now,
        Action<X360ObservationRecord> afterRecord = null)
    {
        var result = new List<X360ObservationRecord>();
        foreach (string role in new[] { "parent-pre", "parent-fresh", "child" })
        {
            var record = json.Deserialize<X360ObservationRecord>(command(role, "FINALIZE"));
            KitObserverAdmission.RequireFinal(record, run.Run, role, run.Slot, now());
            result.Add(record);
            if (afterRecord != null) afterRecord(record);
        }
        return result;
    }
    internal static KitResult Classify(X360RunRecord run, bool independentlyAttributed)
    {
        if (run == null || run.Observations == null || run.Observations.Count > 3 ||
            run.Observations.Select(o => o == null ? null : o.Role).Distinct().Count() != run.Observations.Count ||
            run.Observations.Any(o => o == null || o.Run != run.Run || o.Slot != run.Slot ||
                o.Attribution != "PinnedClientSlotOnly"))
            return KitResult.Inconclusive("Observer identity or exact slot attribution is incomplete.");
        if (independentlyAttributed && run.Observations.Any(o => o.Role != "child" && o.SequenceSeen))
            return new KitResult { Verdict = KitVerdict.Fail,
                Reason = "Confirmed attributable parent XInput challenge evidence, regardless of later gaps or missing observers." };
        if (run.Observations.Count != 3)
            return KitResult.Inconclusive("Required observer missing.");
        var child = run.Observations.SingleOrDefault(o => o.Role == "child");
        var oldParent = run.Observations.SingleOrDefault(o => o.Role == "parent-pre");
        var freshParent = run.Observations.SingleOrDefault(o => o.Role == "parent-fresh");
        if (child == null || oldParent == null || freshParent == null)
            return KitResult.Inconclusive("Required observer missing.");
        if (!independentlyAttributed)
            return KitResult.Inconclusive("Pinned-client XInput slot lacks independent target attribution; no isolation pass.");
        if (!child.Complete || !child.SequenceSeen || !child.ConnectedDuringChallenge ||
            !oldParent.Complete || !freshParent.Complete ||
            child.OtherErrors != 0 || oldParent.OtherErrors != 0 || freshParent.OtherErrors != 0)
            return KitResult.Inconclusive("Child reception or parent challenge-window coverage incomplete.");
        return new KitResult { Verdict = KitVerdict.SyntheticPass,
            Reason = "Scoped, modeled XInput route only; no universal controller isolation claim." };
    }
}

internal static class KitPostChallengeCleanup
{
    private static readonly string[] Roles = { "parent-pre", "parent-fresh", "child" };
    private static string Issue(Exception error)
    {
        string value = error.GetType().Name + ": " + error.Message;
        return value.Length <= 240 ? value : value.Substring(0, 240);
    }
    // This is the Assign coordinator's post-finalization sequence. The target
    // must be confirmed absent before property restoration. Observer completion
    // is attempted for every role even when another cleanup step fails.
    internal static bool Run(X360RunRecord run, Action removeTarget,
        Action<string> completeObserver, Action restoreProperties, Action persist,
        string observationIssue)
    {
        if (run == null || removeTarget == null || completeObserver == null ||
            restoreProperties == null || persist == null ||
            run.ObserverTeardown == null || run.ObserverTeardown.Count != 0)
            throw new InvalidOperationException("Post-challenge cleanup context invalid.");
        var issues = new List<string>();
        if (observationIssue != null) issues.Add("observation: " + observationIssue);
        bool recordFailure = false;
        Action save = () => { try { persist(); }
            catch (Exception error) {
                if (!recordFailure) { issues.Add("record: " + Issue(error)); recordFailure = true; }
                run.Error = String.Join("; ", issues);
            } };
        try { removeTarget(); run.TargetCleanup = "Removed"; }
        catch (Exception error)
        { run.TargetCleanup = "RemovalFailed"; issues.Add("target: " + Issue(error)); }
        run.State = run.TargetCleanup == "Removed" ? "RemovedPendingObserverAndPropertyRecovery" :
            "TargetRemovalUnconfirmed";
        save();
        foreach (string role in Roles)
        {
            var completion = new X360ObserverTeardownRecord { Role = role };
            try { completeObserver(role); completion.Status = "Exited"; }
            catch (Exception error)
            { completion.Status = "Incomplete"; completion.Error = Issue(error);
              issues.Add("observer " + role + ": " + completion.Error); }
            run.ObserverTeardown.Add(completion);
            save();
        }
        if (run.TargetCleanup == "Removed")
        {
            try { restoreProperties(); run.PropertyCleanup = "Restored"; }
            catch (Exception error)
            { run.PropertyCleanup = "RecoveryFailed"; issues.Add("properties: " + Issue(error)); }
        }
        run.State = run.TargetCleanup != "Removed" ? "TargetRemovalUnconfirmed" :
            run.PropertyCleanup != "Restored" ? "PropertyRecoveryFailed" :
            issues.Count == 0 ? "RemovedAndPropertyRestored" : "RemovedAndRestoredWithLimitations";
        run.Error = issues.Count == 0 ? null : String.Join("; ", issues);
        save();
        return issues.Count == 0 && run.TargetCleanup == "Removed" &&
            run.PropertyCleanup == "Restored" &&
            run.ObserverTeardown.All(status => status.Status == "Exited");
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
    private static void Save(X360RunRecord r) { SaveAt(r, Root, true); }
    internal static void SaveAt(X360RunRecord r, string root, bool protectedAcl)
    {
        Guid run = Guid.ParseExact(r.Run, "N");
        if (!Directory.Exists(root))
        {
            if (protectedAcl)
            {
                var sid = WindowsIdentity.GetCurrent().User;
                var acl = new DirectorySecurity();
                acl.SetAccessRuleProtection(true, false);
                acl.SetOwner(sid);
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.CreateDirectory(root, acl);
            }
            else Directory.CreateDirectory(root);
        }
        string path = Path.Combine(root, run.ToString("N") + ".json");
        if (File.Exists(path)) MergeRecord(r, ReadAt(run, root));
        ValidateDiagnosticEvidence(r);
        string body = Json.Serialize(r);
        if (Encoding.UTF8.GetByteCount(body) > 16384) throw new InvalidOperationException("Run record exceeds limit.");
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        FileStream file;
        if (protectedAcl)
        {
            var fileAcl = new FileSecurity();
            var owner = WindowsIdentity.GetCurrent().User;
            fileAcl.SetAccessRuleProtection(true, false);
            fileAcl.SetOwner(owner);
            fileAcl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            file = new FileStream(temporary, FileMode.CreateNew, FileSystemRights.Write, FileShare.None,
                4096, FileOptions.WriteThrough, fileAcl);
        }
        else file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.WriteThrough);
        using (file)
        { var bytes = Encoding.UTF8.GetBytes(body); file.Write(bytes, 0, bytes.Length); file.Flush(true); }
        if (File.Exists(path)) File.Replace(temporary, path, null);
        else File.Move(temporary, path);
    }
    private static void ValidateDiagnosticEvidence(X360RunRecord r)
    {
        if (r.Phases != null)
        {
            ushort[] sequence = { 0x1000, 0x2000, 0x1000, 0 };
            if (r.Phases.Count > 4) throw new InvalidOperationException("Too many challenge phases.");
            long previous = -1;
            for (int i = 0; i < r.Phases.Count; i++)
            {
                var p = r.Phases[i];
                if (p == null || p.Buttons != sequence[i] || p.StartTick <= previous ||
                    p.EndTick <= p.StartTick || p.ActualEndTick < p.StartTick ||
                    (p.Completed && p.ActualEndTick < p.EndTick) ||
                    (!p.Completed && i != r.Phases.Count - 1))
                    throw new InvalidOperationException("Malformed challenge phase record.");
                previous = p.ActualEndTick;
            }
        }
        if (r.Observations != null && (r.Observations.Count > 3 ||
            r.Observations.Select(o => o == null ? null : o.Role).Distinct().Count() != r.Observations.Count ||
            r.Observations.Any(o => o == null || o.Run != r.Run || o.Slot != r.Slot ||
                o.Attribution != "PinnedClientSlotOnly" ||
                (o.Role != "parent-pre" && o.Role != "parent-fresh" && o.Role != "child"))))
            throw new InvalidOperationException("Wrong-run or duplicate observer evidence.");
        string[] roles = { "parent-pre", "parent-fresh", "child" };
        if (r.ObserverTeardown != null && (r.ObserverTeardown.Count > 3 ||
            r.ObserverTeardown.Where((entry, i) => entry == null || entry.Role != roles[i] ||
                (entry.Status != "Exited" && entry.Status != "Incomplete") ||
                (entry.Status == "Exited" && entry.Error != null)).Any()))
            throw new InvalidOperationException("Malformed or duplicate observer teardown status.");
        if (!(r.TargetCleanup == "Present" || r.TargetCleanup == "Removed" || r.TargetCleanup == "RemovalFailed") ||
            !(r.PropertyCleanup == "NotStarted" || r.PropertyCleanup == "Restored" || r.PropertyCleanup == "RecoveryFailed"))
            throw new InvalidOperationException("Unknown cleanup state.");
    }
    private static void MergeRecord(X360RunRecord incoming, X360RunRecord previous)
    {
        if (previous == null || previous.Run != incoming.Run || previous.OwnerSid != incoming.OwnerSid ||
            previous.Pipe != incoming.Pipe || previous.Source != incoming.Source ||
            previous.FeederImageSha256 != incoming.FeederImageSha256 ||
            previous.FeederPid != incoming.FeederPid || previous.FeederStartTicks != incoming.FeederStartTicks ||
            previous.ParentSession != incoming.ParentSession || previous.ChildSession != incoming.ChildSession ||
            previous.ParentLogon != incoming.ParentLogon || previous.ChildLogon != incoming.ChildLogon ||
            previous.Serial != incoming.Serial || previous.Slot != incoming.Slot)
            throw new InvalidOperationException("Conflicting run record identity.");
        if (incoming.Prior == null || incoming.Prior.Count == 0) incoming.Prior = previous.Prior;
        else if (previous.Prior != null && previous.Prior.Count > 0 &&
            (incoming.Prior.Count < previous.Prior.Count || previous.Prior.Where((p, i) =>
                p.Node != incoming.Prior[i].Node || p.Kind != incoming.Prior[i].Kind || p.Value != incoming.Prior[i].Value).Any()))
            throw new InvalidOperationException("Conflicting exact-property originals.");
        if (incoming.Phases == null || incoming.Phases.Count == 0) incoming.Phases = previous.Phases;
        else if (previous.Phases != null && previous.Phases.Count > 0 && !SamePhases(previous.Phases, incoming.Phases))
            throw new InvalidOperationException("Conflicting challenge phase evidence.");
        if (incoming.Observations == null || incoming.Observations.Count == 0) incoming.Observations = previous.Observations;
        else if (previous.Observations != null && previous.Observations.Count > 0 &&
            !ObservationsExtend(previous.Observations, incoming.Observations))
            throw new InvalidOperationException("Conflicting observation evidence.");
        if (incoming.ObserverTeardown == null || incoming.ObserverTeardown.Count == 0)
            incoming.ObserverTeardown = previous.ObserverTeardown;
        else if (previous.ObserverTeardown != null && previous.ObserverTeardown.Count > 0 &&
            (incoming.ObserverTeardown.Count < previous.ObserverTeardown.Count ||
             previous.ObserverTeardown.Where((entry, i) => entry.Role != incoming.ObserverTeardown[i].Role ||
                 entry.Status != incoming.ObserverTeardown[i].Status ||
                 entry.Error != incoming.ObserverTeardown[i].Error).Any()))
            throw new InvalidOperationException("Conflicting observer teardown status.");
        if (incoming.TargetCleanup == "Present") incoming.TargetCleanup = previous.TargetCleanup;
        else if (previous.TargetCleanup != "Present" && previous.TargetCleanup != incoming.TargetCleanup)
            throw new InvalidOperationException("Conflicting feeder cleanup status.");
        if (incoming.PropertyCleanup == "NotStarted") incoming.PropertyCleanup = previous.PropertyCleanup;
        else if (previous.PropertyCleanup != "NotStarted" && previous.PropertyCleanup != incoming.PropertyCleanup)
            throw new InvalidOperationException("Conflicting helper cleanup status.");
    }
    private static bool SamePhases(List<X360PhaseRecord> a, List<X360PhaseRecord> b)
    { return a.Count == b.Count && !a.Where((p, i) => p.Buttons != b[i].Buttons ||
        p.StartTick != b[i].StartTick || p.EndTick != b[i].EndTick ||
        p.ActualEndTick != b[i].ActualEndTick || p.Completed != b[i].Completed).Any(); }
    private static bool ObservationsExtend(List<X360ObservationRecord> a, List<X360ObservationRecord> b)
    { return a.Count <= b.Count && !a.Where((p, i) => p.Run != b[i].Run || p.Role != b[i].Role ||
        p.Slot != b[i].Slot || p.ChallengeStart != b[i].ChallengeStart || p.ChallengeEnd != b[i].ChallengeEnd ||
        p.ChallengeSamples != b[i].ChallengeSamples || p.NotConnected != b[i].NotConnected ||
        p.OtherErrors != b[i].OtherErrors || p.Complete != b[i].Complete ||
        p.SequenceSeen != b[i].SequenceSeen || p.ConnectedDuringChallenge != b[i].ConnectedDuringChallenge ||
        p.Attribution != b[i].Attribution).Any(); }
    internal static X360RunRecord ReadAt(Guid run, string root)
    {
        var file = new FileInfo(Path.Combine(root, run.ToString("N") + ".json"));
        if (!file.Exists || file.Length > 16384) throw new InvalidOperationException("Bounded private run record unavailable.");
        X360RunRecord r = Json.Deserialize<X360RunRecord>(File.ReadAllText(file.FullName, Encoding.UTF8));
        if (r == null || r.Schema != "ChildStream.X360Qualification.v1" || r.Origin != "NATIVE-ORIGIN-UNQUALIFIED" ||
            r.Source != X360KitBuild.SourceSha ||
            r.ViGEmClient != "8d71f6740ffff4671cdadbca255ce528e3cd3fef" ||
            r.Run != run.ToString("N") || r.Pipe != "ChildStream-X360-" + r.Run)
            throw new InvalidOperationException("Run record identity invalid.");
        return r;
    }
    private static X360RunRecord Load(Guid run)
    {
        X360RunRecord r = ReadAt(run, Root);
        if (r.OwnerSid != CurrentSid) throw new InvalidOperationException("Run record owner identity invalid.");
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
    private static void CheckPeer(uint peerPid, X360RunRecord r, KitPeerRole role,
        bool requireFeederLive = true)
    {
        KitPeerAdmission.Require(SnapshotPeer(peerPid), r, ImageHash(OwnImage()), role);
        KitPeerAdmission.RequireCurrent(new WindowsKitWorld(), r, requireFeederLive);
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
        internal Process Observer;
        internal KitPeerSnapshot Peer;
        internal long ReadyTick;
        public void Dispose() { if (Pipe != null) Pipe.Dispose(); if (Observer != null) Observer.Dispose(); }
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
            lease.Observer = Process.GetProcessById((int)pid);
            if (lease.Observer.StartTime.ToUniversalTime().Ticks != lease.Peer.StartTicks)
                throw new InvalidOperationException("Observer process changed after identity check.");
            var observerHandle = lease.Observer.Handle; // Retain exact process through teardown/exit-code read.
            // READY contains two bounded samples, not merely a live process.
            using (var watchdog = new System.Threading.Timer(_ => { try { lease.Pipe.Dispose(); } catch { } },
                null, TimeSpan.FromSeconds(30), Timeout.InfiniteTimeSpan))
            using (var input = new BinaryReader(lease.Pipe, Encoding.UTF8, true))
            {
                var ready = Json.Deserialize<X360ObserverReadyRecord>(Receive(input));
                KitObserverAdmission.RequireReady(ready, r.Run, role, r.Slot,
                    Stopwatch.GetTimestamp(), Stopwatch.Frequency);
            }
            lease.ReadyTick = Stopwatch.GetTimestamp();
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }
    private static void RequireObserverStillRunning(ObserverLease lease, X360RunRecord r, string role,
        bool requireFeederLive = true)
    {
        KitObserverAdmission.RequireLive(lease != null && lease.Pipe.IsConnected,
            lease != null && new WindowsKitWorld().ProcessMatches(lease.Peer.Pid, lease.Peer.StartTicks),
            lease != null && new WindowsKitWorld().GenerationMatches(r.ParentSession, r.ParentLogon) &&
                new WindowsKitWorld().GenerationMatches(r.ChildSession, r.ChildLogon));
        CheckPeer((uint)lease.Peer.Pid, r, role == "child" ? KitPeerRole.ChildObserver : KitPeerRole.ParentObserver,
            requireFeederLive);
    }
    private static string ObserverCommand(ObserverLease lease, X360RunRecord r, string role, string command,
        bool requireFeederLive = true)
    {
        RequireObserverStillRunning(lease, r, role, requireFeederLive);
        using (var output = new BinaryWriter(lease.Pipe, Encoding.UTF8, true))
        using (var input = new BinaryReader(lease.Pipe, Encoding.UTF8, true))
            return KitObserverProtocol.Command(input, output, r, role, command, 3000, lease.Dispose);
    }
    private static void RequireObserverAck(string value, X360RunRecord r, string role, string command)
    {
        if (value != "ACK " + command + " " + r.Run + " " + role)
            throw new InvalidOperationException("Observer acknowledged a different phase or run.");
    }
    private static void CompleteObserverTeardown(ObserverLease lease, X360RunRecord r, string role)
    {
        // Only this post-challenge completion path allows the feeder's expected
        // exit. Exact observer image/token/PID and both WTS generations still bind.
        RequireObserverAck(ObserverCommand(lease, r, role, "TEARDOWN", false),
            r, role, "TEARDOWN");
        if (lease.Observer == null || !lease.Observer.WaitForExit(3000))
            throw new TimeoutException(role + " acknowledged teardown but did not exit.");
        if (lease.Observer.ExitCode != 0)
            throw new InvalidOperationException(role + " exited unsuccessfully after teardown ACK.");
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
                                run.Stop(); r.TargetCleanup = "Removed";
                                r.State = "RemovedPendingPropertyRecovery"; Save(r);
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
                                run.Stop(); r.TargetCleanup = "Removed";
                                r.State = "RemovedPendingPropertyRecovery"; Save(r);
                                Send(output, "REMOVED");
                                return 4;
                            }
                            if (decision != "ARM") throw new InvalidOperationException("No explicit arm received.");
                            CheckContext(r, true);
                            using (var challengeDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(4)))
                                run.PulseAfterExternalArm(Guid.ParseExact(r.Run, "N"), true,
                                    new MonotonicKitClock(), challengeDeadline.Token);
                            r.Phases = run.Phases.Select(p => new X360PhaseRecord
                                { Buttons = p.Buttons, StartTick = p.StartTick, EndTick = p.EndTick,
                                  ActualEndTick = p.ActualEndTick, Completed = p.Completed }).ToList();
                            r.State = "Pulsed"; Save(r);
                            Send(output, "PULSED");
                            Send(output, Json.Serialize(new X360PhaseEnvelope { Run = r.Run, Phases = r.Phases }));
                            var teardown = Task.Factory.StartNew(() => Receive(input));
                            if (!teardown.Wait(TimeSpan.FromSeconds(15)) || teardown.Result != "TEARDOWN " + r.Run)
                                throw new TimeoutException("Finalization did not release exact target teardown.");
                            run.Stop(); r.TargetCleanup = "Removed";
                            r.State = "RemovedPendingPropertyRecovery"; Save(r);
                            Send(output, "REMOVED");
                        }
                        }
                    }
                    return 0;
                }
                catch (Exception ex)
                {
                    r.Phases = run.Phases.Select(p => new X360PhaseRecord
                        { Buttons = p.Buttons, StartTick = p.StartTick, EndTick = p.EndTick,
                          ActualEndTick = p.ActualEndTick, Completed = p.Completed }).ToList();
                    r.Error = ex.GetType().Name + ": " + ex.Message;
                    r.State = "StoppedOrRecoveryRequired";
                    try { run.Stop(); r.TargetCleanup = "Removed"; }
                    catch (Exception cleanup)
                    { r.TargetCleanup = "RemovalFailed"; r.Error += "; removal: " + cleanup.Message; }
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
                RequireObserverAck(ObserverCommand(parentPre, r, "parent-pre", "ASSIGNMENT"),
                    r, "parent-pre", "ASSIGNMENT");
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
                var line = new StringBuilder(); long deadline = Stopwatch.GetTimestamp() + Stopwatch.Frequency * 120;
                while (Stopwatch.GetTimestamp() < deadline)
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
                foreach (var observer in new[] {
                    new { Lease = parentPre, Role = "parent-pre" },
                    new { Lease = parentFresh, Role = "parent-fresh" },
                    new { Lease = childObserver, Role = "child" } })
                {
                    var arm = Json.Deserialize<X360ObserverArmRecord>(ObserverCommand(
                        observer.Lease, r, observer.Role, "START"));
                    KitObserverAdmission.RequireArm(arm, r.Run, observer.Role, r.Slot,
                        Stopwatch.GetTimestamp(), Stopwatch.Frequency);
                }
                Send(output, "ARM");
                armSent = true;
                string observationIssue = null;
                try
                {
                    if (Receive(input) != "PULSED")
                        throw new InvalidOperationException("Feeder did not complete bounded challenge.");
                    var envelope = Json.Deserialize<X360PhaseEnvelope>(Receive(input));
                    KitPhaseAdmission.Require(envelope, r.Run, Stopwatch.Frequency);
                    if (envelope.Phases.Count != 4 || envelope.Phases.Any(p => !p.Completed))
                        throw new InvalidOperationException("Challenge timeline is partial.");
                    r.Phases = envelope.Phases; r.State = "ChallengeFinalizing"; Save(r);
                    r.Observations = KitObservationFinalization.Collect(r,
                        (role, command) => ObserverCommand(role == "parent-pre" ? parentPre :
                            role == "parent-fresh" ? parentFresh : childObserver, r, role, command),
                        Json, Stopwatch.GetTimestamp,
                        record => { r.Observations.Add(record); Save(r); });
                    r.State = "ChallengeFinalized"; Save(r);
                }
                catch (Exception observationFailure)
                { observationIssue = observationFailure.GetType().Name + ": " + observationFailure.Message; }
                bool cleanupComplete = KitPostChallengeCleanup.Run(r,
                    () => {
                        Send(output, "TEARDOWN " + r.Run);
                        if (Receive(input) != "REMOVED")
                            throw new InvalidOperationException("Exact target removal unconfirmed.");
                    },
                    role => CompleteObserverTeardown(role == "parent-pre" ? parentPre :
                        role == "parent-fresh" ? parentFresh : childObserver, r, role),
                    () => {
                        foreach (string node in nodes)
                        {
                            DeviceProperty prior;
                            if (!assignment.Prior.TryGetValue(node, out prior))
                                throw new InvalidOperationException("Original property record unavailable.");
                            world.RestoreAbsentTargetProperty(node, (uint)r.ChildSession, prior);
                        }
                    }, () => Save(r), observationIssue);
                var disposition = KitObservationFinalization.Classify(r, false);
                Console.WriteLine(cleanupComplete ?
                    "Challenge finalized; exact target, observers, and properties restored. " +
                        disposition.Verdict + ": " + disposition.Reason :
                    "Qualification/cleanup incomplete; review distinct target, observer, and property statuses: " + r.Error);
                return cleanupComplete ? 0 : 4;
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
                        r.TargetCleanup = "Removed"; r.PropertyCleanup = "Restored";
                        r.State = "RemovedAndPropertyRestoredAfterAbort"; Save(r);
                    }
                    catch (Exception recovery)
                    {
                        r.PropertyCleanup = "RecoveryFailed";
                        r.Error = "Observer/arm failed; exact property recovery incomplete: " + recovery.Message;
                        try { Save(r); } catch { }
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
        string role = args[1];
        Console.WriteLine("NATIVE-ORIGIN-UNQUALIFIED XInput " + role + " polling owned target index " + run.Slot + ".");
        using (var readiness = new NamedPipeClientStream(".", ObserverPipe(run, role), PipeDirection.InOut, PipeOptions.None))
        {
            readiness.Connect(120000);
            uint helperPid;
            if (!GetNamedPipeServerProcessId(readiness.SafePipeHandle.DangerousGetHandle(), out helperPid))
                throw new InvalidOperationException("Observer helper identity unavailable.");
            CheckPeer(helperPid, run, KitPeerRole.Assignment);
            ObserveCoordinated(readiness, readiness, xinput, run, role, seconds, Console.WriteLine);
        }
        return 0;
    }
    internal static X360ObserverOutcome ObserveCoordinated(Stream inbound, Stream outbound,
        IControllerSlotReader xinput, X360RunRecord run, string role, int seconds, Action<string> log)
    {
        if (inbound == null || outbound == null || xinput == null || run == null ||
            (role != "parent-pre" && role != "parent-fresh" && role != "child") ||
            run.Slot > 3 || seconds < 1 || seconds > 600)
            throw new InvalidOperationException("Observer coordination context invalid.");
        var window = new KitObserverWindow(role == "child", role == "parent-pre");
        var input = new BinaryReader(inbound, Encoding.UTF8, true);
        var output = new BinaryWriter(outbound, Encoding.UTF8, true);
        long firstTick = Stopwatch.GetTimestamp();
        ControllerSlotState first = xinput.Read(run.Slot);
        window.Sample(firstTick, first.Buttons, first.Error, Stopwatch.Frequency);
        Thread.Sleep(50);
        long secondTick = Stopwatch.GetTimestamp();
        ControllerSlotState second = xinput.Read(run.Slot);
        window.Sample(secondTick, second.Buttons, second.Error, Stopwatch.Frequency);
        var ready = new X360ObserverReadyRecord { Run = run.Run, Role = role, Slot = run.Slot,
            FirstTick = firstTick, SecondTick = secondTick,
            FirstError = first.Error, SecondError = second.Error };
        Send(output, Json.Serialize(ready));
        if (log != null) log(Json.Serialize(new { schema = "ChildStream.X360Observation.v2",
            run = run.Run, role = role, phase = window.Phase.ToString(), tick = firstTick,
            slot = run.Slot, error = first.Error, packet = first.Packet, buttons = first.Buttons }));
        long deadline = Stopwatch.GetTimestamp() + Stopwatch.Frequency * seconds;
        long teardownUntil = 0;
        uint previousPacket = second.Packet, previousError = second.Error;
        X360ObservationRecord frozen = null;
        Task<string> command = Task.Factory.StartNew(() => Receive(input));
        while (Stopwatch.GetTimestamp() < deadline)
        {
            string action = null;
            if (command != null && command.IsCompleted)
            {
                action = command.GetAwaiter().GetResult();
                string suffix = " " + run.Run + " " + role;
                if (action == "ASSIGNMENT" + suffix) window.Assignment();
                else if (action == "START" + suffix) window.StartChallenge(Stopwatch.GetTimestamp());
                else if (action == "FINALIZE" + suffix) window.FinalizeChallenge(Stopwatch.GetTimestamp());
                else if (action == "TEARDOWN" + suffix)
                { window.Teardown(); teardownUntil = Stopwatch.GetTimestamp() + Stopwatch.Frequency / 2; }
                else throw new InvalidOperationException("Observer received wrong-run or out-of-order phase command.");
            }
            long tick = Stopwatch.GetTimestamp();
            ControllerSlotState state = xinput.Read(run.Slot);
            window.Sample(tick, state.Buttons, state.Error, Stopwatch.Frequency);
            if (log != null && (state.Packet != previousPacket || state.Error != previousError || action != null))
                log(Json.Serialize(new { schema = "ChildStream.X360Observation.v2", run = run.Run,
                    role = role, phase = window.Phase.ToString(), tick = tick, slot = run.Slot,
                    error = state.Error, packet = state.Packet, buttons = state.Buttons }));
            previousPacket = state.Packet; previousError = state.Error;
            if (action != null)
            {
                if (action.StartsWith("ASSIGNMENT ", StringComparison.Ordinal) ||
                    action.StartsWith("TEARDOWN ", StringComparison.Ordinal))
                    Send(output, "ACK " + (action.StartsWith("ASSIGNMENT ", StringComparison.Ordinal) ?
                        "ASSIGNMENT" : "TEARDOWN") + " " + run.Run + " " + role);
                else if (action.StartsWith("START ", StringComparison.Ordinal))
                    Send(output, Json.Serialize(new X360ObserverArmRecord { Run = run.Run, Role = role,
                        Slot = run.Slot, Tick = tick, Error = state.Error }));
                else if (action.StartsWith("FINALIZE ", StringComparison.Ordinal))
                {
                    frozen = KitObserverAdmission.Finalize(run.Run, role, run.Slot, window);
                    Send(output, Json.Serialize(frozen));
                }
                command = action.StartsWith("TEARDOWN ", StringComparison.Ordinal) ? null :
                    Task.Factory.StartNew(() => Receive(input));
            }
            if (teardownUntil > 0 && tick >= teardownUntil) break;
            Thread.Sleep(50);
        }
        if (frozen == null) throw new InvalidOperationException("Observer deadline expired before challenge finalization.");
        if (log != null) log(Json.Serialize(new { schema = "ChildStream.X360ObservationSummary.v2",
            origin = "NATIVE-ORIGIN-UNQUALIFIED", run = run.Run, role = role,
            challenge = frozen, teardownNotConnected = window.TeardownNotConnected,
            teardownOtherErrors = window.TeardownErrors }));
        return new X360ObserverOutcome { Challenge = frozen,
            TeardownNotConnected = window.TeardownNotConnected,
            TeardownOtherErrors = window.TeardownErrors };
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
