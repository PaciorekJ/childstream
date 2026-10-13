using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// The feasibility host interface is fake-only in this branch. No Windows class
// implements its mutation methods, and no entry point invokes this state machine
// against the physical host.
internal enum ProbeStage
{ Captured, PreparedEnable, AwaitFreshParent, ReadyConnect, Connecting, Connected,
  OutcomeUnknown, TeardownPrepared, ChildEnded, Restoring, Restored, Conflict }
internal enum ProbeConnectOutcome { AutomaticLogon, CredentialPrompt, Failed, Unknown }

internal sealed class ProbeSnapshot
{
    internal ResourceAccess FeatureAccess;
    internal bool FeatureEnabled;
    internal uint ParentSessionId, ConsoleSessionId;
    internal long ParentLogonTime;
    internal string AccountBinding, Edition, RdpRegistryFingerprint, ListenerFingerprint,
        FirewallFingerprint, DisplayFingerprint, NativeResourceFingerprint;
    internal int WindowsBuild;
    internal bool NetworkRdpClosed;
    internal ResourceAccess ChildAccess;
    internal ChildSessionIdentity? AssociatedChild;

    internal string InfrastructureFingerprint()
    { return RdpRegistryFingerprint + "|" + ListenerFingerprint + "|" + FirewallFingerprint + "|" + DisplayFingerprint + "|" + NativeResourceFingerprint; }
}

internal sealed class ProbePlan
{
    internal ProbeSnapshot Original;
    internal string Hash;
    internal bool NeedsEnable { get { return !Original.FeatureEnabled; } }
}

internal sealed class ProbeJournal
{
    internal ProbePlan Plan;
    internal ProbeStage Stage;
    internal uint ActiveParentId;
    internal long ActiveParentLogonTime;
    internal ChildSessionIdentity? PositiveChild;
    internal bool ConsoleConfirmed;
    internal string AuthenticationOutcome = "unobserved";
    internal int ErrorCode;
}

internal sealed class ProbeConnectionResult
{
    internal ProbeConnectOutcome Outcome;
    internal ChildSessionIdentity? Identity;
    internal int ErrorCode;
}

internal interface IFeasibilityHost
{
    ProbeSnapshot Capture();
    bool CompareExchangeChildFeature(bool expected, bool desired);
    ProbeConnectionResult ConnectWithoutPassword();
    bool LogoffExact(ChildSessionIdentity expected);
    bool HasAdministratorPrivilege { get; }
}

internal interface IProbeStore
{
    ProbeJournal Load();
    void Save(ProbeJournal journal);
    ProbeJournal ResolveInterruptedReplacement();
}

internal static class ProbeCodec
{
    internal static byte[] PlanBytes(ProbeSnapshot snapshot)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(1); writer.Write((int)snapshot.FeatureAccess); writer.Write(snapshot.FeatureEnabled);
            writer.Write(snapshot.ParentSessionId); writer.Write(snapshot.ConsoleSessionId);
            writer.Write(snapshot.ParentLogonTime); writer.Write(snapshot.AccountBinding);
            writer.Write((int)snapshot.ChildAccess);
            writer.Write(snapshot.Edition); writer.Write(snapshot.WindowsBuild); writer.Write(snapshot.NetworkRdpClosed);
            writer.Write(snapshot.RdpRegistryFingerprint); writer.Write(snapshot.ListenerFingerprint);
            writer.Write(snapshot.FirewallFingerprint); writer.Write(snapshot.DisplayFingerprint);
            writer.Write(snapshot.NativeResourceFingerprint);
            writer.Flush(); return stream.ToArray();
        }
    }

    internal static string Hash(byte[] data)
    {
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
    }

    internal static ProbeSnapshot ReadPlan(byte[] data)
    {
        using (var stream = new MemoryStream(data))
        using (var reader = new BinaryReader(stream, Encoding.UTF8))
        {
            if (reader.ReadInt32() != 1) throw new InvalidDataException("Unsupported probe plan version.");
            var s = new ProbeSnapshot();
            s.FeatureAccess = (ResourceAccess)reader.ReadInt32(); s.FeatureEnabled = reader.ReadBoolean();
            s.ParentSessionId = reader.ReadUInt32(); s.ConsoleSessionId = reader.ReadUInt32();
            s.ParentLogonTime = reader.ReadInt64(); s.AccountBinding = reader.ReadString();
            s.ChildAccess = (ResourceAccess)reader.ReadInt32();
            if (s.ChildAccess != ResourceAccess.Absent) throw new InvalidDataException("The approved plan requires verified child absence.");
            s.Edition = reader.ReadString(); s.WindowsBuild = reader.ReadInt32(); s.NetworkRdpClosed = reader.ReadBoolean();
            s.RdpRegistryFingerprint = reader.ReadString(); s.ListenerFingerprint = reader.ReadString();
            s.FirewallFingerprint = reader.ReadString(); s.DisplayFingerprint = reader.ReadString();
            s.NativeResourceFingerprint = reader.ReadString();
            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing probe plan data.");
            if (s.FeatureAccess != ResourceAccess.Accessible || s.ParentSessionId == uint.MaxValue ||
                s.ParentSessionId != s.ConsoleSessionId || s.ParentLogonTime <= 0 ||
                s.Edition != "Professional" || s.WindowsBuild < 22000 || !s.NetworkRdpClosed ||
                String.IsNullOrEmpty(s.AccountBinding) || String.IsNullOrEmpty(s.RdpRegistryFingerprint) ||
                String.IsNullOrEmpty(s.ListenerFingerprint) || String.IsNullOrEmpty(s.FirewallFingerprint) ||
                String.IsNullOrEmpty(s.DisplayFingerprint) || String.IsNullOrEmpty(s.NativeResourceFingerprint))
                throw new InvalidDataException("Malformed probe prerequisite snapshot.");
            return s;
        }
    }

    internal static byte[] JournalBytes(ProbeJournal journal)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(1); writer.Write((int)journal.Stage); writer.Write(journal.ActiveParentId);
            writer.Write(journal.ActiveParentLogonTime); writer.Write(journal.PositiveChild.HasValue);
            if (journal.PositiveChild.HasValue)
            { writer.Write(journal.PositiveChild.Value.SessionId); writer.Write(journal.PositiveChild.Value.LogonTime); }
            writer.Write(journal.ConsoleConfirmed); writer.Write(journal.AuthenticationOutcome);
            writer.Write(journal.ErrorCode); writer.Flush(); return stream.ToArray();
        }
    }

    internal static void ReadJournal(byte[] data, ProbeJournal journal)
    {
        using (var stream = new MemoryStream(data))
        using (var reader = new BinaryReader(stream, Encoding.UTF8))
        {
            if (reader.ReadInt32() != 1) throw new InvalidDataException("Unsupported probe journal version.");
            journal.Stage = (ProbeStage)reader.ReadInt32();
            if (!Enum.IsDefined(typeof(ProbeStage), journal.Stage)) throw new InvalidDataException("Invalid probe stage.");
            journal.ActiveParentId = reader.ReadUInt32(); journal.ActiveParentLogonTime = reader.ReadInt64();
            if (reader.ReadBoolean()) journal.PositiveChild = new ChildSessionIdentity(reader.ReadUInt32(), reader.ReadInt64());
            journal.ConsoleConfirmed = reader.ReadBoolean(); journal.AuthenticationOutcome = reader.ReadString();
            journal.ErrorCode = reader.ReadInt32();
            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing probe journal data.");
            if (journal.ActiveParentId == uint.MaxValue || journal.ActiveParentLogonTime <= 0 ||
                (journal.PositiveChild.HasValue &&
                    (journal.PositiveChild.Value.SessionId == uint.MaxValue ||
                     journal.PositiveChild.Value.SessionId == journal.ActiveParentId ||
                     journal.PositiveChild.Value.LogonTime <= 0)) ||
                ((journal.Stage == ProbeStage.Connected || journal.Stage == ProbeStage.TeardownPrepared ||
                  journal.Stage == ProbeStage.ChildEnded) && !journal.PositiveChild.HasValue) ||
                (journal.Stage == ProbeStage.Connected && journal.AuthenticationOutcome != "AutomaticLogon") ||
                (journal.Stage == ProbeStage.ChildEnded && !journal.ConsoleConfirmed))
                throw new InvalidDataException("Inconsistent probe progress snapshot.");
        }
    }
}

// Reuses the classified, atomic journal store from PR #2. Its single record is
// private to this probe; InstallerEngine never accepts ChildSessions as a target.
internal sealed class FileProbeStore : IProbeStore
{
    private readonly FileJournalStore store;
    internal FileProbeStore(string path) { store = new FileJournalStore(path); }
    public ProbeJournal Load() { return Decode(store.Load()); }
    public ProbeJournal ResolveInterruptedReplacement() { return Decode(store.ResolveInterruptedReplacement()); }
    private static ProbeJournal Decode(InstallJournal raw)
    {
        if (raw == null) return null;
        if (raw.Phase != JournalPhase.Planned || raw.Entries.Count != 1 ||
            raw.Entries[0].Phase != JournalPhase.Applied ||
            raw.Entries[0].Operation.Target.Kind != ResourceKind.ChildSessions ||
            raw.Entries[0].Operation.Target.Identity != "ChildStream.FeasibilityProbe")
            throw new InvalidDataException("Unexpected probe journal record.");
        InstallOperation op = raw.Entries[0].Operation;
        if (op.Original.Access != ResourceAccess.Accessible || op.Desired.Access != ResourceAccess.Accessible ||
            op.Original.ValueType != "ProbePlanV1" || op.Desired.ValueType != "ProbeProgressV1" ||
            raw.PlanHash != ProbeCodec.Hash(op.Original.Data))
            throw new InvalidDataException("Probe plan integrity failed.");
        var plan = new ProbePlan { Original = ProbeCodec.ReadPlan(op.Original.Data), Hash = raw.PlanHash };
        var journal = new ProbeJournal { Plan = plan };
        ProbeCodec.ReadJournal(op.Desired.Data, journal);
        return journal;
    }
    public void Save(ProbeJournal journal)
    {
        byte[] planData = ProbeCodec.PlanBytes(journal.Plan.Original);
        if (journal.Plan.Hash != ProbeCodec.Hash(planData)) throw new InvalidDataException("Probe plan changed.");
        var raw = new InstallJournal { PlanHash = journal.Plan.Hash, Phase = JournalPhase.Planned };
        raw.Entries.Add(new JournalEntry { Phase = JournalPhase.Applied,
            Operation = new InstallOperation {
                Target = new ResourceTarget(ResourceKind.ChildSessions, "ChildStream.FeasibilityProbe"),
                Original = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "ProbePlanV1", Data = planData },
                Desired = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "ProbeProgressV1", Data = ProbeCodec.JournalBytes(journal) },
                Privilege = InstallPrivilege.Administrator, OwnershipEvidence = "FeasibilityProbe",
                Verification = "Feature state and session identity", Reversal = "Restore exact original child feature" } });
        store.Save(raw);
    }
}

internal sealed class FeasibilityProbe
{
    private readonly IFeasibilityHost host;
    private readonly IProbeStore store;
    private readonly ITransactionOwnership owner;
    internal FeasibilityProbe(IFeasibilityHost host, IProbeStore store, ITransactionOwnership owner)
    { this.host = host; this.store = store; this.owner = owner; }

    private static void Require(bool condition, string reason)
    { if (!condition) throw new InvalidOperationException(reason); }

    private static void ValidateInitial(ProbeSnapshot s)
    {
        Require(s != null && s.FeatureAccess == ResourceAccess.Accessible && s.ParentSessionId != uint.MaxValue &&
            s.ParentSessionId == s.ConsoleSessionId && s.ParentLogonTime > 0 &&
            s.Edition == "Professional" && s.WindowsBuild >= 22000 && s.NetworkRdpClosed &&
            s.ChildAccess == ResourceAccess.Absent && !s.AssociatedChild.HasValue && !String.IsNullOrEmpty(s.AccountBinding) &&
            !String.IsNullOrEmpty(s.RdpRegistryFingerprint) && !String.IsNullOrEmpty(s.ListenerFingerprint) &&
            !String.IsNullOrEmpty(s.FirewallFingerprint) && !String.IsNullOrEmpty(s.DisplayFingerprint) &&
            !String.IsNullOrEmpty(s.NativeResourceFingerprint),
            "The Windows 11 Pro console, child feature, session, or closed-RDP prerequisites are uncertain.");
    }

    private static void ValidateUnchanged(ProbeJournal journal, ProbeSnapshot current)
    {
        Require(current != null && current.FeatureAccess == ResourceAccess.Accessible &&
            current.AccountBinding == journal.Plan.Original.AccountBinding &&
            current.NetworkRdpClosed && current.InfrastructureFingerprint() == journal.Plan.Original.InfrastructureFingerprint(),
            "RDP, display, native resources, account, or feature observation drifted.");
    }

    internal ProbePlan Plan()
    {
        using (owner.Acquire())
        {
            ProbeSnapshot s = host.Capture(); ValidateInitial(s);
            return new ProbePlan { Original = s, Hash = ProbeCodec.Hash(ProbeCodec.PlanBytes(s)) };
        }
    }

    internal ProbeJournal Begin(ProbePlan plan, string approvedHash, bool explicitConsent)
    {
        using (owner.Acquire())
        {
            Require(explicitConsent && plan != null && plan.Hash == approvedHash &&
                plan.Hash == ProbeCodec.Hash(ProbeCodec.PlanBytes(plan.Original)), "Explicit approval for the exact probe plan is required.");
            Require(store.Load() == null, "A probe journal already exists; recover it before starting again.");
            ProbeSnapshot current = host.Capture(); ValidateInitial(current);
            Require(ProbeCodec.Hash(ProbeCodec.PlanBytes(current)) == plan.Hash, "The approved probe inventory is stale.");
            var journal = new ProbeJournal { Plan = plan, Stage = ProbeStage.Captured,
                ActiveParentId = current.ParentSessionId, ActiveParentLogonTime = current.ParentLogonTime };
            store.Save(journal); return journal;
        }
    }

    internal ProbeJournal PrepareFeature()
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal(); Require(j.Stage == ProbeStage.Captured, "Feature preparation is not available in this stage.");
            ProbeSnapshot s = host.Capture(); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == j.ActiveParentId && s.ParentLogonTime == j.ActiveParentLogonTime &&
                s.ChildAccess == ResourceAccess.Absent && !s.AssociatedChild.HasValue && s.FeatureEnabled == j.Plan.Original.FeatureEnabled,
                "Parent, child, or child-feature state changed before preparation.");
            if (!s.FeatureEnabled)
            {
                Require(host.HasAdministratorPrivilege, "Administrator privilege is required for child-feature change; no escalation is attempted.");
                j.Stage = ProbeStage.PreparedEnable; store.Save(j);
                Require(host.CompareExchangeChildFeature(false, true), "Child-feature enablement did not match the recorded original.");
                ProbeSnapshot verified = host.Capture(); ValidateUnchanged(j, verified);
                Require(verified.FeatureEnabled && verified.ChildAccess == ResourceAccess.Absent &&
                    verified.ParentSessionId == j.ActiveParentId && verified.ParentLogonTime == j.ActiveParentLogonTime,
                    "Child-feature enablement could not be verified.");
            }
            j.Stage = ProbeStage.AwaitFreshParent; store.Save(j); return j;
        }
    }

    internal ProbeJournal ResumeAfterFreshLogon()
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal(); Require(j.Stage == ProbeStage.AwaitFreshParent, "No fresh-parent boundary is pending.");
            ProbeSnapshot s = host.Capture(); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == s.ConsoleSessionId && s.ParentLogonTime != j.Plan.Original.ParentLogonTime &&
                s.ParentLogonTime > 0 && s.FeatureEnabled && s.ChildAccess == ResourceAccess.Absent && !s.AssociatedChild.HasValue,
                "A fresh, child-free parent console logon is required before automatic authentication.");
            j.ActiveParentId = s.ParentSessionId; j.ActiveParentLogonTime = s.ParentLogonTime;
            j.Stage = ProbeStage.ReadyConnect; store.Save(j); return j;
        }
    }

    internal ProbeJournal ConnectOnce()
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal(); Require(j.Stage == ProbeStage.ReadyConnect, "The one connection attempt is unavailable.");
            ProbeSnapshot before = host.Capture(); ValidateUnchanged(j, before);
            Require(before.ParentSessionId == j.ActiveParentId && before.ParentLogonTime == j.ActiveParentLogonTime &&
                before.FeatureEnabled && before.ChildAccess == ResourceAccess.Absent && !before.AssociatedChild.HasValue, "Parent or child changed before connection.");
            j.Stage = ProbeStage.Connecting; store.Save(j);
            ProbeConnectionResult result;
            try { result = host.ConnectWithoutPassword(); }
            catch { j.Stage = ProbeStage.OutcomeUnknown; store.Save(j); throw; }
            ProbeSnapshot after = host.Capture(); ValidateUnchanged(j, after);
            Require(result != null, "The connection result is missing; the attempt is unresolved.");
            j.ErrorCode = result.ErrorCode; j.AuthenticationOutcome = result.Outcome.ToString();
            if (after.ParentSessionId == j.ActiveParentId && after.ParentLogonTime == j.ActiveParentLogonTime &&
                after.ChildAccess == ResourceAccess.Accessible && result.Identity.HasValue && after.AssociatedChild.HasValue &&
                result.Identity.Value.Equals(after.AssociatedChild.Value) &&
                result.Identity.Value.SessionId != before.ParentSessionId && result.Identity.Value.LogonTime > 0)
                j.PositiveChild = result.Identity;
            j.Stage = result.Outcome == ProbeConnectOutcome.AutomaticLogon && j.PositiveChild.HasValue
                ? ProbeStage.Connected : ProbeStage.OutcomeUnknown;
            store.Save(j); return j;
        }
    }

    internal ProbeJournal ConfirmConsoleUsable(bool operatorConfirmed)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(operatorConfirmed && j.PositiveChild.HasValue &&
                (j.Stage == ProbeStage.Connected || j.Stage == ProbeStage.OutcomeUnknown),
                "Physical-console usability needs an explicit operator checkpoint.");
            ProbeSnapshot s = host.Capture(); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == s.ConsoleSessionId && s.ChildAccess == ResourceAccess.Accessible && s.AssociatedChild.HasValue &&
                s.AssociatedChild.Value.Equals(j.PositiveChild.Value), "Console or child identity changed.");
            j.ConsoleConfirmed = true; store.Save(j); return j;
        }
    }

    internal ProbeJournal EndPositiveChild(bool explicitConsent)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(explicitConsent && j.ConsoleConfirmed && j.PositiveChild.HasValue &&
                (j.Stage == ProbeStage.Connected || j.Stage == ProbeStage.OutcomeUnknown),
                "Only a positively identified test child may be ended with explicit consent.");
            ProbeSnapshot before = host.Capture(); ValidateUnchanged(j, before);
            Require(before.ParentSessionId == j.ActiveParentId && before.ParentLogonTime == j.ActiveParentLogonTime &&
                before.ChildAccess == ResourceAccess.Accessible && before.AssociatedChild.HasValue &&
                before.AssociatedChild.Value.Equals(j.PositiveChild.Value),
                "The parent-associated child identity changed; logoff is forbidden.");
            j.Stage = ProbeStage.TeardownPrepared; store.Save(j);
            // TeardownPrepared remains durable on any exception; never automatically repeat logoff.
            bool result = host.LogoffExact(j.PositiveChild.Value);
            ProbeSnapshot after = host.Capture(); ValidateUnchanged(j, after);
            j.Stage = result && after.ParentSessionId == j.ActiveParentId &&
                after.ParentLogonTime == j.ActiveParentLogonTime &&
                after.ChildAccess == ResourceAccess.Absent && !after.AssociatedChild.HasValue
                ? ProbeStage.ChildEnded : ProbeStage.TeardownPrepared;
            store.Save(j); return j;
        }
    }

    internal ProbeJournal RestoreOriginal(bool acknowledgeAmbiguousFeatureMutation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            ProbeSnapshot s = host.Capture(); ValidateUnchanged(j, s);
            if (j.Stage == ProbeStage.Restored)
            {
                Require(s.ChildAccess == ResourceAccess.Absent && !s.AssociatedChild.HasValue &&
                    s.FeatureEnabled == j.Plan.Original.FeatureEnabled,
                    "The previously restored state drifted.");
                return j;
            }
            Require(s.ChildAccess == ResourceAccess.Absent && !s.AssociatedChild.HasValue,
                "A child is present or uncertain; feature restoration is blocked.");
            if (s.FeatureEnabled != j.Plan.Original.FeatureEnabled)
            {
                Require(j.Stage != ProbeStage.Captured &&
                    (j.Stage != ProbeStage.PreparedEnable || acknowledgeAmbiguousFeatureMutation),
                    "The feature changed during an unverified enable intent; explicit recovery review is required.");
                Require(j.Plan.NeedsEnable && s.FeatureEnabled && host.HasAdministratorPrivilege,
                    "Feature state drifted or Administrator privilege is missing; no escalation is attempted.");
                j.Stage = ProbeStage.Restoring; store.Save(j);
                Require(host.CompareExchangeChildFeature(true, false), "Child-feature restoration did not match expected state.");
                s = host.Capture(); ValidateUnchanged(j, s);
                Require(!s.FeatureEnabled, "Child-feature restoration was not verified.");
            }
            j.Stage = ProbeStage.Restored; store.Save(j); return j;
        }
    }

    internal ProbeJournal ResolveInterruptedJournal()
    { using (owner.Acquire()) return store.ResolveInterruptedReplacement(); }

    private ProbeJournal RequiredJournal()
    {
        ProbeJournal journal = store.Load();
        Require(journal != null && journal.Plan.Hash == ProbeCodec.Hash(ProbeCodec.PlanBytes(journal.Plan.Original)),
            "A valid probe journal is required.");
        return journal;
    }
}
