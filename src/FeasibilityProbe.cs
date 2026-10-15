using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// The host adapter is never called by the offline tests against the physical host.
internal enum ProbeStage
{ Captured, PreparedEnable, AwaitFreshParent, StageAQueryUnknown, StageAValidated,
  ReadyConnect, Connecting, Connected,
  OutcomeUnknown, TeardownPrepared, ChildEnded, Restoring, Restored, Conflict }
internal enum ProbeConnectOutcome { AutomaticLogon, CredentialPrompt, Failed, Unknown }
internal enum ProbeNetworkPosture { ConnectedRdpGuard, NetworkIsolated, ExternalNetworkIsolated }

internal sealed class ProbeSnapshot
{
    internal int FormatVersion = 3;
    internal ProbeNetworkPosture NetworkPosture;
    internal bool OperatorConfirmedIsolation;
    internal ResourceAccess FeatureAccess;
    internal bool FeatureEnabled;
    internal uint ParentSessionId, ConsoleSessionId;
    internal int ParentProtocolType;
    internal long ParentLogonTime;
    internal string AccountBinding, Edition, RdpRegistryFingerprint, ListenerFingerprint,
        FirewallFingerprint, DisplayFingerprint, NativeResourceFingerprint;
    internal int WindowsBuild;
    internal bool LocalRdpPostureAccepted;
    internal bool RdpPolicyDenied, TermServiceStopped, RdpListenersAbsent,
        FirewallObservationComplete, NetworkIsolationAccepted, BoundaryAccepted, BoundaryRdpAccepted;
    internal string NetworkFingerprint;
    internal ResourceAccess ChildAccess;
    internal int ChildApiErrorCode;
    internal bool IndependentNoUnexpectedSessions;
    internal bool IndependentOnlyAssociatedChild;
    internal string SessionInventoryFingerprint;
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
    internal bool ConnectionAttempted;
    internal string AuthenticationOutcome = "unobserved";
    internal int ErrorCode;
    internal bool NetworkDeviationObserved;
    internal string NetworkDeviationFingerprint = "";
    internal string NetworkDeviationReason = "";
    internal bool NetworkRecoveryReviewed;
    internal bool ReviewedChildTeardown;
}

internal sealed class ProbeConnectionResult
{
    internal ProbeConnectOutcome Outcome;
    internal ChildSessionIdentity? Identity;
    internal int ErrorCode;
}

internal sealed class ProbeReconnectAssessment
{
    internal bool FeatureRestored, ChildExcluded, NetworkIsolated, RdpPolicyDenied,
        TermServiceStopped, RdpListenersAbsent, InfrastructureRestored, JournalRestored;
    internal bool Ready { get { return FeatureRestored && ChildExcluded && NetworkIsolated &&
        RdpPolicyDenied && TermServiceStopped && RdpListenersAbsent &&
        InfrastructureRestored && JournalRestored; } }
}

internal interface IFeasibilityHost
{
    ProbeSnapshot Capture();
    ProbeSnapshot CaptureBoundary(bool operatorConfirmedPhysicalSeverance);
    bool CompareExchangeChildFeature(bool expected, bool desired);
    ProbeConnectionResult ConnectWithoutPassword(Action observeBoundary, Action<ChildSessionIdentity> observedChild);
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
    internal static bool PreFeatureChildGate(ProbeSnapshot s)
    {
        return s != null && s.IndependentNoUnexpectedSessions && !s.AssociatedChild.HasValue &&
            (s.ChildAccess == ResourceAccess.Absent && s.ChildApiErrorCode == 0 ||
             (!s.FeatureEnabled && s.ChildAccess == ResourceAccess.Unknown && s.ChildApiErrorCode == 1168));
    }
    internal static byte[] PlanBytes(ProbeSnapshot snapshot)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(snapshot.FormatVersion); writer.Write((int)snapshot.FeatureAccess); writer.Write(snapshot.FeatureEnabled);
            writer.Write(snapshot.ParentSessionId); writer.Write(snapshot.ConsoleSessionId);
            writer.Write(snapshot.ParentProtocolType);
            writer.Write(snapshot.ParentLogonTime); writer.Write(snapshot.AccountBinding);
            writer.Write((int)snapshot.ChildAccess); writer.Write(snapshot.ChildApiErrorCode);
            writer.Write(snapshot.IndependentNoUnexpectedSessions); writer.Write(snapshot.SessionInventoryFingerprint);
            writer.Write(snapshot.Edition); writer.Write(snapshot.WindowsBuild); writer.Write(snapshot.LocalRdpPostureAccepted);
            writer.Write(snapshot.RdpRegistryFingerprint); writer.Write(snapshot.ListenerFingerprint);
            writer.Write(snapshot.FirewallFingerprint); writer.Write(snapshot.DisplayFingerprint);
            writer.Write(snapshot.NativeResourceFingerprint);
            if (snapshot.FormatVersion == 4 || snapshot.FormatVersion == 5 || snapshot.FormatVersion == 6)
            {
                writer.Write((int)snapshot.NetworkPosture); writer.Write(snapshot.OperatorConfirmedIsolation);
                writer.Write(snapshot.RdpPolicyDenied); writer.Write(snapshot.TermServiceStopped);
                writer.Write(snapshot.RdpListenersAbsent); writer.Write(snapshot.FirewallObservationComplete);
                writer.Write(snapshot.NetworkIsolationAccepted); writer.Write(snapshot.NetworkFingerprint ?? "");
                if (snapshot.FormatVersion == 5)
                { writer.Write(snapshot.BoundaryAccepted); writer.Write(snapshot.BoundaryRdpAccepted); }
            }
            else if (snapshot.FormatVersion != 3) throw new InvalidDataException("Unsupported probe plan version.");
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
            int version = reader.ReadInt32();
            if (version != 3 && version != 4 && version != 5 && version != 6) throw new InvalidDataException("Unsupported probe plan version.");
            var s = new ProbeSnapshot();
            s.FormatVersion = version;
            s.FeatureAccess = (ResourceAccess)reader.ReadInt32(); s.FeatureEnabled = reader.ReadBoolean();
            s.ParentSessionId = reader.ReadUInt32(); s.ConsoleSessionId = reader.ReadUInt32();
            s.ParentProtocolType = reader.ReadInt32();
            s.ParentLogonTime = reader.ReadInt64(); s.AccountBinding = reader.ReadString();
            s.ChildAccess = (ResourceAccess)reader.ReadInt32(); s.ChildApiErrorCode = reader.ReadInt32();
            s.IndependentNoUnexpectedSessions = reader.ReadBoolean(); s.SessionInventoryFingerprint = reader.ReadString();
            if (!PreFeatureChildGate(s)) throw new InvalidDataException("Pre-feature child evidence is insufficient.");
            s.Edition = reader.ReadString(); s.WindowsBuild = reader.ReadInt32(); s.LocalRdpPostureAccepted = reader.ReadBoolean();
            s.RdpRegistryFingerprint = reader.ReadString(); s.ListenerFingerprint = reader.ReadString();
            s.FirewallFingerprint = reader.ReadString(); s.DisplayFingerprint = reader.ReadString();
            s.NativeResourceFingerprint = reader.ReadString();
            if (version == 4 || version == 5 || version == 6)
            {
                s.NetworkPosture = (ProbeNetworkPosture)reader.ReadInt32();
                s.OperatorConfirmedIsolation = reader.ReadBoolean();
                s.RdpPolicyDenied = reader.ReadBoolean(); s.TermServiceStopped = reader.ReadBoolean();
                s.RdpListenersAbsent = reader.ReadBoolean(); s.FirewallObservationComplete = reader.ReadBoolean();
                s.NetworkIsolationAccepted = reader.ReadBoolean(); s.NetworkFingerprint = reader.ReadString();
                if (version == 5)
                { s.BoundaryAccepted = reader.ReadBoolean(); s.BoundaryRdpAccepted = reader.ReadBoolean(); }
            }
            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing probe plan data.");
            if (s.FeatureAccess != ResourceAccess.Accessible || s.ParentSessionId == uint.MaxValue ||
                s.ParentSessionId != s.ConsoleSessionId || s.ParentProtocolType != 0 || s.ParentLogonTime <= 0 ||
                s.Edition != "Professional" || s.WindowsBuild < 22000 ||
                (version == 3 && !s.LocalRdpPostureAccepted) ||
                ((version == 4 || version == 6) && (s.NetworkPosture != ProbeNetworkPosture.NetworkIsolated ||
                    !s.OperatorConfirmedIsolation || !s.NetworkIsolationAccepted || !s.RdpPolicyDenied ||
                    !s.TermServiceStopped || !s.RdpListenersAbsent || !s.FirewallObservationComplete ||
                    String.IsNullOrEmpty(s.NetworkFingerprint))) ||
                (version == 5 && (s.NetworkPosture != ProbeNetworkPosture.ExternalNetworkIsolated ||
                    !s.OperatorConfirmedIsolation || !s.BoundaryAccepted || !s.BoundaryRdpAccepted || !s.RdpPolicyDenied ||
                    !s.TermServiceStopped || !s.RdpListenersAbsent || !s.FirewallObservationComplete ||
                    String.IsNullOrEmpty(s.NetworkFingerprint))) ||
                String.IsNullOrEmpty(s.AccountBinding) || String.IsNullOrEmpty(s.RdpRegistryFingerprint) ||
                String.IsNullOrEmpty(s.ListenerFingerprint) || String.IsNullOrEmpty(s.FirewallFingerprint) ||
                String.IsNullOrEmpty(s.DisplayFingerprint) || String.IsNullOrEmpty(s.NativeResourceFingerprint) ||
                String.IsNullOrEmpty(s.SessionInventoryFingerprint))
                throw new InvalidDataException("Malformed probe prerequisite snapshot.");
            return s;
        }
    }

    internal static byte[] JournalBytes(ProbeJournal journal)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(journal.Plan.Original.FormatVersion); writer.Write((int)journal.Stage); writer.Write(journal.ActiveParentId);
            writer.Write(journal.ActiveParentLogonTime); writer.Write(journal.PositiveChild.HasValue);
            if (journal.PositiveChild.HasValue)
            { writer.Write(journal.PositiveChild.Value.SessionId); writer.Write(journal.PositiveChild.Value.LogonTime); }
            writer.Write(journal.ConsoleConfirmed); writer.Write(journal.ConnectionAttempted);
            writer.Write(journal.AuthenticationOutcome);
            writer.Write(journal.ErrorCode);
            if (journal.Plan.Original.FormatVersion >= 4)
            {
                writer.Write(journal.NetworkDeviationObserved);
                writer.Write(journal.NetworkDeviationFingerprint ?? "");
                writer.Write(journal.NetworkDeviationReason ?? "");
                writer.Write(journal.NetworkRecoveryReviewed);
            }
            if (journal.Plan.Original.FormatVersion >= 5)
                writer.Write(journal.ReviewedChildTeardown);
            writer.Flush(); return stream.ToArray();
        }
    }

    internal static void ReadJournal(byte[] data, ProbeJournal journal)
    {
        using (var stream = new MemoryStream(data))
        using (var reader = new BinaryReader(stream, Encoding.UTF8))
        {
            if (reader.ReadInt32() != journal.Plan.Original.FormatVersion)
                throw new InvalidDataException("Unsupported probe journal version.");
            journal.Stage = (ProbeStage)reader.ReadInt32();
            if (!Enum.IsDefined(typeof(ProbeStage), journal.Stage)) throw new InvalidDataException("Invalid probe stage.");
            journal.ActiveParentId = reader.ReadUInt32(); journal.ActiveParentLogonTime = reader.ReadInt64();
            if (reader.ReadBoolean()) journal.PositiveChild = new ChildSessionIdentity(reader.ReadUInt32(), reader.ReadInt64());
            journal.ConsoleConfirmed = reader.ReadBoolean(); journal.ConnectionAttempted = reader.ReadBoolean();
            journal.AuthenticationOutcome = reader.ReadString();
            journal.ErrorCode = reader.ReadInt32();
            if (journal.Plan.Original.FormatVersion >= 4)
            {
                journal.NetworkDeviationObserved = reader.ReadBoolean();
                journal.NetworkDeviationFingerprint = reader.ReadString();
                journal.NetworkDeviationReason = reader.ReadString();
                journal.NetworkRecoveryReviewed = reader.ReadBoolean();
                if (journal.NetworkRecoveryReviewed && !journal.NetworkDeviationObserved ||
                    journal.NetworkDeviationObserved && String.IsNullOrEmpty(journal.NetworkDeviationReason))
                    throw new InvalidDataException("Inconsistent network recovery snapshot.");
            }
            // Published v5 journals may lack this tail. V6 requires it so
            // reviewed exact-child recovery is always represented durably.
            if (journal.Plan.Original.FormatVersion == 6 && stream.Position == stream.Length)
                throw new InvalidDataException("Missing v6 reviewed child teardown field.");
            if (journal.Plan.Original.FormatVersion >= 5 && stream.Position < stream.Length)
                journal.ReviewedChildTeardown = reader.ReadBoolean();
            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing probe journal data.");
            if (journal.ActiveParentId == uint.MaxValue || journal.ActiveParentLogonTime <= 0 ||
                (journal.PositiveChild.HasValue &&
                    (journal.PositiveChild.Value.SessionId == uint.MaxValue ||
                     journal.PositiveChild.Value.SessionId == journal.ActiveParentId ||
                     journal.PositiveChild.Value.LogonTime <= 0)) ||
                ((journal.Stage == ProbeStage.Connected || journal.Stage == ProbeStage.TeardownPrepared ||
                  journal.Stage == ProbeStage.ChildEnded) && !journal.PositiveChild.HasValue) ||
                (journal.Stage == ProbeStage.Connected && journal.AuthenticationOutcome != "AutomaticLogon") ||
                (journal.Stage == ProbeStage.Connected && !journal.ConnectionAttempted) ||
                (journal.Stage == ProbeStage.ChildEnded && !journal.ConsoleConfirmed &&
                 !journal.ReviewedChildTeardown) ||
                journal.ReviewedChildTeardown &&
                    (journal.Plan.Original.FormatVersion != 5 && journal.Plan.Original.FormatVersion != 6 ||
                     !journal.ConnectionAttempted ||
                     !journal.PositiveChild.HasValue ||
                     (journal.Stage != ProbeStage.TeardownPrepared &&
                      journal.Stage != ProbeStage.ChildEnded && journal.Stage != ProbeStage.Restoring &&
                      journal.Stage != ProbeStage.Restored && journal.Stage != ProbeStage.Conflict)))
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
            !(op.Original.ValueType == "ProbePlanV3" && op.Desired.ValueType == "ProbeProgressV3" ||
              op.Original.ValueType == "ProbePlanV4" && op.Desired.ValueType == "ProbeProgressV4" ||
              op.Original.ValueType == "ProbePlanV5" && op.Desired.ValueType == "ProbeProgressV5" ||
              op.Original.ValueType == "ProbePlanV6" && op.Desired.ValueType == "ProbeProgressV6") ||
            raw.PlanHash != ProbeCodec.Hash(op.Original.Data))
            throw new InvalidDataException("Probe plan integrity failed.");
        var plan = new ProbePlan { Original = ProbeCodec.ReadPlan(op.Original.Data), Hash = raw.PlanHash };
        if (op.Original.ValueType != "ProbePlanV" + plan.Original.FormatVersion)
            throw new InvalidDataException("Probe plan type/version mismatch.");
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
                Original = new ResourceState { Access = ResourceAccess.Accessible,
                    ValueType = "ProbePlanV" + journal.Plan.Original.FormatVersion, Data = planData },
                Desired = new ResourceState { Access = ResourceAccess.Accessible,
                    ValueType = "ProbeProgressV" + journal.Plan.Original.FormatVersion,
                    Data = ProbeCodec.JournalBytes(journal) },
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

    private static bool IsIsolated(ProbeNetworkPosture posture)
    { return posture == ProbeNetworkPosture.NetworkIsolated || posture == ProbeNetworkPosture.ExternalNetworkIsolated; }

    private static bool StageBPosture(ProbeSnapshot original)
    { return original.NetworkPosture == ProbeNetworkPosture.ConnectedRdpGuard && original.FormatVersion == 3 ||
        original.NetworkPosture == ProbeNetworkPosture.ExternalNetworkIsolated && original.FormatVersion == 5 ||
        original.NetworkPosture == ProbeNetworkPosture.NetworkIsolated && original.FormatVersion == 6; }

    private static bool IsolationAccepted(ProbeSnapshot snapshot, ProbeNetworkPosture posture)
    { return snapshot != null && (posture == ProbeNetworkPosture.NetworkIsolated
        ? snapshot.NetworkIsolationAccepted : posture == ProbeNetworkPosture.ExternalNetworkIsolated && snapshot.BoundaryAccepted); }

    private ProbeSnapshot CaptureFor(ProbeNetworkPosture posture, bool confirmation)
    { return posture == ProbeNetworkPosture.ExternalNetworkIsolated
        ? host.CaptureBoundary(confirmation) : host.Capture(); }

    private static void ValidateInitial(ProbeSnapshot s, ProbeNetworkPosture posture, bool isolationConfirmed)
    {
        Require(s != null && s.FeatureAccess == ResourceAccess.Accessible && s.ParentSessionId != uint.MaxValue &&
            s.ParentSessionId == s.ConsoleSessionId && s.ParentProtocolType == 0 && s.ParentLogonTime > 0 &&
            s.Edition == "Professional" && s.WindowsBuild >= 22000 &&
            ProbeCodec.PreFeatureChildGate(s) && !String.IsNullOrEmpty(s.AccountBinding) &&
            !String.IsNullOrEmpty(s.RdpRegistryFingerprint) && !String.IsNullOrEmpty(s.ListenerFingerprint) &&
            !String.IsNullOrEmpty(s.FirewallFingerprint) && !String.IsNullOrEmpty(s.DisplayFingerprint) &&
            !String.IsNullOrEmpty(s.NativeResourceFingerprint) &&
            !String.IsNullOrEmpty(s.SessionInventoryFingerprint),
            "The Windows 11 Pro console, child feature, session, or closed-RDP prerequisites are uncertain.");
        if (posture == ProbeNetworkPosture.ConnectedRdpGuard)
            Require(s.LocalRdpPostureAccepted,
                "Observed local RDP posture is not acceptable: a listener, service, policy, firewall rule, or required reading blocks the plan.");
        else
            Require(IsIsolated(posture) && isolationConfirmed &&
                !s.FeatureEnabled && IsolationAccepted(s, posture) &&
                (posture != ProbeNetworkPosture.ExternalNetworkIsolated || s.BoundaryRdpAccepted) &&
                !String.IsNullOrEmpty(s.NetworkFingerprint) &&
                s.RdpPolicyDenied && s.TermServiceStopped && s.RdpListenersAbsent &&
                s.FirewallObservationComplete,
                "Physical isolation confirmation, independent network isolation, or the unchanged RDP baseline is missing.");
    }

    private void RecordNetworkDeviation(ProbeJournal journal, ProbeSnapshot current, string reason)
    {
        journal.NetworkDeviationObserved = true;
        journal.NetworkRecoveryReviewed = false;
        journal.NetworkDeviationFingerprint = current == null ? "" : current.NetworkFingerprint ?? "";
        journal.NetworkDeviationReason = reason;
        store.Save(journal);
    }

    private ProbeSnapshot CaptureForJournal(ProbeJournal journal, bool confirmation)
    {
        try { return CaptureFor(journal.Plan.Original.NetworkPosture, confirmation); }
        catch (Exception ex)
        {
            if (IsIsolated(journal.Plan.Original.NetworkPosture))
                RecordNetworkDeviation(journal, null, "BoundaryCaptureFailed:" + ex.GetType().Name);
            throw;
        }
    }

    private void ValidateUnchanged(ProbeJournal journal, ProbeSnapshot current)
    {
        if (IsIsolated(journal.Plan.Original.NetworkPosture))
        {
            bool isolated = IsolationAccepted(current, journal.Plan.Original.NetworkPosture);
            bool same = isolated && current.NetworkFingerprint == journal.Plan.Original.NetworkFingerprint;
            if (!same)
            {
                RecordNetworkDeviation(journal, current,
                    isolated ? "NetworkFingerprintDrift" : "NetworkIsolationLostOrUnknown");
                throw new InvalidOperationException("Network isolation or its approved fingerprint changed; progression stopped.");
            }
            Require(!journal.NetworkDeviationObserved,
                "A network deviation requires reviewed recovery; progression is forbidden.");
            Require(current.FeatureAccess == ResourceAccess.Accessible &&
                current.ParentSessionId == current.ConsoleSessionId &&
                current.RdpPolicyDenied && current.TermServiceStopped && current.RdpListenersAbsent &&
                (journal.Plan.Original.NetworkPosture != ProbeNetworkPosture.ExternalNetworkIsolated || current.BoundaryRdpAccepted) &&
                current.FirewallObservationComplete && current.AccountBinding == journal.Plan.Original.AccountBinding &&
                current.ParentProtocolType == 0 &&
                current.InfrastructureFingerprint() == journal.Plan.Original.InfrastructureFingerprint(),
                "RDP, service, listener, firewall, display, native resources, or account drifted.");
            return;
        }
        Require(current != null && current.FeatureAccess == ResourceAccess.Accessible &&
            current.AccountBinding == journal.Plan.Original.AccountBinding && current.ParentProtocolType == 0 &&
            current.LocalRdpPostureAccepted && current.InfrastructureFingerprint() == journal.Plan.Original.InfrastructureFingerprint(),
            "RDP, display, native resources, account, or feature observation drifted.");
    }

    internal ProbePlan Plan(ProbeNetworkPosture posture = ProbeNetworkPosture.ConnectedRdpGuard,
        bool operatorConfirmedIsolation = false)
    {
        // Planning must leave no lock file or journal on the host.
        ProbeSnapshot s = CaptureFor(posture, operatorConfirmedIsolation);
        ValidateInitial(s, posture, operatorConfirmedIsolation);
        if (IsIsolated(posture))
        {
            s.FormatVersion = posture == ProbeNetworkPosture.NetworkIsolated ? 6 : 5;
            s.NetworkPosture = posture;
            s.OperatorConfirmedIsolation = operatorConfirmedIsolation;
        }
        return new ProbePlan { Original = s, Hash = ProbeCodec.Hash(ProbeCodec.PlanBytes(s)) };
    }

    internal ProbeJournal Begin(ProbePlan plan, string approvedHash, bool explicitConsent)
    {
        using (owner.Acquire())
        {
            Require(explicitConsent && plan != null && plan.Hash == approvedHash &&
                plan.Hash == ProbeCodec.Hash(ProbeCodec.PlanBytes(plan.Original)), "Explicit approval for the exact probe plan is required.");
            Require(store.Load() == null, "A probe journal already exists; recover it before starting again.");
            ProbeSnapshot current = CaptureFor(plan.Original.NetworkPosture, plan.Original.OperatorConfirmedIsolation);
            ValidateInitial(current, plan.Original.NetworkPosture, plan.Original.OperatorConfirmedIsolation);
            if (IsIsolated(plan.Original.NetworkPosture))
            {
                current.FormatVersion = plan.Original.FormatVersion;
                current.NetworkPosture = plan.Original.NetworkPosture;
                current.OperatorConfirmedIsolation = plan.Original.OperatorConfirmedIsolation;
            }
            Require(ProbeCodec.Hash(ProbeCodec.PlanBytes(current)) == plan.Hash, "The approved probe inventory is stale.");
            var journal = new ProbeJournal { Plan = plan, Stage = ProbeStage.Captured,
                ActiveParentId = current.ParentSessionId, ActiveParentLogonTime = current.ParentLogonTime };
            store.Save(journal); return journal;
        }
    }

    internal ProbeJournal PrepareFeature(bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal(); Require(j.Stage == ProbeStage.Captured, "Feature preparation is not available in this stage.");
            Require(!IsIsolated(j.Plan.Original.NetworkPosture) || operatorConfirmedIsolation,
                "Isolated feature enablement requires renewed physical isolation confirmation.");
            ProbeSnapshot s = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == j.ActiveParentId && s.ParentLogonTime == j.ActiveParentLogonTime &&
                ProbeCodec.PreFeatureChildGate(s) && s.SessionInventoryFingerprint == j.Plan.Original.SessionInventoryFingerprint &&
                s.FeatureEnabled == j.Plan.Original.FeatureEnabled,
                "Parent, child, or child-feature state changed before preparation.");
            if (!s.FeatureEnabled)
            {
                Require(host.HasAdministratorPrivilege, "Administrator privilege is required for child-feature change; no escalation is attempted.");
                j.Stage = ProbeStage.PreparedEnable; store.Save(j);
                Require(host.CompareExchangeChildFeature(false, true), "Child-feature enablement did not match the recorded original.");
                ProbeSnapshot verified = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, verified);
                Require(verified.FeatureEnabled && verified.IndependentNoUnexpectedSessions &&
                    !verified.AssociatedChild.HasValue &&
                    verified.ParentSessionId == j.ActiveParentId && verified.ParentLogonTime == j.ActiveParentLogonTime,
                    "Child-feature enablement could not be verified.");
            }
            j.Stage = ProbeStage.AwaitFreshParent; store.Save(j); return j;
        }
    }

    internal ProbeJournal ResumeAfterFreshLogon(bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal(); Require(j.Stage == ProbeStage.AwaitFreshParent, "No fresh-parent boundary is pending.");
            Require(!IsIsolated(j.Plan.Original.NetworkPosture) || operatorConfirmedIsolation,
                "Isolated fresh-logon verification requires renewed physical isolation confirmation.");
            ProbeSnapshot s = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == s.ConsoleSessionId && s.ParentLogonTime != j.Plan.Original.ParentLogonTime &&
                s.ParentLogonTime > 0 && s.FeatureEnabled && s.IndependentNoUnexpectedSessions && !s.AssociatedChild.HasValue,
                "A fresh parent console logon without an unexpected session is required.");
            j.ActiveParentId = s.ParentSessionId; j.ActiveParentLogonTime = s.ParentLogonTime;
            j.Stage = s.ChildAccess == ResourceAccess.Absent && s.ChildApiErrorCode == 0
                ? ProbeStage.StageAValidated : ProbeStage.StageAQueryUnknown;
            store.Save(j); return j;
        }
    }

    internal ProbeJournal ApproveStageB(string approvedHash, bool explicitConsent,
        bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(StageBPosture(j.Plan.Original) &&
                j.Stage == ProbeStage.StageAValidated && explicitConsent && j.Plan.Hash == approvedHash,
                "Stage B requires separate consent for the exact Stage A plan.");
            Require(!IsIsolated(j.Plan.Original.NetworkPosture) || operatorConfirmedIsolation,
                "Stage B requires renewed physical isolation confirmation.");
            ProbeSnapshot s = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == j.ActiveParentId && s.ParentLogonTime == j.ActiveParentLogonTime &&
                s.ParentSessionId == s.ConsoleSessionId && s.FeatureEnabled &&
                s.ChildAccess == ResourceAccess.Absent && s.ChildApiErrorCode == 0 &&
                s.IndependentNoUnexpectedSessions && !s.AssociatedChild.HasValue,
                "Stage B requires a fresh positive API no-child result and independent session evidence.");
            j.Stage = ProbeStage.ReadyConnect; store.Save(j); return j;
        }
    }

    internal ProbeJournal ConnectOnce(bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(StageBPosture(j.Plan.Original) &&
                j.Stage == ProbeStage.ReadyConnect, "The one connection attempt is unavailable.");
            Require(!IsIsolated(j.Plan.Original.NetworkPosture) || operatorConfirmedIsolation,
                "Stage B connection requires renewed physical isolation confirmation.");
            ProbeSnapshot before = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, before);
            Require(before.ParentSessionId == j.ActiveParentId && before.ParentLogonTime == j.ActiveParentLogonTime &&
                before.FeatureEnabled && before.ChildAccess == ResourceAccess.Absent && before.ChildApiErrorCode == 0 &&
                before.IndependentNoUnexpectedSessions && !before.AssociatedChild.HasValue,
                "Parent or child changed before connection.");
            j.ConnectionAttempted = true; j.Stage = ProbeStage.Connecting; store.Save(j);
            object journalGate = new object();
            Action observeBoundary = () =>
            {
                lock (journalGate)
                {
                    ProbeSnapshot observed = CaptureForJournal(j, operatorConfirmedIsolation);
                    ValidateUnchanged(j, observed);
                    Require(observed.ParentSessionId == j.ActiveParentId &&
                        observed.ParentLogonTime == j.ActiveParentLogonTime && observed.FeatureEnabled &&
                        (observed.ChildAccess == ResourceAccess.Absent &&
                            observed.IndependentNoUnexpectedSessions && !observed.AssociatedChild.HasValue ||
                         observed.ChildAccess == ResourceAccess.Accessible &&
                            observed.IndependentOnlyAssociatedChild && observed.AssociatedChild.HasValue &&
                            (!j.PositiveChild.HasValue ||
                             j.PositiveChild.Value.Equals(observed.AssociatedChild.Value))),
                        "Unexpected parent, child, or session during the viewer test.");
                }
            };
            Action<ChildSessionIdentity> observedChild = identity =>
            {
                lock (journalGate)
                {
                    ProbeSnapshot observed = CaptureForJournal(j, operatorConfirmedIsolation);
                    ValidateUnchanged(j, observed);
                    Require(observed.ParentSessionId == j.ActiveParentId &&
                        observed.ParentLogonTime == j.ActiveParentLogonTime && observed.FeatureEnabled &&
                        observed.ChildAccess == ResourceAccess.Accessible &&
                        observed.IndependentOnlyAssociatedChild && observed.AssociatedChild.HasValue &&
                        observed.AssociatedChild.Value.Equals(identity) &&
                        identity.SessionId != j.ActiveParentId && identity.LogonTime > 0,
                        "The connected viewer does not have one exact parent-associated child.");
                    Require(!j.PositiveChild.HasValue || j.PositiveChild.Value.Equals(identity),
                        "The connected child identity changed.");
                    j.PositiveChild = identity;
                    j.AuthenticationOutcome = "AutomaticLogonObserved";
                    store.Save(j);
                }
            };
            try
            {
                ProbeConnectionResult result = host.ConnectWithoutPassword(observeBoundary, observedChild);
                ProbeSnapshot after = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, after);
                Require(result != null, "The connection result is missing; the attempt is unresolved.");
                j.ErrorCode = result.ErrorCode; j.AuthenticationOutcome = result.Outcome.ToString();
                bool verifiedChild = after.ParentSessionId == j.ActiveParentId &&
                    after.ParentLogonTime == j.ActiveParentLogonTime &&
                    after.ChildAccess == ResourceAccess.Accessible && after.IndependentOnlyAssociatedChild &&
                    result.Identity.HasValue && j.PositiveChild.HasValue && after.AssociatedChild.HasValue &&
                    result.Identity.Value.Equals(after.AssociatedChild.Value) &&
                    result.Identity.Value.Equals(j.PositiveChild.Value) &&
                    result.Identity.Value.SessionId != before.ParentSessionId && result.Identity.Value.LogonTime > 0;
                j.Stage = result.Outcome == ProbeConnectOutcome.AutomaticLogon && verifiedChild
                    ? ProbeStage.Connected : ProbeStage.OutcomeUnknown;
                store.Save(j); return j;
            }
            catch (Exception ex)
            {
                j.Stage = ProbeStage.OutcomeUnknown; j.ErrorCode = ex.HResult;
                j.AuthenticationOutcome = "Exception:" + ex.GetType().Name;
                store.Save(j); throw;
            }
        }
    }

    internal ProbeJournal ConfirmConsoleUsable(bool operatorConfirmed,
        bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(StageBPosture(j.Plan.Original) &&
                operatorConfirmed && j.PositiveChild.HasValue &&
                (j.Stage == ProbeStage.Connected || j.Stage == ProbeStage.OutcomeUnknown),
                "Physical-console usability needs an explicit operator checkpoint.");
            Require(!IsIsolated(j.Plan.Original.NetworkPosture) || operatorConfirmedIsolation,
                "Interaction confirmation requires renewed physical isolation confirmation.");
            ProbeSnapshot s = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == s.ConsoleSessionId && s.ChildAccess == ResourceAccess.Accessible &&
                s.IndependentOnlyAssociatedChild && s.AssociatedChild.HasValue &&
                s.AssociatedChild.Value.Equals(j.PositiveChild.Value), "Console or child identity changed.");
            j.ConsoleConfirmed = true; store.Save(j); return j;
        }
    }

    internal ProbeJournal EndPositiveChild(bool explicitConsent,
        bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(StageBPosture(j.Plan.Original) &&
                explicitConsent && j.ConsoleConfirmed && j.PositiveChild.HasValue &&
                (j.Stage == ProbeStage.Connected || j.Stage == ProbeStage.OutcomeUnknown),
                "Only a positively identified test child may be ended with explicit consent.");
            Require(!IsIsolated(j.Plan.Original.NetworkPosture) || operatorConfirmedIsolation,
                "Child teardown requires renewed physical isolation confirmation.");
            ProbeSnapshot before = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, before);
            Require(before.ParentSessionId == j.ActiveParentId && before.ParentLogonTime == j.ActiveParentLogonTime &&
                before.ChildAccess == ResourceAccess.Accessible && before.IndependentOnlyAssociatedChild &&
                before.AssociatedChild.HasValue &&
                before.AssociatedChild.Value.Equals(j.PositiveChild.Value),
                "The parent-associated child identity changed; logoff is forbidden.");
            j.Stage = ProbeStage.TeardownPrepared; store.Save(j);
            // TeardownPrepared remains durable on any exception; never automatically repeat logoff.
            bool result = host.LogoffExact(j.PositiveChild.Value);
            ProbeSnapshot after = CaptureForJournal(j, operatorConfirmedIsolation); ValidateUnchanged(j, after);
            j.Stage = result && after.ParentSessionId == j.ActiveParentId &&
                after.ParentLogonTime == j.ActiveParentLogonTime &&
                after.ChildAccess == ResourceAccess.Absent && after.IndependentNoUnexpectedSessions &&
                !after.AssociatedChild.HasValue
                ? ProbeStage.ChildEnded : ProbeStage.TeardownPrepared;
            store.Save(j); return j;
        }
    }

    internal ProbeJournal ReconcileInterruptedConnection(bool operatorConfirmedIsolation)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(IsIsolated(j.Plan.Original.NetworkPosture) && StageBPosture(j.Plan.Original) &&
                operatorConfirmedIsolation && j.Stage == ProbeStage.Connecting &&
                j.ConnectionAttempted && j.PositiveChild.HasValue,
                "Only a durably identified interrupted isolated connection can be reconciled.");
            ProbeSnapshot s = CaptureForJournal(j, true); ValidateUnchanged(j, s);
            Require(s.ParentSessionId == j.ActiveParentId && s.ParentLogonTime == j.ActiveParentLogonTime &&
                s.ChildAccess == ResourceAccess.Accessible && s.IndependentOnlyAssociatedChild &&
                s.AssociatedChild.HasValue && s.AssociatedChild.Value.Equals(j.PositiveChild.Value),
                "The interrupted viewer's exact child is not independently present.");
            j.Stage = ProbeStage.OutcomeUnknown;
            j.AuthenticationOutcome = "InterruptedAfterIdentity";
            store.Save(j); return j;
        }
    }

    internal ProbeJournal EndPositiveChildReviewed(bool explicitConsent, bool operatorConfirmedIsolation)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(IsIsolated(j.Plan.Original.NetworkPosture) && StageBPosture(j.Plan.Original) &&
                explicitConsent && operatorConfirmedIsolation && j.ConnectionAttempted &&
                j.PositiveChild.HasValue &&
                (j.Stage == ProbeStage.Connecting || j.Stage == ProbeStage.Connected ||
                 j.Stage == ProbeStage.OutcomeUnknown),
                "Reviewed teardown requires a durably identified test child and separate consent.");
            ProbeSnapshot before = CaptureForJournal(j, true);
            Require(IsolationAccepted(before, j.Plan.Original.NetworkPosture) &&
                (j.Plan.Original.NetworkPosture != ProbeNetworkPosture.NetworkIsolated ||
                 before.NetworkFingerprint == j.Plan.Original.NetworkFingerprint) &&
                before.FeatureAccess == ResourceAccess.Accessible &&
                before.FeatureEnabled && before.RdpPolicyDenied && before.FirewallObservationComplete &&
                before.AccountBinding == j.Plan.Original.AccountBinding &&
                before.ParentSessionId == j.ActiveParentId &&
                before.ParentSessionId == before.ConsoleSessionId && before.ParentProtocolType == 0 &&
                before.ParentLogonTime == j.ActiveParentLogonTime &&
                before.ChildAccess == ResourceAccess.Accessible &&
                before.IndependentOnlyAssociatedChild && before.AssociatedChild.HasValue &&
                before.AssociatedChild.Value.Equals(j.PositiveChild.Value),
                "Reviewed teardown lacks the approved isolation or the exact child identity.");
            j.ReviewedChildTeardown = true;
            j.Stage = ProbeStage.TeardownPrepared; store.Save(j);
            bool result = host.LogoffExact(j.PositiveChild.Value);
            ProbeSnapshot after = CaptureForJournal(j, true);
            j.Stage = result && IsolationAccepted(after, j.Plan.Original.NetworkPosture) &&
                (j.Plan.Original.NetworkPosture != ProbeNetworkPosture.NetworkIsolated ||
                 after.NetworkFingerprint == j.Plan.Original.NetworkFingerprint) &&
                after.AccountBinding == j.Plan.Original.AccountBinding &&
                after.ParentSessionId == j.ActiveParentId &&
                after.ParentLogonTime == j.ActiveParentLogonTime &&
                after.ChildAccess == ResourceAccess.Absent && after.ChildApiErrorCode == 0 &&
                after.IndependentNoUnexpectedSessions && !after.AssociatedChild.HasValue
                ? ProbeStage.ChildEnded : ProbeStage.TeardownPrepared;
            store.Save(j); return j;
        }
    }

    internal ProbeJournal RestoreOriginal(bool acknowledgeAmbiguousFeatureMutation = false,
        bool acknowledgeNetworkDeviation = false, bool operatorConfirmedIsolation = false)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            ProbeSnapshot s = CaptureForJournal(j, operatorConfirmedIsolation);
            if (IsIsolated(j.Plan.Original.NetworkPosture))
            {
                Require(operatorConfirmedIsolation,
                    "Isolated restoration requires renewed physical isolation confirmation.");
                bool isolated = IsolationAccepted(s, j.Plan.Original.NetworkPosture);
                if (!isolated || s.NetworkFingerprint != j.Plan.Original.NetworkFingerprint)
                    RecordNetworkDeviation(j, s,
                        isolated ? "NetworkFingerprintDrift" : "NetworkIsolationLostOrUnknown");
                Require(isolated, "Network isolation is lost or unknown; feature restoration is blocked.");
                Require(!j.NetworkDeviationObserved || acknowledgeNetworkDeviation && operatorConfirmedIsolation,
                    "Recorded network deviation requires explicit reviewed recovery and renewed physical isolation confirmation.");
                if (j.NetworkDeviationObserved)
                {
                    Require(s.RdpPolicyDenied && s.FirewallObservationComplete &&
                        s.AccountBinding == j.Plan.Original.AccountBinding &&
                        s.ParentSessionId == s.ConsoleSessionId && s.ParentProtocolType == 0,
                        "Reviewed network recovery lacks the original RDP policy, firewall reading, or console identity.");
                    j.NetworkRecoveryReviewed = true; store.Save(j);
                }
            }
            Require(RecoveryCanExcludeChild(j, s),
                "A child or an unexpected session may exist; restoration is blocked.");
            if (j.Stage == ProbeStage.Restored)
            {
                Require(s.FeatureEnabled == j.Plan.Original.FeatureEnabled && InfrastructureUnchanged(j, s),
                    "The previously restored state drifted.");
                return j;
            }
            if (s.FeatureEnabled != j.Plan.Original.FeatureEnabled)
            {
                Require(j.Stage != ProbeStage.Captured &&
                    (j.Stage != ProbeStage.PreparedEnable || acknowledgeAmbiguousFeatureMutation),
                    "The feature changed during an unverified enable intent; explicit recovery review is required.");
                Require(j.Plan.NeedsEnable && s.FeatureEnabled && host.HasAdministratorPrivilege,
                    "Feature state drifted or Administrator privilege is missing; no escalation is attempted.");
                j.Stage = ProbeStage.Restoring; store.Save(j);
                Require(host.CompareExchangeChildFeature(true, false), "Child-feature restoration did not match expected state.");
                s = CaptureForJournal(j, operatorConfirmedIsolation);
                Require(RecoveryCanExcludeChild(j, s) && !s.FeatureEnabled,
                    "Child-feature restoration or session absence was not verified.");
            }
            if (IsIsolated(j.Plan.Original.NetworkPosture) &&
                (!IsolationAccepted(s, j.Plan.Original.NetworkPosture) || s.NetworkFingerprint != j.Plan.Original.NetworkFingerprint))
                RecordNetworkDeviation(j, s, IsolationAccepted(s, j.Plan.Original.NetworkPosture) ?
                    "NetworkFingerprintDriftAfterRestore" : "NetworkIsolationLostAfterRestore");
            j.Stage = InfrastructureUnchanged(j, s) ? ProbeStage.Restored : ProbeStage.Conflict;
            store.Save(j);
            Require(j.Stage == ProbeStage.Restored,
                "Feature restoration was verified, but another original-state observation drifted.");
            return j;
        }
    }

    private static bool InfrastructureUnchanged(ProbeJournal j, ProbeSnapshot s)
    {
        if (s == null || s.InfrastructureFingerprint() != j.Plan.Original.InfrastructureFingerprint()) return false;
        if (IsIsolated(j.Plan.Original.NetworkPosture))
            return IsolationAccepted(s, j.Plan.Original.NetworkPosture) &&
                s.NetworkFingerprint == j.Plan.Original.NetworkFingerprint &&
                s.RdpPolicyDenied && s.TermServiceStopped && s.RdpListenersAbsent &&
                (j.Plan.Original.NetworkPosture != ProbeNetworkPosture.ExternalNetworkIsolated || s.BoundaryRdpAccepted) &&
                s.FirewallObservationComplete;
        return s.LocalRdpPostureAccepted;
    }

    internal ProbeReconnectAssessment AssessReconnect(bool operatorConfirmedIsolation)
    {
        using (owner.Acquire())
        {
            ProbeJournal j = RequiredJournal();
            Require(IsIsolated(j.Plan.Original.NetworkPosture),
                "Reconnect assessment applies only to an isolated Stage A plan.");
            Require(operatorConfirmedIsolation,
                "Reconnect assessment requires renewed physical isolation confirmation.");
            ProbeSnapshot s = CaptureForJournal(j, operatorConfirmedIsolation);
            bool sameNetwork = IsolationAccepted(s, j.Plan.Original.NetworkPosture) &&
                s.NetworkFingerprint == j.Plan.Original.NetworkFingerprint;
            if (!sameNetwork)
                RecordNetworkDeviation(j, s, IsolationAccepted(s, j.Plan.Original.NetworkPosture) ?
                    "NetworkFingerprintDriftAtReconnectCheck" : "NetworkIsolationLostAtReconnectCheck");
            var result = new ProbeReconnectAssessment {
                FeatureRestored = s != null && s.FeatureAccess == ResourceAccess.Accessible &&
                    s.FeatureEnabled == j.Plan.Original.FeatureEnabled,
                ChildExcluded = RecoveryCanExcludeChild(j, s),
                NetworkIsolated = sameNetwork,
                RdpPolicyDenied = s != null && s.RdpPolicyDenied &&
                    s.RdpRegistryFingerprint == j.Plan.Original.RdpRegistryFingerprint,
                TermServiceStopped = s != null && s.TermServiceStopped,
                RdpListenersAbsent = s != null && s.RdpListenersAbsent &&
                    s.ListenerFingerprint == j.Plan.Original.ListenerFingerprint,
                InfrastructureRestored = InfrastructureUnchanged(j, s),
                JournalRestored = j.Stage == ProbeStage.Restored &&
                    (!j.NetworkDeviationObserved || j.NetworkRecoveryReviewed)
            };
            return result;
        }
    }

    private static bool RecoveryCanExcludeChild(ProbeJournal j, ProbeSnapshot s)
    {
        if (s == null || s.FeatureAccess != ResourceAccess.Accessible ||
            s.AccountBinding != j.Plan.Original.AccountBinding ||
            s.ParentSessionId != s.ConsoleSessionId || s.ParentProtocolType != 0 || !s.IndependentNoUnexpectedSessions ||
            s.AssociatedChild.HasValue) return false;
        bool stageAOnly = !j.ConnectionAttempted;
        return (s.ChildAccess == ResourceAccess.Absent && s.ChildApiErrorCode == 0) ||
            (stageAOnly && s.ChildAccess == ResourceAccess.Unknown && s.ChildApiErrorCode == 1168);
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
