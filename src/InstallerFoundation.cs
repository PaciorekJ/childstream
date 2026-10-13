using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Pure transaction logic. No implementation in this file calls a Windows mutation API.
internal enum ResourceKind { RegistryValue, ChildSessions, FirewallRule, StartupEntry, OwnedFile, Process, SunshineInstall, Port, VddInstall }
internal enum ResourceAccess { Absent, Accessible, Inaccessible, Unknown, Conflicting }
internal enum InstallPrivilege { CurrentUser, Administrator }
internal enum JournalPhase { Planned, Prepared, Applied, Reversing, Reversed, Conflict, Complete, RolledBack }

// Data is the exact raw value/file data, never a rendered or redacted substitute. The
// policy refuses credentials and non-owned registry keys before such data is journaled.
internal sealed class ResourceState
{
    internal ResourceAccess Access;
    internal string ValueType = "";
    internal byte[] Data = new byte[0];
    internal string Owner = "";
    internal SortedDictionary<string, string> Filters = new SortedDictionary<string, string>(StringComparer.Ordinal);

    internal ResourceState Copy()
    {
        var copy = new ResourceState { Access = Access, ValueType = ValueType, Data = (byte[])Data.Clone(), Owner = Owner };
        foreach (var pair in Filters) copy.Filters.Add(pair.Key, pair.Value);
        return copy;
    }

    internal bool Same(ResourceState other)
    {
        return other != null && Convert.ToBase64String(Canonical.Bytes(this)) == Convert.ToBase64String(Canonical.Bytes(other));
    }
}

internal sealed class ResourceTarget
{
    internal ResourceKind Kind;
    internal string Identity;
    internal ResourceTarget(ResourceKind kind, string identity) { Kind = kind; Identity = identity; }
}

internal sealed class InstallOperation
{
    internal ResourceTarget Target;
    internal ResourceState Original;
    internal ResourceState Desired;
    internal InstallPrivilege Privilege;
    internal string OwnershipEvidence;
    internal string Verification;
    internal string Reversal;
}

internal sealed class InstallPlan
{
    internal readonly List<InstallOperation> Operations = new List<InstallOperation>();
    internal string Hash;
}

internal sealed class JournalEntry
{
    internal InstallOperation Operation;
    internal JournalPhase Phase;
}

internal sealed class InstallJournal
{
    internal string PlanHash;
    internal JournalPhase Phase;
    internal readonly List<JournalEntry> Entries = new List<JournalEntry>();
}

internal interface IInstallerHost
{
    ResourceState Read(ResourceTarget target);
    // Adapter must compare exact state at the mutation boundary and refuse drift.
    bool CompareExchange(ResourceTarget target, ResourceState expected, ResourceState desired);
    bool HasPrivilege(InstallPrivilege privilege);
}

internal interface IJournalStore
{
    InstallJournal Load();
    void Save(InstallJournal journal);
    InstallJournal ResolveInterruptedReplacement();
}

internal static class Canonical
{
    internal static byte[] Bytes(ResourceState state)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            WriteState(writer, state);
            writer.Flush();
            return stream.ToArray();
        }
    }

    internal static void WriteState(BinaryWriter writer, ResourceState state)
    {
        writer.Write((int)state.Access);
        writer.Write(state.ValueType ?? "");
        writer.Write(state.Owner ?? "");
        writer.Write(state.Data.Length);
        writer.Write(state.Data);
        writer.Write(state.Filters.Count);
        foreach (var pair in state.Filters) { writer.Write(pair.Key); writer.Write(pair.Value); }
    }

    internal static ResourceState ReadState(BinaryReader reader)
    {
        var state = new ResourceState();
        state.Access = (ResourceAccess)reader.ReadInt32();
        if (!Enum.IsDefined(typeof(ResourceAccess), state.Access)) throw new InvalidDataException("Invalid resource access.");
        state.ValueType = reader.ReadString();
        state.Owner = reader.ReadString();
        int length = reader.ReadInt32();
        if (length < 0 || length > 8 * 1024 * 1024) throw new InvalidDataException("Invalid resource data length.");
        state.Data = reader.ReadBytes(length);
        if (state.Data.Length != length) throw new EndOfStreamException();
        int filters = reader.ReadInt32();
        if (filters < 0 || filters > 64) throw new InvalidDataException("Invalid filter count.");
        for (int i = 0; i < filters; i++) state.Filters.Add(reader.ReadString(), reader.ReadString());
        return state;
    }

    internal static void WriteOperation(BinaryWriter writer, InstallOperation op)
    {
        writer.Write((int)op.Target.Kind); writer.Write(op.Target.Identity);
        WriteState(writer, op.Original); WriteState(writer, op.Desired);
        writer.Write((int)op.Privilege);
        writer.Write(op.OwnershipEvidence); writer.Write(op.Verification); writer.Write(op.Reversal);
    }

    internal static InstallOperation ReadOperation(BinaryReader reader)
    {
        ResourceKind kind = (ResourceKind)reader.ReadInt32();
        if (!Enum.IsDefined(typeof(ResourceKind), kind)) throw new InvalidDataException("Invalid resource kind.");
        var op = new InstallOperation();
        op.Target = new ResourceTarget(kind, reader.ReadString());
        op.Original = ReadState(reader); op.Desired = ReadState(reader);
        op.Privilege = (InstallPrivilege)reader.ReadInt32();
        if (!Enum.IsDefined(typeof(InstallPrivilege), op.Privilege)) throw new InvalidDataException("Invalid privilege.");
        op.OwnershipEvidence = reader.ReadString(); op.Verification = reader.ReadString(); op.Reversal = reader.ReadString();
        return op;
    }

    internal static string Hash(InstallPlan plan)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(1); writer.Write(plan.Operations.Count);
            foreach (var op in plan.Operations) WriteOperation(writer, op);
            writer.Flush();
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream.ToArray())).Replace("-", "").ToLowerInvariant();
        }
    }
}

// Scope is immutable and intentionally excludes global RDP, child-session settings,
// firewall, native Sunshine/VDD, processes, ports, and startup entries.
internal sealed class InstallerPolicy
{
    private readonly string ownedRoot;
    private readonly IJournalPathProbe pathProbe;
    internal InstallerPolicy(string ownedRoot, IJournalPathProbe pathProbe = null)
    {
        if (!Path.IsPathRooted(ownedRoot)) throw new ArgumentException("The owned root must be absolute.");
        this.ownedRoot = Path.GetFullPath(ownedRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        this.pathProbe = pathProbe ?? new RealJournalPathProbe();
        if (Path.GetPathRoot(this.ownedRoot).Equals(this.ownedRoot, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The owned root must be a subdirectory.");
    }

    internal void ValidateTarget(ResourceTarget target)
    {
        if (target == null || String.IsNullOrEmpty(target.Identity))
            throw new InvalidOperationException("Missing resource target.");
        if (target.Kind != ResourceKind.OwnedFile && target.Kind != ResourceKind.RegistryValue)
            throw new InvalidOperationException("The resource class is inventory-only.");
        if (target.Kind == ResourceKind.OwnedFile)
        {
            string path = ValidateCanonicalFilePath(target.Identity, false, pathProbe);
            if (!path.StartsWith(ownedRoot, StringComparison.OrdinalIgnoreCase) ||
                path.IndexOf("vdd", StringComparison.OrdinalIgnoreCase) >= 0)
                throw new InvalidOperationException("File is outside the owned portable installation.");
        }
        if (target.Kind == ResourceKind.RegistryValue &&
            !target.Identity.StartsWith(@"HKCU\Software\ChildStream\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Registry value is outside ChildStream ownership.");
    }

    internal static string ValidateCanonicalFilePath(string candidate, bool allowDirectory = false, IJournalPathProbe probe = null)
    {
        probe = probe ?? new RealJournalPathProbe();
        if (String.IsNullOrEmpty(candidate) || !Path.IsPathRooted(candidate) || candidate.StartsWith(@"\\", StringComparison.Ordinal))
            throw new InvalidOperationException("File path must be a local absolute path.");
        string full = Path.GetFullPath(candidate);
        if (!String.Equals(candidate, full, StringComparison.OrdinalIgnoreCase) ||
            candidate.IndexOf(':', Path.GetPathRoot(full).Length) >= 0)
            throw new InvalidOperationException("File path is noncanonical or uses an alternate data stream.");
        for (string current = full; current != null; current = Path.GetDirectoryName(current))
        {
            try
            {
                FileAttributes attributes = probe.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                    (current == full && !allowDirectory && (attributes & FileAttributes.Directory) != 0))
                    throw new InvalidOperationException("File path crosses a reparse point or targets a directory.");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        return full;
    }

    internal void Validate(InstallOperation op)
    {
        if (op == null || op.Target == null || op.Original == null || op.Desired == null ||
            String.IsNullOrEmpty(op.Target.Identity) || String.IsNullOrEmpty(op.OwnershipEvidence) ||
            String.IsNullOrEmpty(op.Verification) || String.IsNullOrEmpty(op.Reversal))
            throw new InvalidOperationException("Incomplete installation operation.");
        if (op.Original.Access != ResourceAccess.Absent && op.Original.Access != ResourceAccess.Accessible)
            throw new InvalidOperationException("A resource is inaccessible, unknown, or conflicting.");
        if (op.Desired.Access != ResourceAccess.Accessible && op.Desired.Access != ResourceAccess.Absent)
            throw new InvalidOperationException("Invalid desired state.");
        ValidateTarget(op.Target);
        ValidateState(op.Original); ValidateState(op.Desired);
        if (!op.Original.Same(op.Desired) && op.Original.Access == ResourceAccess.Accessible &&
            op.Original.Owner != op.OwnershipEvidence)
            throw new InvalidOperationException("Existing resource is not owned by this transaction.");
        if (!op.Original.Same(op.Desired) && op.Desired.Access == ResourceAccess.Accessible &&
            op.Desired.Owner != op.OwnershipEvidence)
            throw new InvalidOperationException("Desired resource lacks ownership evidence.");
        if (op.Original.Data.Length > 8 * 1024 * 1024 || op.Desired.Data.Length > 8 * 1024 * 1024)
            throw new InvalidOperationException("Resource exceeds journal limit.");
    }

    private static void ValidateState(ResourceState state)
    {
        if (state.Data == null || state.Filters == null ||
            (state.Access == ResourceAccess.Absent &&
             (!String.IsNullOrEmpty(state.ValueType) || state.Data.Length != 0 ||
              !String.IsNullOrEmpty(state.Owner) || state.Filters.Count != 0)) ||
            (state.Access == ResourceAccess.Accessible && String.IsNullOrEmpty(state.ValueType)))
            throw new InvalidOperationException("Malformed resource snapshot.");
    }
}

internal sealed class InstallerEngine
{
    private readonly IInstallerHost host;
    private readonly IJournalStore store;
    private readonly InstallerPolicy policy;
    private readonly ITransactionOwnership ownership;
    internal InstallerEngine(IInstallerHost host, IJournalStore store, InstallerPolicy policy, ITransactionOwnership ownership)
    { this.host = host; this.store = store; this.policy = policy; this.ownership = ownership; }

    internal InstallPlan Plan(IEnumerable<InstallOperation> requested)
    { using (ownership.Acquire()) return PlanOwned(requested); }

    private InstallPlan PlanOwned(IEnumerable<InstallOperation> requested)
    {
        var plan = new InstallPlan();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var requestedOp in requested)
        {
            policy.ValidateTarget(requestedOp.Target);
            var op = new InstallOperation { Target = requestedOp.Target,
                Original = host.Read(requestedOp.Target).Copy(), Desired = requestedOp.Desired.Copy(),
                Privilege = requestedOp.Privilege, OwnershipEvidence = requestedOp.OwnershipEvidence,
                Verification = requestedOp.Verification, Reversal = requestedOp.Reversal };
            policy.Validate(op);
            if (!seen.Add(op.Target.Kind + ":" + op.Target.Identity)) throw new InvalidOperationException("Duplicate target.");
            plan.Operations.Add(op);
        }
        plan.Operations.Sort((a, b) => StringComparer.Ordinal.Compare(a.Target.Kind + ":" + a.Target.Identity,
            b.Target.Kind + ":" + b.Target.Identity));
        plan.Hash = Canonical.Hash(plan);
        return plan;
    }

    internal InstallJournal Apply(InstallPlan plan, string approvedHash)
    { using (ownership.Acquire()) return ApplyOwned(plan, approvedHash); }

    private InstallJournal ApplyOwned(InstallPlan plan, string approvedHash)
    {
        if (plan == null || plan.Hash != Canonical.Hash(plan) || plan.Hash != approvedHash)
            throw new InvalidOperationException("The approved plan hash is absent, stale, or altered.");
        InstallJournal prior = store.Load();
        if (prior != null) ValidateJournal(prior);
        if (prior != null && prior.Phase != JournalPhase.RolledBack)
        {
            if (prior.Phase == JournalPhase.Complete && prior.PlanHash == plan.Hash)
            {
                foreach (var op in plan.Operations)
                    if (!host.Read(op.Target).Same(op.Desired)) throw new InvalidOperationException("Installed state drifted.");
                return prior;
            }
            throw new InvalidOperationException("An existing transaction needs recovery before another Apply.");
        }
        foreach (var op in plan.Operations)
        {
            policy.Validate(op);
            if (!host.HasPrivilege(op.Privilege)) throw new UnauthorizedAccessException("Required privilege is missing.");
            if (!host.Read(op.Target).Same(op.Original)) throw new InvalidOperationException("Plan became stale before Apply.");
        }
        var journal = new InstallJournal { PlanHash = plan.Hash, Phase = JournalPhase.Planned };
        foreach (var op in plan.Operations) journal.Entries.Add(new JournalEntry { Operation = op, Phase = JournalPhase.Planned });
        store.Save(journal); // full original state is durable before the first mutation
        foreach (var entry in journal.Entries)
        {
            if (entry.Operation.Original.Same(entry.Operation.Desired))
            { entry.Phase = JournalPhase.Applied; store.Save(journal); continue; }
            entry.Phase = JournalPhase.Prepared; store.Save(journal);
            if (!host.CompareExchange(entry.Operation.Target, entry.Operation.Original, entry.Operation.Desired))
                throw new InvalidOperationException("Resource changed at the install mutation boundary.");
            if (!host.Read(entry.Operation.Target).Same(entry.Operation.Desired))
                throw new InvalidOperationException("Install postcondition failed.");
            entry.Phase = JournalPhase.Applied; store.Save(journal);
        }
        journal.Phase = JournalPhase.Complete; store.Save(journal);
        return journal;
    }

    internal InstallJournal RecoverOrUninstall()
    { using (ownership.Acquire()) return RecoverOwned(); }

    internal InstallJournal ResolveInterruptedJournal()
    {
        using (ownership.Acquire())
        {
            InstallJournal journal = store.ResolveInterruptedReplacement();
            ValidateJournal(journal);
            return journal;
        }
    }

    private InstallJournal RecoverOwned()
    {
        InstallJournal journal = store.Load();
        if (journal == null) throw new InvalidOperationException("No transaction journal exists.");
        ValidateJournal(journal);
        if (journal.Phase == JournalPhase.RolledBack) return journal;
        if (journal.Phase != JournalPhase.Reversing)
        { journal.Phase = JournalPhase.Reversing; store.Save(journal); }
        for (int i = journal.Entries.Count - 1; i >= 0; i--)
        {
            JournalEntry entry = journal.Entries[i];
            InstallOperation op = entry.Operation;
            ResourceState actual = host.Read(op.Target);
            if (entry.Phase == JournalPhase.Reversed)
            {
                if (!actual.Same(op.Original)) throw Conflict(journal, entry, "A reversed resource drifted.");
                continue;
            }
            if (actual.Same(op.Original))
            { entry.Phase = JournalPhase.Reversed; store.Save(journal); continue; }
            if (!actual.Same(op.Desired) || op.Original.Same(op.Desired) ||
                (entry.Phase != JournalPhase.Prepared && entry.Phase != JournalPhase.Applied &&
                 entry.Phase != JournalPhase.Reversing && entry.Phase != JournalPhase.Conflict))
                throw Conflict(journal, entry, "Resource drifted or was never changed by this transaction.");
            if (!host.HasPrivilege(op.Privilege)) throw new UnauthorizedAccessException("Required reversal privilege is missing.");
            entry.Phase = JournalPhase.Reversing; store.Save(journal);
            if (!host.CompareExchange(op.Target, op.Desired, op.Original))
                throw Conflict(journal, entry, "Resource changed at the reversal mutation boundary.");
            if (!host.Read(op.Target).Same(op.Original)) throw Conflict(journal, entry, "Rollback postcondition failed.");
            entry.Phase = JournalPhase.Reversed; store.Save(journal);
        }
        journal.Phase = JournalPhase.RolledBack; store.Save(journal);
        return journal;
    }

    private Exception Conflict(InstallJournal journal, JournalEntry entry, string reason)
    {
        entry.Phase = JournalPhase.Conflict; journal.Phase = JournalPhase.Conflict; store.Save(journal);
        return new InvalidOperationException(reason + " Inspect " + entry.Operation.Target.Identity + " and retry recovery.");
    }

    private void ValidateJournal(InstallJournal journal)
    {
        var plan = new InstallPlan();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string previous = null;
        foreach (var entry in journal.Entries)
        {
            policy.Validate(entry.Operation);
            if ((journal.Phase == JournalPhase.Complete && entry.Phase != JournalPhase.Applied) ||
                (journal.Phase == JournalPhase.RolledBack && entry.Phase != JournalPhase.Reversed))
                throw new InvalidDataException("Journal phase and entry phase disagree.");
            string key = entry.Operation.Target.Kind + ":" + entry.Operation.Target.Identity;
            if (!seen.Add(key) || (previous != null && StringComparer.Ordinal.Compare(previous, key) > 0))
                throw new InvalidDataException("Journal targets are duplicated or unordered.");
            previous = key;
            plan.Operations.Add(entry.Operation);
        }
        if (journal.PlanHash != Canonical.Hash(plan)) throw new InvalidDataException("Journal plan hash mismatch.");
    }
}

internal enum JournalReadState
{ VerifiedAbsent, Valid, Inaccessible, Corrupt, UnexpectedType, InterruptedReplacement, UnknownConflict }

internal sealed class JournalInspection
{
    internal JournalReadState State;
    internal InstallJournal Journal;
    internal string Detail;
    internal JournalInspection(JournalReadState state, InstallJournal journal, string detail)
    { State = state; Journal = journal; Detail = detail; }
}

internal sealed class JournalStateException : IOException
{
    internal readonly JournalReadState State;
    internal JournalStateException(JournalReadState state, string detail) : base("Journal " + state + ": " + detail)
    { State = state; }
}

internal interface IJournalPathProbe { FileAttributes GetAttributes(string path); }
internal sealed class RealJournalPathProbe : IJournalPathProbe
{ public FileAttributes GetAttributes(string path) { return File.GetAttributes(path); } }
internal enum JournalWriteBoundary { BeforeTemporaryCreate, AfterTemporaryFlush, BeforePublish, AfterPublish }

// One bounded, checksummed snapshot per transition. An interrupted .new file
// blocks Apply and is preserved until explicit repair under transaction ownership.
internal sealed class FileJournalStore : IJournalStore
{
    private const int MaximumJournalBytes = 32 * 1024 * 1024;
    private readonly string path;
    private readonly IJournalPathProbe probe;
    private readonly Action<JournalWriteBoundary> writeFault;
    internal FileJournalStore(string path, IJournalPathProbe probe = null, Action<JournalWriteBoundary> writeFault = null)
    {
        if (!Path.IsPathRooted(path)) throw new ArgumentException("Journal path must be absolute.");
        this.path = Path.GetFullPath(path);
        this.probe = probe ?? new RealJournalPathProbe();
        this.writeFault = writeFault;
    }

    private JournalInspection Result(JournalReadState state, string detail)
    { return new JournalInspection(state, null, detail); }

    private JournalReadState Node(string candidate, bool directory)
    {
        try
        {
            FileAttributes attributes = probe.GetAttributes(candidate);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                ((attributes & FileAttributes.Directory) != 0) != directory)
                return JournalReadState.UnexpectedType;
            return JournalReadState.Valid;
        }
        catch (FileNotFoundException) { return JournalReadState.VerifiedAbsent; }
        catch (DirectoryNotFoundException) { return JournalReadState.VerifiedAbsent; }
        catch (UnauthorizedAccessException) { return JournalReadState.Inaccessible; }
        catch (System.Security.SecurityException) { return JournalReadState.Inaccessible; }
        catch (IOException) { return JournalReadState.UnknownConflict; }
    }

    private JournalReadState ParentState()
    {
        var parents = new Stack<string>();
        for (string current = Path.GetDirectoryName(path); current != null; current = Path.GetDirectoryName(current))
            parents.Push(current);
        while (parents.Count != 0)
        {
            JournalReadState state = Node(parents.Pop(), true);
            if (state != JournalReadState.Valid) return state;
        }
        return JournalReadState.Valid;
    }

    internal JournalInspection Inspect()
    {
        JournalReadState parent = ParentState();
        if (parent != JournalReadState.Valid && parent != JournalReadState.VerifiedAbsent)
            return Result(parent, "Journal directory is not a verified regular directory.");
        JournalReadState main = Node(path, false);
        JournalReadState pending = Node(path + ".new", false);
        foreach (JournalReadState state in new[] { main, pending })
            if (state == JournalReadState.Inaccessible || state == JournalReadState.UnexpectedType ||
                state == JournalReadState.UnknownConflict)
                return Result(state, "Journal or replacement path cannot be trusted.");
        if (pending == JournalReadState.Valid)
        {
            InstallJournal replacement;
            try
            {
                replacement = ReadJournal(path + ".new");
            }
            catch (UnauthorizedAccessException) { return Result(JournalReadState.Inaccessible, "Replacement cannot be read."); }
            catch (System.Security.SecurityException) { return Result(JournalReadState.Inaccessible, "Replacement cannot be read."); }
            catch (InvalidDataException) { return Result(JournalReadState.InterruptedReplacement, "Replacement is incomplete or corrupt."); }
            catch (EndOfStreamException) { return Result(JournalReadState.InterruptedReplacement, "Replacement is incomplete."); }
            catch (IOException) { return Result(JournalReadState.UnknownConflict, "Replacement read failed."); }
            if (main == JournalReadState.Valid)
            {
                try
                {
                    if (ReadJournal(path).PlanHash != replacement.PlanHash)
                        return Result(JournalReadState.UnknownConflict, "Main and replacement plans differ.");
                }
                catch (UnauthorizedAccessException) { return Result(JournalReadState.Inaccessible, "Main journal cannot be read."); }
                catch (System.Security.SecurityException) { return Result(JournalReadState.Inaccessible, "Main journal cannot be read."); }
                catch (InvalidDataException) { return Result(JournalReadState.Corrupt, "Main journal is corrupt."); }
                catch (EndOfStreamException) { return Result(JournalReadState.Corrupt, "Main journal is truncated."); }
                catch (IOException) { return Result(JournalReadState.UnknownConflict, "Main journal read failed."); }
            }
            return Result(JournalReadState.InterruptedReplacement, "A complete replacement awaits explicit recovery.");
        }
        if (main == JournalReadState.VerifiedAbsent) return Result(JournalReadState.VerifiedAbsent, "No journal or replacement exists.");
        try { return new JournalInspection(JournalReadState.Valid, ReadJournal(path), "Validated journal."); }
        catch (UnauthorizedAccessException) { return Result(JournalReadState.Inaccessible, "Journal cannot be read."); }
        catch (System.Security.SecurityException) { return Result(JournalReadState.Inaccessible, "Journal cannot be read."); }
        catch (InvalidDataException) { return Result(JournalReadState.Corrupt, "Journal content is corrupt."); }
        catch (EndOfStreamException) { return Result(JournalReadState.Corrupt, "Journal content is truncated."); }
        catch (IOException) { return Result(JournalReadState.UnknownConflict, "Journal read failed."); }
    }

    public InstallJournal Load()
    {
        JournalInspection inspection = Inspect();
        if (inspection.State == JournalReadState.VerifiedAbsent) return null;
        if (inspection.State == JournalReadState.Valid) return inspection.Journal;
        throw new JournalStateException(inspection.State, inspection.Detail);
    }

    private InstallJournal ReadJournal(string candidate)
    {
        byte[] all = File.ReadAllBytes(candidate);
        if (all.Length < 36 || all.Length > MaximumJournalBytes) throw new InvalidDataException("Malformed journal length.");
        int payloadLength = all.Length - 32;
        byte[] payload = new byte[payloadLength]; Array.Copy(all, payload, payloadLength);
        using (var sha = SHA256.Create())
        {
            byte[] digest = sha.ComputeHash(payload);
            for (int i = 0; i < digest.Length; i++) if (digest[i] != all[payloadLength + i])
                throw new InvalidDataException("Journal checksum mismatch.");
        }
        using (var stream = new MemoryStream(payload))
        using (var reader = new BinaryReader(stream, Encoding.UTF8))
        {
            if (reader.ReadInt32() != 1) throw new InvalidDataException("Unsupported journal version.");
            var journal = new InstallJournal { PlanHash = reader.ReadString(), Phase = (JournalPhase)reader.ReadInt32() };
            if (!Enum.IsDefined(typeof(JournalPhase), journal.Phase)) throw new InvalidDataException("Invalid journal phase.");
            int count = reader.ReadInt32();
            if (count < 0 || count > 256) throw new InvalidDataException("Invalid journal entry count.");
            for (int i = 0; i < count; i++)
            {
                var entry = new JournalEntry { Operation = Canonical.ReadOperation(reader), Phase = (JournalPhase)reader.ReadInt32() };
                if (!Enum.IsDefined(typeof(JournalPhase), entry.Phase)) throw new InvalidDataException("Invalid entry phase.");
                journal.Entries.Add(entry);
            }
            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing journal data.");
            return journal;
        }
    }

    public InstallJournal ResolveInterruptedReplacement()
    {
        JournalInspection state = Inspect();
        if (state.State != JournalReadState.InterruptedReplacement)
            throw new JournalStateException(state.State, "There is no safely resolvable interrupted replacement.");
        InstallJournal replacement = ReadJournal(path + ".new");
        JournalReadState main = Node(path, false);
        if (main == JournalReadState.Valid)
        {
            InstallJournal original = ReadJournal(path);
            if (original.PlanHash != replacement.PlanHash)
                throw new JournalStateException(JournalReadState.UnknownConflict, "Replacement belongs to another plan.");
            File.Move(path + ".new", path + ".interrupted-" + Guid.NewGuid().ToString("N"));
        }
        else if (main == JournalReadState.VerifiedAbsent) File.Move(path + ".new", path);
        else throw new JournalStateException(main, "Main journal changed during recovery.");
        return Load();
    }

    public void Save(InstallJournal journal)
    {
        JournalInspection existing = Inspect();
        if (existing.State != JournalReadState.Valid && existing.State != JournalReadState.VerifiedAbsent)
            throw new JournalStateException(existing.State, existing.Detail);
        byte[] payload;
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(1); writer.Write(journal.PlanHash); writer.Write((int)journal.Phase);
            writer.Write(journal.Entries.Count);
            foreach (var entry in journal.Entries) { Canonical.WriteOperation(writer, entry.Operation); writer.Write((int)entry.Phase); }
            writer.Flush(); payload = stream.ToArray();
        }
        if (payload.Length > MaximumJournalBytes - 32) throw new InvalidDataException("Journal exceeds size limit.");
        byte[] checksum;
        using (var sha = SHA256.Create()) checksum = sha.ComputeHash(payload);
        string tmp = path + ".new";
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        if (writeFault != null) writeFault(JournalWriteBoundary.BeforeTemporaryCreate);
        using (var file = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { file.Write(payload, 0, payload.Length); file.Write(checksum, 0, checksum.Length); file.Flush(true); }
        if (writeFault != null) writeFault(JournalWriteBoundary.AfterTemporaryFlush);
        if (writeFault != null) writeFault(JournalWriteBoundary.BeforePublish);
        if (existing.State == JournalReadState.Valid) File.Replace(tmp, path, null);
        else File.Move(tmp, path);
        if (writeFault != null) writeFault(JournalWriteBoundary.AfterPublish);
    }
}
