using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal static class InstallerFoundationTests
{
    private static int assertions;
    private static string root;
    private static string file1, file2;
    private const string owner = "childstream-test-installation";

    private sealed class FakeHost : IInstallerHost
    {
        internal readonly Dictionary<string, ResourceState> Values = new Dictionary<string, ResourceState>();
        internal int Writes;
        internal int Reads;
        internal int FailWrite;
        internal bool FailAfter;
        internal bool Authorized = true;
        public ResourceState Read(ResourceTarget target)
        {
            Reads++;
            ResourceState value;
            return Values.TryGetValue(target.Kind + ":" + target.Identity, out value) ? value.Copy() : Absent();
        }
        public bool CompareExchange(ResourceTarget target, ResourceState expected, ResourceState state)
        {
            if (!Read(target).Same(expected)) return false;
            Writes++;
            if (Writes == FailWrite && !FailAfter) throw new IOException("Injected before write.");
            Values[target.Kind + ":" + target.Identity] = state.Copy();
            if (Writes == FailWrite && FailAfter) throw new IOException("Injected after write.");
            return true;
        }
        public bool HasPrivilege(InstallPrivilege privilege) { return Authorized; }
        internal void External(ResourceTarget target, ResourceState state) { Values[target.Kind + ":" + target.Identity] = state.Copy(); }
    }

    private sealed class FaultStore : IJournalStore
    {
        internal readonly FileJournalStore Disk;
        internal int Saves;
        internal int FailSave;
        internal FaultStore(string path) { Disk = new FileJournalStore(path); }
        public InstallJournal Load() { return Disk.Load(); }
        public void Save(InstallJournal journal)
        {
            Saves++;
            if (Saves == FailSave) throw new IOException("Injected journal failure.");
            Disk.Save(journal);
        }
    }
    private sealed class FakeProvenance : IPackageProvenanceVerifier
    {
        internal bool Trusted;
        public bool VerifyOfficialReleaseAsset(string path, string sourceUrl, string version)
        { return Trusted && sourceUrl.Contains("/LizardByte/Sunshine/") && version == "v1.0"; }
    }
    private sealed class FakeExecutableSigner : IExecutableSignerVerifier
    {
        internal bool Trusted;
        public bool VerifyTrustedExecutable(string path, string thumbprint) { return Trusted && thumbprint.Length == 40; }
    }

    private static ResourceState Absent() { return new ResourceState { Access = ResourceAccess.Absent }; }
    private static ResourceState FileValue(string value)
    { return new ResourceState { Access = ResourceAccess.Accessible, ValueType = "FileBytes", Data = Encoding.UTF8.GetBytes(value), Owner = owner }; }
    private static InstallOperation Operation(string path, string value)
    {
        return new InstallOperation { Target = new ResourceTarget(ResourceKind.OwnedFile, path),
            Desired = FileValue(value), Privilege = InstallPrivilege.CurrentUser,
            OwnershipEvidence = owner, Verification = "Exact bytes and owner marker", Reversal = "Restore exact original snapshot" };
    }
    private static InstallerEngine Engine(FakeHost host, IJournalStore store)
    { return new InstallerEngine(host, store, new InstallerPolicy(root)); }
    private static InstallPlan Plan(InstallerEngine engine)
    { return engine.Plan(new [] { Operation(file2, "two"), Operation(file1, "one") }); }
    private static void Check(bool condition, string label)
    { assertions++; if (!condition) throw new Exception("Assertion failed: " + label); }
    private static void Throws<T>(Action action, string label) where T : Exception
    {
        bool threw = false;
        try { action(); } catch (T) { threw = true; }
        Check(threw, label);
    }
    private static string PathFor(string caseName) { return Path.Combine(root, caseName + ".journal"); }
    private static void Clean(string path) { if (File.Exists(path)) File.Delete(path); if (File.Exists(path + ".new")) File.Delete(path + ".new"); }

    private static void BasicAndIdempotence()
    {
        var host = new FakeHost(); string path = PathFor("basic"); Clean(path);
        var store = new FaultStore(path); var engine = Engine(host, store); var plan = Plan(engine);
        Check(plan.Operations[0].Target.Identity == file1, "stable operation order");
        Check(plan.Hash == Plan(engine).Hash, "deterministic plan hash");
        Throws<InvalidOperationException>(() => engine.Apply(plan, "incorrect"), "approval hash required");
        Check(host.Writes == 0 && store.Load() == null, "bad hash has no effects");
        plan.Operations[0].Desired.Data[0] = 70;
        Throws<InvalidOperationException>(() => engine.Apply(plan, plan.Hash), "changed plan rejected");
        plan = Plan(engine);
        Check(engine.Apply(plan, plan.Hash).Phase == JournalPhase.Complete, "installation completes");
        Check(host.Writes == 2, "two writes");
        Check(Engine(host, new FaultStore(path)).Apply(plan, plan.Hash).Phase == JournalPhase.Complete, "repeat install no-op");
        Check(host.Writes == 2, "repeat install no additional writes");
        Check(Engine(host, new FaultStore(path)).RecoverOrUninstall().Phase == JournalPhase.RolledBack, "uninstall completes");
        Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file1)).Access == ResourceAccess.Absent, "first file removed");
        Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file2)).Access == ResourceAccess.Absent, "second file removed");
        Check(Engine(host, new FaultStore(path)).RecoverOrUninstall().Phase == JournalPhase.RolledBack, "repeated uninstall no-op");
    }

    private static void FaultMatrix()
    {
        for (int save = 1; save <= 6; save++)
        {
            var host = new FakeHost(); string path = PathFor("save" + save); Clean(path);
            var store = new FaultStore(path) { FailSave = save }; var engine = Engine(host, store); var plan = Plan(engine);
            Throws<IOException>(() => engine.Apply(plan, plan.Hash), "journal failure " + save);
            if (File.Exists(path))
            {
                var recovered = Engine(host, new FaultStore(path)).RecoverOrUninstall();
                Check(recovered.Phase == JournalPhase.RolledBack, "recover journal failure " + save);
            }
            Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file1)).Access == ResourceAccess.Absent, "journal failure clears file one " + save);
            Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file2)).Access == ResourceAccess.Absent, "journal failure clears file two " + save);
        }
        for (int write = 1; write <= 2; write++) for (int after = 0; after <= 1; after++)
        {
            var host = new FakeHost { FailWrite = write, FailAfter = after == 1 };
            string path = PathFor("write" + write + after); Clean(path);
            var engine = Engine(host, new FaultStore(path)); var plan = Plan(engine);
            Throws<IOException>(() => engine.Apply(plan, plan.Hash), "write failure " + write + after);
            host.FailWrite = 0;
            Check(Engine(host, new FaultStore(path)).RecoverOrUninstall().Phase == JournalPhase.RolledBack, "recover write failure " + write + after);
            Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file1)).Access == ResourceAccess.Absent, "write failure clears first " + write + after);
            Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file2)).Access == ResourceAccess.Absent, "write failure clears second " + write + after);
        }
        for (int save = 1; save <= 5; save++)
        {
            var host = new FakeHost(); string path = PathFor("rollback-save" + save); Clean(path);
            var plan = Plan(Engine(host, new FaultStore(path)));
            Engine(host, new FaultStore(path)).Apply(plan, plan.Hash);
            var store = new FaultStore(path) { FailSave = save };
            Throws<IOException>(() => Engine(host, store).RecoverOrUninstall(), "rollback journal failure " + save);
            Check(Engine(host, new FaultStore(path)).RecoverOrUninstall().Phase == JournalPhase.RolledBack,
                "restart completes rollback after journal failure " + save);
            Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file1)).Access == ResourceAccess.Absent,
                "rollback journal clears first " + save);
            Check(host.Read(new ResourceTarget(ResourceKind.OwnedFile, file2)).Access == ResourceAccess.Absent,
                "rollback journal clears second " + save);
        }
        for (int write = 1; write <= 2; write++) for (int after = 0; after <= 1; after++)
        {
            var host = new FakeHost(); string path = PathFor("rollback-write" + write + after); Clean(path);
            var plan = Plan(Engine(host, new FaultStore(path)));
            Engine(host, new FaultStore(path)).Apply(plan, plan.Hash);
            host.FailWrite = host.Writes + write; host.FailAfter = after == 1;
            Throws<IOException>(() => Engine(host, new FaultStore(path)).RecoverOrUninstall(),
                "rollback mutation failure " + write + after);
            host.FailWrite = 0;
            Check(Engine(host, new FaultStore(path)).RecoverOrUninstall().Phase == JournalPhase.RolledBack,
                "restart completes rollback after mutation failure " + write + after);
        }
    }

    private static void ConflictsAndAuthorization()
    {
        var host = new FakeHost(); string path = PathFor("conflict"); Clean(path);
        var engine = Engine(host, new FaultStore(path)); var plan = Plan(engine);
        host.Authorized = false;
        Throws<UnauthorizedAccessException>(() => engine.Apply(plan, plan.Hash), "privilege denied");
        Check(host.Writes == 0, "no unauthorized writes");
        host.Authorized = true;
        host.External(plan.Operations[0].Target, FileValue("external"));
        Throws<InvalidOperationException>(() => engine.Apply(plan, plan.Hash), "stale inventory blocked");
        Check(host.Writes == 0, "stale plan no writes");
        host.External(plan.Operations[0].Target, Absent());
        engine.Apply(plan, plan.Hash);
        host.External(plan.Operations[1].Target, FileValue("user changed"));
        Throws<InvalidOperationException>(() => Engine(host, new FaultStore(path)).RecoverOrUninstall(), "external drift blocks rollback");
        Check(new FileJournalStore(path).Load().Phase == JournalPhase.Conflict, "conflict remains journaled");
        Check(host.Read(plan.Operations[1].Target).Same(FileValue("user changed")), "external data preserved");
        host.External(plan.Operations[1].Target, plan.Operations[1].Desired);
        Check(Engine(host, new FaultStore(path)).RecoverOrUninstall().Phase == JournalPhase.RolledBack, "conflict can be resolved");
        Check(host.Read(plan.Operations[0].Target).Access == ResourceAccess.Absent, "reverse order completes");

        host = new FakeHost(); path = PathFor("unowned"); Clean(path);
        var unowned = FileValue("old"); unowned.Owner = "someone else";
        host.External(new ResourceTarget(ResourceKind.OwnedFile, file1), unowned);
        var e2 = Engine(host, new FaultStore(path));
        Throws<InvalidOperationException>(() => Plan(e2), "unowned collision blocked");
        var same = Operation(file1, "old"); same.Desired = unowned.Copy();
        var noOpPlan = e2.Plan(new [] { same });
        e2.Apply(noOpPlan, noOpPlan.Hash);
        Check(host.Writes == 0, "existing desired unowned state is no-op");
        e2.RecoverOrUninstall();
        Check(host.Read(same.Target).Same(unowned), "unowned no-op preserved on uninstall");
    }

    private static void ScopeAndMalformed()
    {
        var host = new FakeHost(); var engine = Engine(host, new FaultStore(PathFor("scope")));
        foreach (ResourceKind kind in new [] { ResourceKind.ChildSessions, ResourceKind.Process, ResourceKind.SunshineInstall,
            ResourceKind.Port, ResourceKind.VddInstall, ResourceKind.StartupEntry })
        {
            var op = Operation(file1, "x"); op.Target = new ResourceTarget(kind, "native resource");
            Throws<InvalidOperationException>(() => engine.Plan(new [] { op }), "read-only kind " + kind);
        }
        var native = Operation(Path.Combine(root, "..", "Sunshine", "config.json"), "x");
        int readsBefore = host.Reads;
        Throws<InvalidOperationException>(() => engine.Plan(new [] { native }), "native Sunshine path outside root");
        Check(host.Reads == readsBefore, "forbidden target is not inventoried by mutation planner");
        var vdd = Operation(Path.Combine(root, "vdd-driver.sys"), "x");
        Throws<InvalidOperationException>(() => engine.Plan(new [] { vdd }), "VDD path excluded");
        var rdp = Operation(file1, "x"); rdp.Target = new ResourceTarget(ResourceKind.RegistryValue,
            @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections");
        Throws<InvalidOperationException>(() => engine.Plan(new [] { rdp }), "RDP registry forbidden");
        var broad = Operation(file1, "x"); broad.Target = new ResourceTarget(ResourceKind.FirewallRule, "ChildStream.test");
        broad.Desired.Filters["RemoteAddress"] = "Any";
        Throws<InvalidOperationException>(() => engine.Plan(new [] { broad }), "broad firewall forbidden");
        var unknown = Operation(file1, "x"); host.External(unknown.Target, new ResourceState { Access = ResourceAccess.Unknown });
        Throws<InvalidOperationException>(() => engine.Plan(new [] { unknown }), "unknown inventory forbidden");
        host.External(unknown.Target, Absent());
        foreach (ResourceAccess access in new [] { ResourceAccess.Inaccessible, ResourceAccess.Conflicting })
        {
            host.External(unknown.Target, new ResourceState { Access = access });
            Throws<InvalidOperationException>(() => engine.Plan(new [] { unknown }), "uncertain inventory " + access);
        }
        string path = PathFor("malformed"); Clean(path);
        File.WriteAllBytes(path, new byte [] { 1, 2, 3 });
        Throws<InvalidDataException>(() => new FileJournalStore(path).Load(), "short journal rejected");
        File.WriteAllBytes(path, new byte[40]);
        Throws<InvalidDataException>(() => new FileJournalStore(path).Load(), "bad checksum rejected");
    }

    private static void ExactRegistrySnapshot()
    {
        var state = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "REG_EXPAND_SZ",
            Data = new byte [] { 0, 1, 255, 0, 42 }, Owner = owner };
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream))
        {
            Canonical.WriteState(writer, state); writer.Flush(); stream.Position = 0;
            using (var reader = new BinaryReader(stream))
                Check(Canonical.ReadState(reader).Same(state), "exact registry type and bytes round trip");
        }
        var host = new FakeHost(); string path = PathFor("registry"); Clean(path);
        var target = new ResourceTarget(ResourceKind.RegistryValue, @"HKCU\Software\ChildStream\Value");
        host.External(target, state);
        var desired = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "REG_DWORD",
            Data = new byte[] { 7, 0, 0, 0 }, Owner = owner };
        var op = new InstallOperation { Target = target, Desired = desired, Privilege = InstallPrivilege.CurrentUser,
            OwnershipEvidence = owner, Verification = "Exact registry type/data", Reversal = "Restore original registry type/data" };
        var engine = Engine(host, new FaultStore(path));
        var plan = engine.Plan(new[] { op });
        engine.Apply(plan, plan.Hash);
        Check(host.Read(target).Same(desired), "registry desired type/data applied in fake");
        Engine(host, new FaultStore(path)).RecoverOrUninstall();
        Check(host.Read(target).Same(state), "registry original presence/type/bytes restored exactly");
    }

    private static void TamperedJournalAndRecoveryPrivilege()
    {
        var host = new FakeHost(); string path = PathFor("tamper"); Clean(path);
        var engine = Engine(host, new FaultStore(path)); var plan = Plan(engine);
        engine.Apply(plan, plan.Hash);
        host.Authorized = false;
        int writes = host.Writes;
        Throws<UnauthorizedAccessException>(() => Engine(host, new FaultStore(path)).RecoverOrUninstall(),
            "recovery needs operation privilege");
        Check(host.Writes == writes, "unauthorized recovery does not write");
        host.Authorized = true;
        var store = new FileJournalStore(path);
        var journal = store.Load();
        journal.Entries[0].Operation.Target.Identity = @"C:\Program Files\Sunshine\config.json";
        store.Save(journal); // valid outer checksum, invalid scoped payload
        Throws<InvalidOperationException>(() => Engine(host, new FaultStore(path)).RecoverOrUninstall(),
            "valid-checksum malicious journal target rejected");
        Check(host.Writes == writes, "tampered journal does not write");
    }

    private static void InventoryAndPackage()
    {
        var inventory = new SystemInventory();
        inventory.Registry.Add(new RegistryValueInventory { Hive = "HKCU", Key = @"Software\ChildStream\State",
            ValueName = "binary", ValueType = "REG_BINARY", ExactData = new byte [] { 0, 255, 1 },
            Access = ResourceAccess.Accessible });
        inventory.ChildFeatures.Add(new ChildFeatureInventory { Access = ResourceAccess.Unknown, Enabled = null });
        inventory.Sunshine.Add(new SunshineInstallInventory { Path = @"C:\Program Files\Sunshine",
            NativeInstallation = true, Access = ResourceAccess.Accessible });
        inventory.ValidateForReview();
        string review = inventory.RegistryReviewLine(inventory.Registry[0]);
        Check(review.Contains("sha256=") && !review.Contains("255"), "registry review hides raw bytes");
        inventory.Registry[0].Key = @"Software\ChildStream\password";
        Throws<InvalidDataException>(() => inventory.ValidateForReview(), "credential inventory forbidden");
        inventory.Registry[0].Key = @"Software\ChildStream\State";
        inventory.Firewall.Add(new FirewallRuleInventory { Access = ResourceAccess.Accessible, Identity = "rule" });
        Throws<InvalidDataException>(() => inventory.ValidateForReview(), "incomplete firewall filters rejected");
        inventory.Firewall.Clear();
        inventory.ChildFeatures[0].Enabled = true;
        Throws<InvalidDataException>(() => inventory.ValidateForReview(), "unknown feature cannot claim enabled state");
        inventory.ChildFeatures[0].Enabled = null;

        var package = new PortableSunshinePackage { Version = "v1.0", SourceUrl =
            "https://github.com/LizardByte/Sunshine/releases/download/v1.0/sunshine.zip",
            PortableRoot = Path.Combine(root, "portable"), ConfigRoot = Path.Combine(root, "config"),
            ExecutableSignerThumbprint = new string('a', 40), Sha256 = new string('0', 64) };
        package.Validate(root);
        using (var stream = new MemoryStream(new byte [] { 1, 2, 3 }))
            Throws<InvalidDataException>(() => package.VerifyBytes(stream), "unmatched package digest blocked");
        string artifact = Path.Combine(root, "downloaded.zip");
        File.WriteAllBytes(artifact, new byte[] { 1, 2, 3 });
        using (var sha = SHA256.Create())
            package.Sha256 = BitConverter.ToString(sha.ComputeHash(new byte[] { 1, 2, 3 })).Replace("-", "").ToLowerInvariant();
        Throws<InvalidDataException>(() => package.Admit(artifact, new FakeProvenance()), "untrusted provenance blocked");
        using (var locked = package.Admit(artifact, new FakeProvenance { Trusted = true }))
            Check(locked.Position == 0 && locked.ReadByte() == 1, "verified package stream remains open for extraction");
        Throws<InvalidDataException>(() => package.VerifyExtractedExecutable(
            Path.Combine(root, "portable", "sunshine.exe"), new FakeExecutableSigner()), "untrusted extracted executable blocked");
        package.VerifyExtractedExecutable(Path.Combine(root, "portable", "sunshine.exe"),
            new FakeExecutableSigner { Trusted = true });
        Check(true, "trusted executable under portable root admitted by contract");
        package.SourceUrl = "https://example.com/sunshine.zip";
        Throws<InvalidDataException>(() => package.Validate(root), "untrusted package origin blocked");
        package.SourceUrl = "https://github.com/LizardByte/Sunshine/releases/download/v1.0/sunshine.zip";
        package.ConfigRoot = @"C:\Program Files\Sunshine";
        Throws<InvalidDataException>(() => package.Validate(root), "native Sunshine configuration excluded");
    }

    internal static int Main()
    {
        root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "installer-fixtures");
        Directory.CreateDirectory(root);
        file1 = Path.Combine(root, "portable", "a.exe"); file2 = Path.Combine(root, "portable", "b.exe");
        try
        {
            BasicAndIdempotence(); FaultMatrix(); ConflictsAndAuthorization(); ScopeAndMalformed();
            ExactRegistrySnapshot(); InventoryAndPackage(); TamperedJournalAndRecoveryPrivilege();
            Console.WriteLine("Installer offline assertions passed: " + assertions); return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
