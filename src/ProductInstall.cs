using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

// The candidate ZIP digest is supplied from the separately reviewed CI artifact.
// Its self-described manifest is never accepted as its own authenticity proof.
internal sealed class ProductInstallPayload
{
    internal readonly Dictionary<string, byte[]> Files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
    internal static readonly string[] InstalledFiles = {
        "bin/ChildStream.exe", "bin/ChildStreamSetup.exe", "bin/ChildStreamBootstrap.exe",
        "bin/ChildStreamFeasibilityProbe.exe", "scripts/feasibility-inventory.ps1",
        "scripts/rdp-containment-observe.ps1"
    };
    internal static ProductInstallPayload ReadCandidate(string zipPath, string approvedSha256)
    {
        InstallerPolicy.ValidateCanonicalFilePath(zipPath);
        if (!IsHex256(approvedSha256)) throw new InvalidDataException("A reviewed candidate SHA-256 is required.");
        var result = new ProductInstallPayload();
        using (var file = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            using (var sha = SHA256.Create())
                if (!String.Equals(Hex(sha.ComputeHash(file)), approvedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Candidate archive differs from the reviewed artifact.");
            file.Position = 0;
            using (var zip = new ZipArchive(file, ZipArchiveMode.Read, true))
                foreach (string name in InstalledFiles)
                {
                    ZipArchiveEntry entry = zip.GetEntry(name);
                    if (entry == null || zip.Entries.Count(e => e.FullName.Equals(name, StringComparison.OrdinalIgnoreCase)) != 1 ||
                        entry.Length < 1 || entry.Length > 8 * 1024 * 1024)
                        throw new InvalidDataException("Candidate lacks an exact bounded ChildStream payload: " + name);
                    using (var source = entry.Open())
                    using (var memory = new MemoryStream())
                    {
                        source.CopyTo(memory);
                        if (memory.Length != entry.Length) throw new InvalidDataException("Candidate payload length changed.");
                        result.Files.Add(name, memory.ToArray());
                    }
                }
        }
        return result;
    }
    internal static bool IsHex256(string value)
    { return value != null && value.Length == 64 && value.All(Uri.IsHexDigit); }
    internal static string Hex(byte[] bytes)
    { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
}

internal sealed class ProductInstallPlan
{
    internal InstallPlan Files;
    internal PortableExtractionPlan Sunshine;
    internal string Hash;
}

// Only new files in a dedicated ChildStream root are admitted. The archive
// journal is reversed first, then the small-file journal. No feature, task,
// firewall, service, driver, native Sunshine, or user identity is changed.
internal sealed class ProductInstallCoordinator
{
    private readonly InstallerEngine files;
    private readonly string root;
    private readonly InstallPrivilege privilege;
#if TEST_ONLY
    private readonly PortableSunshinePackage testPackage;
#endif
    internal ProductInstallCoordinator(InstallerEngine files, string root, InstallPrivilege privilege)
    {
        this.files = files; this.root = InstallerPolicy.ValidateCanonicalFilePath(root, true).TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(this.root), "ChildStream", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Installation requires a dedicated ChildStream root.");
        this.privilege = privilege;
    }
#if TEST_ONLY
    internal ProductInstallCoordinator(InstallerEngine files, string root, InstallPrivilege privilege,
        PortableSunshinePackage testPackage) : this(files, root, privilege)
    { this.testPackage = testPackage; }
#endif
    private string SunshineRoot { get { return Path.Combine(root, "versions", SunshineReleasePin.Version); } }
    private PortableSunshinePackage Package
    { get {
#if TEST_ONLY
        if (testPackage != null) return testPackage;
#endif
        return SunshineReleasePin.Create(SunshineRoot, Path.Combine(root, "identity"));
    } }
    private static string InstalledRelative(string source)
    { return source.StartsWith("bin/", StringComparison.Ordinal) ? source.Substring(4) : source; }
    private List<InstallOperation> Operations(ProductInstallPayload payload)
    {
        if (payload == null || payload.Files.Count != ProductInstallPayload.InstalledFiles.Length)
            throw new InvalidDataException("The candidate payload is incomplete.");
        var operations = new List<InstallOperation>();
        foreach (string name in ProductInstallPayload.InstalledFiles)
        {
            byte[] bytes;
            if (!payload.Files.TryGetValue(name, out bytes) || bytes == null || bytes.Length == 0 || bytes.Length > 8 * 1024 * 1024)
                throw new InvalidDataException("Required candidate payload is missing or unbounded: " + name);
            string target = InstallerPolicy.ValidateCanonicalFilePath(Path.Combine(root,
                InstalledRelative(name).Replace('/', Path.DirectorySeparatorChar)));
            operations.Add(new InstallOperation {
                Target = new ResourceTarget(ResourceKind.OwnedFile, target),
                Desired = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "FileBytes",
                    Owner = "ChildStream.Candidate.v1", Data = bytes },
                Privilege = privilege, OwnershipEvidence = "ChildStream.Candidate.v1",
                Verification = "ExactBytes", Reversal = "DeleteExactOwnedBytes"
            });
        }
        return operations;
    }
    private static string CombinedHash(string filesHash, string sunshineHash)
    {
        using (var sha = SHA256.Create())
            return ProductInstallPayload.Hex(sha.ComputeHash(Encoding.ASCII.GetBytes(
                "ChildStream.ProductInstall.v1\n" + filesHash + "\n" + sunshineHash + "\n")));
    }
    internal ProductInstallPlan Plan(ProductInstallPayload payload, Stream admittedSunshine)
    {
        if (admittedSunshine == null) throw new InvalidDataException("Pinned Sunshine archive is unavailable.");
        var plan = new ProductInstallPlan();
        plan.Files = files.PlanReadOnly(Operations(payload));
        plan.Sunshine = PortableExtractionTransaction.Plan(admittedSunshine, Package, root);
        plan.Hash = CombinedHash(plan.Files.Hash, plan.Sunshine.Hash);
        return plan;
    }
    internal ProductInstallPlan PlanCommitted(ProductInstallPayload payload, Stream admittedSunshine,
        InstallJournal committed)
    {
        if (committed == null || committed.Phase != JournalPhase.Complete)
            throw new InvalidOperationException("Repair requires a complete prior ChildStream installation journal.");
        var plan = new ProductInstallPlan { Files = new InstallPlan() };
        foreach (JournalEntry entry in committed.Entries) plan.Files.Operations.Add(entry.Operation);
        plan.Files.Hash = committed.PlanHash;
        if (Canonical.Hash(plan.Files) != plan.Files.Hash)
            throw new InvalidDataException("Committed installation journal changed.");
        RequirePayload(plan.Files, payload);
        plan.Sunshine = PortableExtractionTransaction.Plan(admittedSunshine, Package, root);
        plan.Hash = CombinedHash(plan.Files.Hash, plan.Sunshine.Hash);
        return plan;
    }
    private void RequirePayload(InstallPlan plan, ProductInstallPayload payload)
    {
        List<InstallOperation> expected = Operations(payload);
        if (plan.Operations.Count != expected.Count ||
            expected.Any(op => !plan.Operations.Any(p =>
                p.Target.Kind == op.Target.Kind && p.Target.Identity == op.Target.Identity &&
                p.Desired.Same(op.Desired) && p.Privilege == op.Privilege &&
                p.OwnershipEvidence == op.OwnershipEvidence)))
            throw new InvalidOperationException("Candidate payload changed after planning.");
    }
    internal void Apply(ProductInstallPlan plan, ProductInstallPayload payload, Stream admittedSunshine,
        string approvedHash)
    {
        if (plan == null || plan.Files == null || plan.Sunshine == null ||
            !String.Equals(plan.Files.Hash, Canonical.Hash(plan.Files), StringComparison.Ordinal) ||
            !String.Equals(plan.Hash, CombinedHash(plan.Files.Hash, plan.Sunshine.Hash), StringComparison.Ordinal) ||
            !String.Equals(plan.Hash, approvedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The reviewed combined installation plan changed.");
        RequirePayload(plan.Files, payload);
        PortableExtractionPlan currentArchive = PortableExtractionTransaction.Plan(admittedSunshine, Package, root);
        if (!String.Equals(currentArchive.Hash, plan.Sunshine.Hash, StringComparison.Ordinal))
            throw new InvalidOperationException("Pinned Sunshine archive changed after planning.");
        files.Apply(plan.Files, plan.Files.Hash);
        PortableExtractionTransaction.Apply(admittedSunshine, Package, root, plan.Sunshine.Hash, null);
    }
    internal void RecoverOrUninstall()
    {
        string manifest = SunshineRoot + ".childstream-journal";
        string rolledBack = manifest + ".rolledback";
        if (File.Exists(manifest) || File.Exists(rolledBack))
            PortableExtractionTransaction.Recover(SunshineRoot);
        else if (Directory.Exists(SunshineRoot) || File.Exists(SunshineRoot))
            throw new InvalidOperationException("Unjournaled Sunshine version root blocks recovery.");
        files.RecoverOrUninstall();
    }
}
