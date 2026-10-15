using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

internal sealed class PortableExtractionFile
{
    internal string RelativePath;
    internal long Length;
    internal string Sha256;
}

internal sealed class PortableExtractionPlan
{
    internal string Root, Version, SourceUrl, ArchiveSha256, Hash;
    internal readonly List<PortableExtractionFile> Files = new List<PortableExtractionFile>();
}

// An immutable manifest is flushed before creating the version directory.
// Recovery removes only exact, manifest-listed bytes through verified handles.
internal static class PortableExtractionTransaction
{
    private const int MaxManifestBytes = 512 * 1024;
    private static string Digest(Stream stream)
    {
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private static string ManifestPath(string root) { return root + ".childstream-journal"; }

    private static void ValidateOwnedRoot(string versionRoot, string ownedRoot)
    {
        string owned = InstallerPolicy.ValidateCanonicalFilePath(ownedRoot, true)
            .TrimEnd(Path.DirectorySeparatorChar);
        string version = InstallerPolicy.ValidateCanonicalFilePath(versionRoot, true)
            .TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(owned), "ChildStream", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetDirectoryName(Path.GetDirectoryName(version)), owned,
                StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFileName(Path.GetDirectoryName(version)), "versions",
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Portable extraction must stay in a dedicated ChildStream version directory.");
    }

    internal static PortableExtractionPlan Plan(Stream verifiedArchive, PortableSunshinePackage package,
        string ownedRoot)
    {
        ValidateOwnedRoot(package.PortableRoot, ownedRoot);
        package.Validate(ownedRoot);
        verifiedArchive.Position = 0;
        package.VerifyBytes(verifiedArchive);
        verifiedArchive.Position = 0;
        IList<string> paths = PortableSunshineArchive.ValidateManifest(verifiedArchive);
        var plan = new PortableExtractionPlan { Root = package.PortableRoot, Version = package.Version,
            SourceUrl = package.SourceUrl, ArchiveSha256 = package.Sha256 };
        using (var zip = new ZipArchive(verifiedArchive, ZipArchiveMode.Read, true))
        {
            foreach (string path in paths.OrderBy(p => p, StringComparer.Ordinal))
            {
                ZipArchiveEntry entry = zip.GetEntry(path);
                using (var input = entry.Open())
                    plan.Files.Add(new PortableExtractionFile { RelativePath = path.Substring("Sunshine/".Length),
                        Length = entry.Length, Sha256 = Digest(input) });
            }
        }
        verifiedArchive.Position = 0;
        PortableExtractionFile executable = plan.Files.SingleOrDefault(f => f.RelativePath == "sunshine.exe");
        if (executable == null || !String.Equals(executable.Sha256, package.ExecutableSha256,
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Pinned Sunshine executable is absent or its digest changed.");
        plan.Hash = Digest(new MemoryStream(Payload(plan)));
        return plan;
    }

    private static byte[] Payload(PortableExtractionPlan plan)
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(2); writer.Write(plan.Root); writer.Write(plan.Version);
            writer.Write(plan.SourceUrl); writer.Write(plan.ArchiveSha256);
            writer.Write(plan.Files.Count);
            foreach (var file in plan.Files)
            { writer.Write(file.RelativePath); writer.Write(file.Length); writer.Write(file.Sha256); }
            writer.Flush(); return stream.ToArray();
        }
    }

    private static PortableExtractionPlan Read(string root, string path = null)
    {
        path = path ?? ManifestPath(root);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        if (!File.Exists(path)) throw new InvalidOperationException("No verified extraction journal exists.");
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length < 36 || bytes.Length > MaxManifestBytes) throw new InvalidDataException("Extraction journal size is invalid.");
        byte[] payload = new byte[bytes.Length - 32];
        Buffer.BlockCopy(bytes, 0, payload, 0, payload.Length);
        using (var sha = SHA256.Create())
        {
            byte[] digest = sha.ComputeHash(payload);
            for (int i = 0; i < digest.Length; i++)
                if (digest[i] != bytes[payload.Length + i]) throw new InvalidDataException("Extraction journal checksum mismatch.");
        }
        var plan = new PortableExtractionPlan();
        using (var reader = new BinaryReader(new MemoryStream(payload), Encoding.UTF8))
        {
            if (reader.ReadInt32() != 2) throw new InvalidDataException("Unsupported extraction journal version.");
            plan.Root = reader.ReadString(); plan.Version = reader.ReadString();
            plan.SourceUrl = reader.ReadString(); plan.ArchiveSha256 = reader.ReadString();
            if (!String.Equals(plan.Root, root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Extraction journal targets another root.");
            if (String.IsNullOrEmpty(plan.Version) || String.IsNullOrEmpty(plan.SourceUrl) ||
                plan.ArchiveSha256.Length != 64 || !plan.ArchiveSha256.All(Uri.IsHexDigit) ||
                !String.Equals(plan.SourceUrl, "https://github.com/LizardByte/Sunshine/releases/download/" +
                    plan.Version + "/" + Path.GetFileName(new Uri(plan.SourceUrl).AbsolutePath), StringComparison.Ordinal))
                throw new InvalidDataException("Extraction journal release provenance is invalid.");
            int count = reader.ReadInt32();
            if (count < 1 || count > 4096) throw new InvalidDataException("Extraction journal file count is invalid.");
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < count; i++)
            {
                var file = new PortableExtractionFile { RelativePath = reader.ReadString(),
                    Length = reader.ReadInt64(), Sha256 = reader.ReadString() };
                ValidateRelative(file.RelativePath);
                if (!seen.Add(file.RelativePath) || file.Length < 0 || file.Length > 256L * 1024 * 1024 ||
                    file.Sha256.Length != 64 || !file.Sha256.All(Uri.IsHexDigit))
                    throw new InvalidDataException("Extraction journal entry is invalid.");
                plan.Files.Add(file);
            }
            if (reader.BaseStream.Position != reader.BaseStream.Length)
                throw new InvalidDataException("Trailing extraction journal bytes.");
        }
        plan.Hash = Digest(new MemoryStream(payload));
        return plan;
    }

    private static void ValidateRelative(string relative)
    {
        if (String.IsNullOrEmpty(relative) || relative.StartsWith("/", StringComparison.Ordinal) ||
            relative.IndexOf(':') >= 0 || relative.IndexOf('\\') >= 0 || relative.IndexOf('\0') >= 0)
            throw new InvalidDataException("Invalid extraction relative path.");
        foreach (string part in relative.Split('/'))
            if (part.Length == 0 || part == "." || part == "..")
                throw new InvalidDataException("Extraction path traversal.");
    }

    private static string FilePath(PortableExtractionPlan plan, PortableExtractionFile file)
    {
        ValidateRelative(file.RelativePath);
        string path = Path.Combine(plan.Root, file.RelativePath.Replace('/', Path.DirectorySeparatorChar));
        InstallerPolicy.ValidateCanonicalFilePath(path);
        return path;
    }

    private static bool SameFile(string path, PortableExtractionFile file)
    {
        if (!File.Exists(path)) return false;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            return stream.Length == file.Length && String.Equals(Digest(stream), file.Sha256,
                StringComparison.OrdinalIgnoreCase);
    }

    internal static void Apply(Stream verifiedArchive, PortableSunshinePackage package,
        string ownedRoot, string approvedHash, IExecutableSignerVerifier signer)
    {
        PortableExtractionPlan plan = Plan(verifiedArchive, package, ownedRoot);
        if (!String.Equals(plan.Hash, approvedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Extraction plan hash was not approved.");
        string manifest = ManifestPath(plan.Root);
        InstallerPolicy.ValidateCanonicalFilePath(manifest);
        if (File.Exists(manifest))
        {
            PortableExtractionPlan previous = Read(plan.Root);
            if (previous.Hash != plan.Hash) throw new InvalidOperationException("Another extraction plan owns this root.");
            if (plan.Files.All(f => SameFile(FilePath(plan, f), f))) return;
            throw new InvalidOperationException("Interrupted extraction needs reviewed recovery before retry.");
        }
        if (Directory.Exists(plan.Root) || File.Exists(plan.Root))
            throw new InvalidOperationException("Portable version root already exists and is not owned by this plan.");
        byte[] payload = Payload(plan);
        byte[] checksum;
        using (var sha = SHA256.Create()) checksum = sha.ComputeHash(payload);
        Directory.CreateDirectory(Path.GetDirectoryName(manifest));
        using (var file = new FileStream(manifest, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { file.Write(payload, 0, payload.Length); file.Write(checksum, 0, checksum.Length); file.Flush(true); }
        verifiedArchive.Position = 0;
        PortableSunshineArchive.ExtractIntoNewRoot(verifiedArchive, plan.Root, package, signer);
        if (!plan.Files.All(f => SameFile(FilePath(plan, f), f)))
            throw new InvalidDataException("Extracted Sunshine files do not match the durable plan.");
    }

    private static void InspectTree(string root, HashSet<string> allowedFiles, HashSet<string> allowedDirs)
    {
        if (!Directory.Exists(root)) return;
        foreach (string child in Directory.GetFileSystemEntries(root))
        {
            FileAttributes attributes = File.GetAttributes(child);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Extraction tree contains a reparse point; recovery stopped.");
            if ((attributes & FileAttributes.Directory) != 0)
            {
                if (!allowedDirs.Contains(child)) throw new InvalidOperationException("Unowned directory in extraction tree.");
                InspectTree(child, allowedFiles, allowedDirs);
            }
            else if (!allowedFiles.Contains(child))
                throw new InvalidOperationException("Unowned file in extraction tree.");
        }
    }

    internal static void Recover(string root)
    {
        ValidateOwnedRoot(root, Path.GetDirectoryName(Path.GetDirectoryName(root)));
        string manifest = ManifestPath(root);
        string rolledBack = manifest + ".rolledback";
        if (!File.Exists(manifest))
        {
            Read(root, rolledBack);
            if (Directory.Exists(root) || File.Exists(root))
                throw new InvalidOperationException("Portable root exists after journaled rollback.");
            return;
        }
        PortableExtractionPlan plan = Read(root);
        if (File.Exists(rolledBack) && Read(root, rolledBack).Hash != plan.Hash)
            throw new InvalidOperationException("A different rolled-back extraction plan already owns this root.");
        InstallerPolicy.ValidateCanonicalFilePath(root, true);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in plan.Files)
        {
            string path = FilePath(plan, entry);
            files.Add(path);
            for (string parent = Path.GetDirectoryName(path); parent != null &&
                !String.Equals(parent, root, StringComparison.OrdinalIgnoreCase); parent = Path.GetDirectoryName(parent))
                dirs.Add(parent);
            if (File.Exists(path) && !SameFile(path, entry))
                throw new InvalidOperationException("Extracted file changed; recovery preserves it for review.");
        }
        InspectTree(root, files, dirs); // inspect every path before the first deletion
        foreach (var entry in plan.Files)
        {
            string path = FilePath(plan, entry);
            if (File.Exists(path)) WindowsOwnedInstallerHost.DeleteVerifiedHash(path, entry.Length, entry.Sha256);
        }
        foreach (string directory in dirs.OrderByDescending(p => p.Length))
            if (Directory.Exists(directory)) Directory.Delete(directory, false);
        if (Directory.Exists(root)) Directory.Delete(root, false);
        if (File.Exists(rolledBack)) File.Delete(manifest);
        else File.Move(manifest, rolledBack);
        // The immutable rolled-back journal remains as recovery evidence.
    }
}
