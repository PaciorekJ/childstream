using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

// A bundle manifest carries layout and integrity information, not publisher
// authentication. Reviewers must verify the published outer ZIP digest before
// approving execution of this unsigned package or its elevated helper.
internal sealed class ProductBundle
{
    internal string Root, CandidatePath, SunshinePath, CandidateSha256, SourceSha;
    private sealed class Descriptor
    {
        public string schema { get; set; }
        public string sourceSha { get; set; }
        public string candidateSha256 { get; set; }
        public string sunshineSha256 { get; set; }
        public string launcherSha256 { get; set; }
        public string bootstrapSha256 { get; set; }
    }
    private static string Hash(string path)
    {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var sha = SHA256.Create())
            return ProductInstallPayload.Hex(sha.ComputeHash(file));
    }
    private static void Match(string actual, string expected, string label)
    {
        if (!ProductInstallPayload.IsHex256(expected) ||
            !String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Bundle " + label + " differs from its manifest.");
    }
    internal static ProductBundle Read(string directory)
    { return ReadPinned(directory, SunshineReleasePin.ArchiveSha256); }
#if TEST_ONLY
    internal static ProductBundle ReadFixture(string directory, string fixtureSunshineSha256)
    { return ReadPinned(directory, fixtureSunshineSha256); }
#endif
    private static ProductBundle ReadPinned(string directory, string pinnedSunshineSha256)
    {
        if (String.IsNullOrWhiteSpace(directory)) throw new InvalidDataException("Bundle directory is missing.");
        string root = Path.GetFullPath(directory);
        string manifest = Path.Combine(root, "bundle.json");
        if (!File.Exists(manifest)) throw new FileNotFoundException("Bundle manifest is missing.", manifest);
        if (new FileInfo(manifest).Length > 8192) throw new InvalidDataException("Bundle manifest is oversized.");
        Descriptor data = new JavaScriptSerializer().Deserialize<Descriptor>(File.ReadAllText(manifest, Encoding.UTF8));
        if (data == null || data.schema != "ChildStream.UserBundle.v1" ||
            data.sourceSha == null || data.sourceSha.Length != 40)
            throw new InvalidDataException("Bundle schema or source identity is invalid.");
        foreach (char c in data.sourceSha) if (!Uri.IsHexDigit(c))
            throw new InvalidDataException("Bundle source identity is invalid.");
        string candidate = Path.Combine(root, "payload", "ChildStream-candidate.zip");
        string sunshine = Path.Combine(root, "payload", SunshineReleasePin.AssetName);
        string launcher = Path.Combine(root, "ChildStream.exe");
        string bootstrap = Path.Combine(root, "ChildStreamBootstrap.exe");
        Match(Hash(candidate), data.candidateSha256, "candidate");
        Match(Hash(sunshine), data.sunshineSha256, "Sunshine archive");
        Match(data.sunshineSha256, pinnedSunshineSha256, "pinned Sunshine archive");
        Match(Hash(launcher), data.launcherSha256, "launcher");
        Match(Hash(bootstrap), data.bootstrapSha256, "bootstrap");
        ProductInstallPayload.ReadCandidate(candidate, data.candidateSha256);
        using (var file = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.None))
        using (var zip = new ZipArchive(file, ZipArchiveMode.Read))
        {
            foreach (var pair in new[] { new { Name = "bin/ChildStream.exe", Hash = data.launcherSha256 },
                                         new { Name = "bin/ChildStreamBootstrap.exe", Hash = data.bootstrapSha256 } })
            {
                var entry = zip.GetEntry(pair.Name);
                if (entry == null) throw new InvalidDataException("Bundle executable is missing from candidate.");
                using (var input = entry.Open()) using (var sha = SHA256.Create())
                    Match(ProductInstallPayload.Hex(sha.ComputeHash(input)), pair.Hash, pair.Name);
            }
        }
        return new ProductBundle { Root = root, CandidatePath = candidate,
            SunshinePath = sunshine, CandidateSha256 = data.candidateSha256, SourceSha = data.sourceSha };
    }
    private static string PointerPath
    {
        get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ChildStream", "reviewed-bundle.path"); }
    }
    internal static ProductBundle FindCurrent()
    {
        string here = AppDomain.CurrentDomain.BaseDirectory;
        if (File.Exists(Path.Combine(here, "bundle.json"))) return Read(here);
        if (!File.Exists(PointerPath)) return null;
        string root = File.ReadAllText(PointerPath, Encoding.UTF8).Trim();
        return Read(root); // Fail closed if the reviewed bundle was moved or changed.
    }
    internal void Remember()
    {
        Read(Root);
        Directory.CreateDirectory(Path.GetDirectoryName(PointerPath));
        string temporary = PointerPath + ".partial";
        File.WriteAllText(temporary, Root + Environment.NewLine, Encoding.UTF8);
        if (File.Exists(PointerPath)) File.Replace(temporary, PointerPath, null);
        else File.Move(temporary, PointerPath);
    }
}
