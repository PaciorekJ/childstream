using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

// Pins are independently recorded from the official versioned release asset.
// The selected lite executable is unsigned; its executable hash is mandatory.
internal static class SunshineReleasePin
{
    // Official prerelease built from 178a0467da1dde750b182be4ae10ff8f8245ad01.
    // That commit is 49 commits after external-audio merge fd45d2dd853d4f9310616112d78168226df6099c.
    internal const string Version = "v2026.1015.174736";
    internal const string AssetName = "Sunshine-Windows-AMD64-lite.zip";
    internal const string AssetUrl = "https://github.com/LizardByte/Sunshine/releases/download/" + Version + "/" + AssetName;
    internal const string ArchiveSha256 = "35fa21069c314896e9b476e16e42fe4d60986dc3926b54e80d1c693e40d314cc";
    internal const string ExecutableSha256 = "424cb1bbfe994c7676ff03957f1b3e1e79d218264677ec0b8959b5c809523c8c";

    internal static PortableSunshinePackage Create(string portableRoot, string configRoot)
    {
        return new PortableSunshinePackage { Version = Version, SourceUrl = AssetUrl,
            Sha256 = ArchiveSha256, ExecutableSha256 = ExecutableSha256,
            PortableRoot = portableRoot, ConfigRoot = configRoot };
    }
}

internal sealed class PinnedSunshineReleaseVerifier : IPackageProvenanceVerifier
{
    public bool VerifyOfficialReleaseAsset(string path, string sourceUrl, string version)
    {
        return String.Equals(sourceUrl, SunshineReleasePin.AssetUrl, StringComparison.Ordinal) &&
            String.Equals(version, SunshineReleasePin.Version, StringComparison.Ordinal) &&
            File.Exists(path);
    }
}

internal static class PortableSunshineArchive
{
    // Inspect the locked, digest-verified stream before any extraction. A future
    // installer may extract only into a new ChildStream-owned staging directory.
    internal static IList<string> ValidateManifest(Stream verifiedArchive)
    {
        if (verifiedArchive == null || !verifiedArchive.CanRead || !verifiedArchive.CanSeek ||
            verifiedArchive.Position != 0)
            throw new InvalidDataException("The verified Sunshine archive must be seekable at offset zero.");
        var paths = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool executable = false;
        long expanded = 0;
        using (var zip = new ZipArchive(verifiedArchive, ZipArchiveMode.Read, true))
        {
            if (zip.Entries.Count == 0 || zip.Entries.Count > 4096)
                throw new InvalidDataException("Unexpected Sunshine archive entry count.");
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string path = entry.FullName.Replace('\\', '/');
                if (!path.StartsWith("Sunshine/", StringComparison.Ordinal) ||
                    path.StartsWith("/", StringComparison.Ordinal) || path.IndexOf(':') >= 0 ||
                    path.IndexOf('\0') >= 0 || path.Length > 512)
                    throw new InvalidDataException("Sunshine archive has an unexpected path.");
                string[] parts = path.Split('/');
                for (int i = 0; i < parts.Length; i++)
                    if (parts[i].Length == 0 && i == parts.Length - 1 && path.EndsWith("/", StringComparison.Ordinal))
                        continue;
                    else if (!SafePart(parts[i]))
                        throw new InvalidDataException("Sunshine archive has an unsafe Windows path component.");
                if (!seen.Add(path.TrimEnd('/')))
                    throw new InvalidDataException("Sunshine archive contains a duplicate path.");
                // ZIP Unix symlinks (type 0120000) and Windows reparse points are not admitted.
                int unixType = (entry.ExternalAttributes >> 16) & 0xF000;
                if (unixType == 0xA000 || (entry.ExternalAttributes & 0x400) != 0 ||
                    ((entry.ExternalAttributes >> 16) & 0x400) != 0)
                    throw new InvalidDataException("Sunshine archive contains a link or reparse point.");
                if (!path.EndsWith("/", StringComparison.Ordinal))
                {
                    if (entry.Length < 0 || entry.Length > 256L * 1024 * 1024 ||
                        expanded > 1024L * 1024 * 1024 - entry.Length)
                        throw new InvalidDataException("Sunshine archive exceeds extraction limits.");
                    expanded += entry.Length;
                    paths.Add(path);
                    if (path == "Sunshine/sunshine.exe") executable = true;
                }
            }
        }
        verifiedArchive.Position = 0;
        if (!executable) throw new InvalidDataException("Pinned Sunshine executable is missing or archive layout changed.");
        return paths;
    }

    private static bool SafePart(string part)
    {
        if (String.IsNullOrEmpty(part) || part == "." || part == ".." ||
            part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal) ||
            part.IndexOfAny(new [] { '<', '>', ':', '"', '|', '?', '*', '\\' }) >= 0)
            return false;
        foreach (char c in part) if (c < 32) return false;
        string stem = part.Split('.')[0].ToUpperInvariant();
        if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL") return false;
        if (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) ||
            stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] >= '1' && stem[3] <= '9') return false;
        return true;
    }

    // The caller owns a newly created empty staging root, under the validated
    // portable root. This method never overwrites another installation.
    internal static void ExtractIntoNewRoot(Stream verifiedArchive, string newRoot,
        PortableSunshinePackage package, IExecutableSignerVerifier signer)
    {
        package.Validate(Path.GetDirectoryName(Path.GetDirectoryName(package.PortableRoot)));
        if (!String.Equals(Path.GetFullPath(newRoot), Path.GetFullPath(package.PortableRoot),
                StringComparison.OrdinalIgnoreCase) || Directory.Exists(newRoot) || File.Exists(newRoot))
            throw new InvalidDataException("Extraction requires an absent, exact owned version directory.");
        verifiedArchive.Position = 0;
        package.VerifyBytes(verifiedArchive);
        verifiedArchive.Position = 0;
        ValidateManifest(verifiedArchive);
        Directory.CreateDirectory(newRoot);
        try
        {
            using (var zip = new ZipArchive(verifiedArchive, ZipArchiveMode.Read, true))
            {
                foreach (ZipArchiveEntry entry in zip.Entries)
                {
                    if (entry.FullName.EndsWith("/", StringComparison.Ordinal)) continue;
                    string relative = entry.FullName.Substring("Sunshine/".Length).Replace('/', Path.DirectorySeparatorChar);
                    string destination = Path.Combine(newRoot, relative);
                    InstallerPolicy.ValidateCanonicalFilePath(destination);
                    Directory.CreateDirectory(Path.GetDirectoryName(destination));
                    using (var input = entry.Open())
                    using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        byte[] buffer = new byte[65536];
                        long written = 0;
                        int count;
                        while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            written += count;
                            if (written > entry.Length) throw new InvalidDataException("Archive entry expanded beyond declared size.");
                            output.Write(buffer, 0, count);
                        }
                        if (written != entry.Length) throw new InvalidDataException("Archive entry length changed.");
                        output.Flush(true);
                    }
                }
            }
            package.VerifyExtractedExecutable(Path.Combine(newRoot, "sunshine.exe"), signer);
        }
        catch
        {
            // Do not erase an ambiguous partial extraction. Recovery must inspect
            // this root and its ownership before removing it.
            throw;
        }
    }
}
