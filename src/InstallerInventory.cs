using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
#pragma warning disable 0649 // Adapter-facing record fields are populated by future host probes.

// These are read-only observations. Unknown and inaccessible are separate from absent;
// no adapter may infer absence from a failed native query.
internal sealed class RegistryValueInventory
{
    internal string Hive, Key, ValueName, ValueType;
    internal byte[] ExactData;
    internal ResourceAccess Access;
}
internal sealed class ChildFeatureInventory
{
    internal ResourceAccess Access;
    internal bool? Enabled;
}
internal sealed class FirewallRuleInventory
{
    internal string Identity, Direction, Action, Profile, Protocol, LocalAddress,
        RemoteAddress, LocalPorts, RemotePorts, Program, Service;
    internal bool? Enabled;
    internal ResourceAccess Access;
}
internal sealed class StartupResourceInventory
{
    internal string Identity, Scope, Executable, Arguments, Owner;
    internal ResourceAccess Access;
}
internal sealed class OwnedFileInventory
{
    internal string Path, Sha256, Owner;
    internal long? Length;
    internal ResourceAccess Access;
}
internal sealed class ProcessInventory
{
    internal uint? Pid, SessionId;
    internal long? StartTime;
    internal string ExecutablePath;
    internal ResourceAccess Access;
}
internal sealed class SunshineInstallInventory
{
    internal string Path, ServiceIdentity, Version, Owner;
    internal ResourceAccess Access;
    internal bool NativeInstallation;
}
internal sealed class PortInventory
{
    internal string Protocol, LocalAddress;
    internal ushort? LocalPort;
    internal uint? ProcessId;
    internal ResourceAccess Access;
}

internal sealed class SystemInventory
{
    internal readonly List<RegistryValueInventory> Registry = new List<RegistryValueInventory>();
    internal readonly List<ChildFeatureInventory> ChildFeatures = new List<ChildFeatureInventory>();
    internal readonly List<FirewallRuleInventory> Firewall = new List<FirewallRuleInventory>();
    internal readonly List<StartupResourceInventory> Startup = new List<StartupResourceInventory>();
    internal readonly List<OwnedFileInventory> OwnedFiles = new List<OwnedFileInventory>();
    internal readonly List<ProcessInventory> Processes = new List<ProcessInventory>();
    internal readonly List<SunshineInstallInventory> Sunshine = new List<SunshineInstallInventory>();
    internal readonly List<PortInventory> Ports = new List<PortInventory>();

    internal void ValidateForReview()
    {
        foreach (var value in Registry)
        {
            if (value.Access == ResourceAccess.Accessible && (String.IsNullOrEmpty(value.ValueType) || value.ExactData == null))
                throw new InvalidDataException("Accessible registry value needs exact type and data.");
            if (value.Access != ResourceAccess.Accessible && value.ExactData != null)
                throw new InvalidDataException("Uncertain registry data cannot be represented as exact.");
            if (String.IsNullOrEmpty(value.Key) || value.Key.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.Key.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0)
                throw new InvalidDataException("Credential registry inventory is forbidden.");
        }
        foreach (var rule in Firewall)
            if (rule.Access == ResourceAccess.Accessible && (String.IsNullOrEmpty(rule.Identity) || String.IsNullOrEmpty(rule.Direction) ||
                String.IsNullOrEmpty(rule.Action) || String.IsNullOrEmpty(rule.Profile) || String.IsNullOrEmpty(rule.Protocol) ||
                String.IsNullOrEmpty(rule.LocalAddress) || String.IsNullOrEmpty(rule.RemoteAddress) ||
                String.IsNullOrEmpty(rule.LocalPorts) || String.IsNullOrEmpty(rule.RemotePorts)))
                throw new InvalidDataException("Accessible firewall inventory needs identity and complete filters.");
        foreach (var feature in ChildFeatures)
            if ((feature.Access == ResourceAccess.Accessible) != feature.Enabled.HasValue)
                throw new InvalidDataException("Child-session feature observation is incomplete or falsely definite.");
        foreach (var entry in Startup)
            if (entry.Access == ResourceAccess.Accessible && (String.IsNullOrEmpty(entry.Identity) ||
                String.IsNullOrEmpty(entry.Scope) || String.IsNullOrEmpty(entry.Executable)))
                throw new InvalidDataException("Startup observation lacks identity, scope, or executable.");
        foreach (var file in OwnedFiles)
            if (file.Access == ResourceAccess.Accessible && (String.IsNullOrEmpty(file.Path) ||
                String.IsNullOrEmpty(file.Sha256) || !file.Length.HasValue))
                throw new InvalidDataException("Owned-file observation lacks path, digest, or length.");
        foreach (var process in Processes)
            if (process.Access == ResourceAccess.Accessible && (!process.Pid.HasValue ||
                !process.SessionId.HasValue || !process.StartTime.HasValue || String.IsNullOrEmpty(process.ExecutablePath)))
                throw new InvalidDataException("Process observation lacks identity or executable.");
        foreach (var sunshine in Sunshine)
            if (sunshine.Access == ResourceAccess.Accessible && String.IsNullOrEmpty(sunshine.Path))
                throw new InvalidDataException("Sunshine installation observation lacks a path.");
        foreach (var port in Ports)
            if (port.Access == ResourceAccess.Accessible && (String.IsNullOrEmpty(port.Protocol) ||
                String.IsNullOrEmpty(port.LocalAddress) || !port.LocalPort.HasValue || !port.ProcessId.HasValue))
                throw new InvalidDataException("Port observation lacks endpoint or owner process.");
    }

    // Review reports contain only hashes and lengths, never registry bytes, command
    // arguments, Sunshine configuration, pairing material, or file contents.
    internal string RegistryReviewLine(RegistryValueInventory value)
    {
        if (value.Access != ResourceAccess.Accessible) return value.Hive + "\\" + value.Key + ": " + value.Access;
        using (var sha = SHA256.Create())
            return value.Hive + "\\" + value.Key + "\\" + value.ValueName + ": " + value.ValueType +
                " bytes=" + value.ExactData.Length + " sha256=" +
                BitConverter.ToString(sha.ComputeHash(value.ExactData)).Replace("-", "").ToLowerInvariant();
    }
}

internal interface IReadOnlyInventoryProbe
{
    SystemInventory Capture();
}

internal interface IPackageProvenanceVerifier
{
    bool VerifyOfficialReleaseAsset(string packagePath, string sourceUrl, string version);
}
internal interface IExecutableSignerVerifier
{
    bool VerifyTrustedExecutable(string executablePath, string pinnedThumbprint);
}

// An immutable package admission contract. The future downloader must bind its
// obtained bytes to an independently pinned digest and verified release provenance
// before extraction into the dedicated portable root. No network call occurs here.
internal sealed class PortableSunshinePackage
{
    internal string Version, SourceUrl, Sha256, ExecutableSha256, ExecutableSignerThumbprint, PortableRoot, ConfigRoot;

    internal void Validate(string ownedRoot)
    {
        Uri uri;
        if (String.IsNullOrEmpty(Version) || Version == "." || Version == ".." ||
            Version.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            !Uri.TryCreate(SourceUrl, UriKind.Absolute, out uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com" ||
            !uri.AbsolutePath.StartsWith("/LizardByte/Sunshine/releases/download/" + Version + "/", StringComparison.Ordinal) ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new InvalidDataException("Sunshine source must be an exact official versioned release URL.");
        if (Sha256 == null || Sha256.Length != 64 || !IsHex(Sha256) ||
            ((ExecutableSignerThumbprint == null || ExecutableSignerThumbprint.Length < 40 ||
              !IsHex(ExecutableSignerThumbprint)) &&
             (ExecutableSha256 == null || ExecutableSha256.Length != 64 || !IsHex(ExecutableSha256))))
            throw new InvalidDataException("Package digest and executable signer or digest pin are required.");
        string root = Path.GetFullPath(ownedRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string portable = InstallerPolicy.ValidateCanonicalFilePath(PortableRoot, true).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string config = InstallerPolicy.ValidateCanonicalFilePath(ConfigRoot, true).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!portable.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
            !config.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
            config.StartsWith(portable, StringComparison.OrdinalIgnoreCase) ||
            portable.StartsWith(config, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFileName(portable.TrimEnd(Path.DirectorySeparatorChar)), Version, StringComparison.Ordinal))
            throw new InvalidDataException("Portable package and configuration need separate owned paths.");
    }

    internal void VerifyBytes(Stream package)
    {
        if (package == null || !package.CanRead) throw new InvalidDataException("Package is unreadable.");
        using (var sha = SHA256.Create())
        {
            string actual = BitConverter.ToString(sha.ComputeHash(package)).Replace("-", "").ToLowerInvariant();
            if (!String.Equals(actual, Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Sunshine package digest mismatch.");
        }
    }

    internal FileStream Admit(string packagePath, IPackageProvenanceVerifier verifier)
    {
        InstallerPolicy.ValidateCanonicalFilePath(packagePath);
        var package = new FileStream(packagePath, FileMode.Open, FileAccess.Read, FileShare.None);
        try
        {
            VerifyBytes(package);
            if (verifier == null || !verifier.VerifyOfficialReleaseAsset(packagePath, SourceUrl, Version))
                throw new InvalidDataException("Sunshine release asset provenance verification failed.");
            package.Position = 0;
            VerifyBytes(package); // bind provenance check to the same locked bytes
            package.Position = 0;
            return package; // caller keeps the locked stream through extraction
        }
        catch { package.Dispose(); throw; }
    }

    internal void VerifyExtractedExecutable(string executablePath, IExecutableSignerVerifier verifier)
    {
        string root = InstallerPolicy.ValidateCanonicalFilePath(PortableRoot, true).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!InstallerPolicy.ValidateCanonicalFilePath(executablePath).StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Portable Sunshine executable is outside the owned root.");
        if (!String.IsNullOrEmpty(ExecutableSha256))
        {
            using (var file = new FileStream(executablePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
            {
                string actual = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
                if (!String.Equals(actual, ExecutableSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Portable Sunshine executable digest mismatch.");
            }
        }
        if (!String.IsNullOrEmpty(ExecutableSignerThumbprint) &&
            (verifier == null || !verifier.VerifyTrustedExecutable(executablePath, ExecutableSignerThumbprint)))
            throw new InvalidDataException("Portable Sunshine executable signer verification failed.");
    }

    private static bool IsHex(string value)
    {
        foreach (char c in value) if (!Uri.IsHexDigit(c)) return false;
        return true;
    }
}
