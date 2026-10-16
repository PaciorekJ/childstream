using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

internal sealed class SunshineAdminCredential
{
    internal string UserName, Password;
}

// The same Windows user owns this directory across child logon generations.
// Installed binaries and the native Sunshine profile are never used as state.
internal interface IChildSunshineIdentity : IDisposable
{
    string DirectoryPath { get; }
    string CertificatePath { get; }
    string CredentialFilePath { get; }
    bool HasSunshineCredentials { get; }
    SunshineAdminCredential GetOrCreateCredentials();
    string ReadCertificateSha256();
}
internal sealed class SunshineIdentityStore : IChildSunshineIdentity
{
    private readonly string directory, credentialPath, certificatePath;
    private readonly FileStream writerLock;
    internal string DirectoryPath { get { return directory; } }
    internal string CertificatePath { get { return certificatePath; } }
    internal string CredentialFilePath { get { return Path.Combine(directory, "credentials.json"); } }
    internal bool HasSunshineCredentials { get { return RegularFilePresent(CredentialFilePath); } }
    string IChildSunshineIdentity.DirectoryPath { get { return DirectoryPath; } }
    string IChildSunshineIdentity.CertificatePath { get { return CertificatePath; } }
    string IChildSunshineIdentity.CredentialFilePath { get { return CredentialFilePath; } }
    bool IChildSunshineIdentity.HasSunshineCredentials { get { return HasSunshineCredentials; } }
    internal SunshineIdentityStore(string childStreamDataRoot)
    {
        if (String.IsNullOrEmpty(childStreamDataRoot) || !Path.IsPathRooted(childStreamDataRoot))
            throw new InvalidDataException("ChildStream data root must be absolute.");
        string root = InstallerPolicy.ValidateCanonicalFilePath(childStreamDataRoot, true)
            .TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(root), "ChildStream", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Identity must be under a dedicated ChildStream data root.");
        directory = Path.Combine(root, "identity");
        InstallerPolicy.ValidateCanonicalFilePath(directory, true);
        string sid = WindowsIdentity.GetCurrent().User.Value;
        if (!System.IO.Directory.Exists(directory))
        {
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-18"), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            System.IO.Directory.CreateDirectory(directory, acl);
        }
        VerifyPrivateDirectory(sid);
        credentialPath = Path.Combine(directory, "admin.dpapi");
        certificatePath = Path.Combine(directory, "sunshine.cert");
        writerLock = new FileStream(Path.Combine(directory, "writer.lock"), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
    }
    private void VerifyPrivateDirectory(string sid)
    {
        var security = System.IO.Directory.GetAccessControl(directory,
            AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected) throw new UnauthorizedAccessException("Identity directory inherits other access.");
        string owner = security.GetOwner(typeof(SecurityIdentifier)).Value;
        if (owner != sid && owner != "S-1-5-18" && owner != "S-1-5-32-544")
            throw new UnauthorizedAccessException("Identity directory has an unexpected owner.");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            string principal = rule.IdentityReference.Value;
            if (rule.AccessControlType == AccessControlType.Allow &&
                principal != sid && principal != "S-1-5-18" && principal != "S-1-5-32-544")
                throw new UnauthorizedAccessException("Identity directory has an unexpected access grant.");
        }
    }
    private static bool RegularFilePresent(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new InvalidDataException("Owned Sunshine identity file is not a regular file.");
            return true;
        }
        catch (FileNotFoundException) { return false; }
    }
    internal SunshineAdminCredential GetOrCreateCredentials()
    {
        InstallerPolicy.ValidateCanonicalFilePath(credentialPath);
        if (RegularFilePresent(credentialPath))
        {
            byte[] encrypted = File.ReadAllBytes(credentialPath);
            if (encrypted.Length < 32 || encrypted.Length > 4096) throw new InvalidDataException("Owned credentials are malformed.");
            byte[] plain = ProtectedData.Unprotect(encrypted, Encoding.UTF8.GetBytes("ChildStream.Sunshine.v1"),
                DataProtectionScope.CurrentUser);
            try
            {
                string value = new UTF8Encoding(false, true).GetString(plain);
                string[] fields = value.Split('\n');
                if (fields.Length != 2 || fields[0] != "ChildStream" || fields[1].Length < 32)
                    throw new InvalidDataException("Owned credentials are malformed.");
                return new SunshineAdminCredential { UserName = fields[0], Password = fields[1] };
            }
            finally { Array.Clear(plain, 0, plain.Length); }
        }
        byte[] random = new byte[32];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(random);
        string password = Convert.ToBase64String(random);
        Array.Clear(random, 0, random.Length);
        byte[] clear = Encoding.UTF8.GetBytes("ChildStream\n" + password);
        byte[] protectedBytes;
        try { protectedBytes = ProtectedData.Protect(clear, Encoding.UTF8.GetBytes("ChildStream.Sunshine.v1"),
            DataProtectionScope.CurrentUser); }
        finally { Array.Clear(clear, 0, clear.Length); }
        using (var stream = new FileStream(credentialPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { stream.Write(protectedBytes, 0, protectedBytes.Length); stream.Flush(true); }
        return new SunshineAdminCredential { UserName = "ChildStream", Password = password };
    }
    SunshineAdminCredential IChildSunshineIdentity.GetOrCreateCredentials() { return GetOrCreateCredentials(); }
    internal string ReadCertificateSha256()
    {
        InstallerPolicy.ValidateCanonicalFilePath(certificatePath);
        byte[] pem = File.ReadAllBytes(certificatePath);
        if (pem.Length < 128 || pem.Length > 65536) throw new InvalidDataException("Owned certificate is malformed.");
        string text = Encoding.ASCII.GetString(pem);
        const string begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----";
        int first = text.IndexOf(begin, StringComparison.Ordinal), last = text.IndexOf(end, StringComparison.Ordinal);
        if (first < 0 || last <= first || text.IndexOf(begin, first + begin.Length, StringComparison.Ordinal) >= 0)
            throw new InvalidDataException("Owned certificate PEM is ambiguous.");
        string base64 = text.Substring(first + begin.Length, last - first - begin.Length)
            .Replace("\r", "").Replace("\n", "").Trim();
        byte[] der = Convert.FromBase64String(base64);
        using (var certificate = new X509Certificate2(der))
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-", "");
    }
    string IChildSunshineIdentity.ReadCertificateSha256() { return ReadCertificateSha256(); }
    public void Dispose() { writerLock.Dispose(); }
}
