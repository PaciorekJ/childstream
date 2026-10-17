using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using System.Security.Principal;

// Candidate adapter for small, newly created ChildStream files only. Runtime
// Sunshine binaries exceed the journal's byte limit and use a separate verified
// archive admission path. No global registry, service, firewall or RDP writer.
internal sealed class WindowsOwnedInstallerHost : IInstallerHost
{
    private readonly InstallerPolicy policy;
    private readonly FileJournalStore journal;

    internal WindowsOwnedInstallerHost(string ownedRoot, string journalPath)
    {
        string root = InstallerPolicy.ValidateCanonicalFilePath(ownedRoot, true)
            .TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(root), "ChildStream", StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFullPath(journalPath).StartsWith(root + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Owned-file adapter requires a dedicated ChildStream root and journal.");
        policy = new InstallerPolicy(root);
        journal = new FileJournalStore(journalPath);
    }

    public bool HasPrivilege(InstallPrivilege privilege)
    {
        if (privilege == InstallPrivilege.CurrentUser) return true;
        if (privilege != InstallPrivilege.Administrator) return false;
        var identity = WindowsIdentity.GetCurrent();
        return identity != null && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public ResourceState Read(ResourceTarget target)
    {
        policy.ValidateTarget(target);
        if (target.Kind != ResourceKind.OwnedFile)
            throw new InvalidOperationException("This adapter supports only new ChildStream-owned files.");
        string path = InstallerPolicy.ValidateCanonicalFilePath(target.Identity);
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return new ResourceState { Access = ResourceAccess.Absent }; }
        catch (DirectoryNotFoundException) { return new ResourceState { Access = ResourceAccess.Absent }; }
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            return new ResourceState { Access = ResourceAccess.Conflicting };
        var info = new FileInfo(path);
        if (info.Length > 8 * 1024 * 1024)
            return new ResourceState { Access = ResourceAccess.Conflicting };
        byte[] data;
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length != info.Length) return new ResourceState { Access = ResourceAccess.Unknown };
            data = new byte[(int)file.Length];
            int offset = 0;
            while (offset < data.Length)
            {
                int read = file.Read(data, offset, data.Length - offset);
                if (read == 0) return new ResourceState { Access = ResourceAccess.Unknown };
                offset += read;
            }
        }
        var state = new ResourceState { Access = ResourceAccess.Accessible, ValueType = "FileBytes", Data = data };
        InstallJournal saved = journal.Load(); // An interrupted or corrupt journal is never treated as absent.
        if (saved != null && saved.Phase != JournalPhase.RolledBack)
            foreach (var entry in saved.Entries)
                if (entry.Operation.Target.Kind == ResourceKind.OwnedFile &&
                    String.Equals(entry.Operation.Target.Identity, target.Identity, StringComparison.OrdinalIgnoreCase) &&
                    entry.Operation.Original.Access == ResourceAccess.Absent &&
                    entry.Operation.Desired.Access == ResourceAccess.Accessible &&
                    BytesEqual(data, entry.Operation.Desired.Data))
                { state.Owner = entry.Operation.OwnershipEvidence; break; }
        return state;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    public bool CompareExchange(ResourceTarget target, ResourceState expected, ResourceState desired)
    {
        policy.ValidateTarget(target);
        if (target.Kind != ResourceKind.OwnedFile) throw new InvalidOperationException("Only owned files can be changed.");
        if (!Read(target).Same(expected)) return false;
        if (expected.Access == ResourceAccess.Absent && desired.Access == ResourceAccess.Accessible)
        {
            string parent = Path.GetDirectoryName(target.Identity);
            InstallerPolicy.ValidateCanonicalFilePath(parent, true);
            Directory.CreateDirectory(parent);
            using (var file = new FileStream(target.Identity, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { file.Write(desired.Data, 0, desired.Data.Length); file.Flush(true); }
            return true;
        }
        if (expected.Access == ResourceAccess.Accessible && desired.Access == ResourceAccess.Absent)
        {
            if (String.IsNullOrEmpty(expected.Owner))
                throw new InvalidOperationException("Unowned file cannot be removed.");
            DeleteVerifiedHandle(target.Identity, expected.Data);
            return true;
        }
        throw new InvalidOperationException("In-place replacement of an existing file is unsupported.");
    }

    private static void DeleteVerifiedHandle(string path, byte[] expected)
    {
        string digest;
        using (var sha = SHA256.Create())
            digest = BitConverter.ToString(sha.ComputeHash(expected)).Replace("-", "").ToLowerInvariant();
        DeleteVerifiedHash(path, expected.Length, digest);
    }

    internal static void DeleteVerifiedHash(string path, long expectedLength, string expectedSha256)
    {
        // A no-share handle prevents a second opener between verification and
        // disposition. Do not delete by path after closing the verified handle.
        using (SafeFileHandle handle = CreateFile(path, 0x80010000, 0, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
        {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot lock owned file for rollback.");
            using (var stream = new FileStream(handle, FileAccess.Read, 4096, false))
            {
                if (stream.Length != expectedLength) throw new InvalidOperationException("Owned file length drifted before rollback.");
                using (var sha = SHA256.Create())
                    if (!String.Equals(BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", ""),
                            expectedSha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Owned file bytes drifted before rollback.");
                var disposition = new FileDispositionInfo { DeleteFile = true };
                if (!SetFileInformationByHandle(handle, 4, ref disposition, (uint)Marshal.SizeOf(typeof(FileDispositionInfo))))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Owned file handle disposition failed.");
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int fileInfoClass,
        ref FileDispositionInfo fileInfo, uint size);
}
