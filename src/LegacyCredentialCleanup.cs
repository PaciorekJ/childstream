using System;
using System.IO;
using System.Security;

internal enum LegacyCredentialStatus
{
    Absent,
    Present,
    Removed,
    Inaccessible,
    Failed,
    OutsideOwnedPath,
    Cancelled
}

internal interface ILegacyFileAccess
{
    FileAttributes GetAttributes(string path);
    void Delete(string path);
}

internal sealed class WindowsLegacyFileAccess : ILegacyFileAccess
{
    public FileAttributes GetAttributes(string path) { return File.GetAttributes(path); }
    public void Delete(string path) { File.Delete(path); }
}

internal sealed class LegacyCredentialCleanup
{
    private readonly string candidatePath;
    private readonly ILegacyFileAccess files;
    private readonly bool ownedPath;

    internal string CandidatePath { get { return candidatePath; } }

    internal LegacyCredentialCleanup(string executablePath, string candidatePath, ILegacyFileAccess files)
    {
        this.candidatePath = candidatePath;
        this.files = files;
        try
        {
            string executable = Path.GetFullPath(executablePath);
            string candidate = Path.GetFullPath(candidatePath);
            string expected = Path.Combine(Path.GetDirectoryName(executable), "cred.bin");
            ownedPath = string.Equals(Path.GetFileName(executable), "ChildStream.exe", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(candidate, expected, StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException) { ownedPath = false; }
        catch (NotSupportedException) { ownedPath = false; }
    }

    internal LegacyCredentialStatus Inspect()
    {
        if (!ownedPath) return LegacyCredentialStatus.OutsideOwnedPath;
        try
        {
            FileAttributes attributes = files.GetAttributes(candidatePath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                return LegacyCredentialStatus.OutsideOwnedPath;
            return LegacyCredentialStatus.Present;
        }
        catch (FileNotFoundException) { return LegacyCredentialStatus.Absent; }
        catch (DirectoryNotFoundException) { return LegacyCredentialStatus.Absent; }
        catch (UnauthorizedAccessException) { return LegacyCredentialStatus.Inaccessible; }
        catch (SecurityException) { return LegacyCredentialStatus.Inaccessible; }
        catch (IOException) { return LegacyCredentialStatus.Failed; }
    }

    internal LegacyCredentialStatus RemoveWithApproval(bool approved)
    {
        LegacyCredentialStatus before = Inspect();
        if (before != LegacyCredentialStatus.Present) return before;
        if (!approved) return LegacyCredentialStatus.Cancelled;
        try { files.Delete(candidatePath); }
        catch (UnauthorizedAccessException) { return LegacyCredentialStatus.Inaccessible; }
        catch (SecurityException) { return LegacyCredentialStatus.Inaccessible; }
        catch (IOException) { return LegacyCredentialStatus.Failed; }
        LegacyCredentialStatus after = Inspect();
        return after == LegacyCredentialStatus.Absent ? LegacyCredentialStatus.Removed :
            after == LegacyCredentialStatus.Present ? LegacyCredentialStatus.Failed : after;
    }
}
