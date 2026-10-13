using System;
using System.IO;

internal interface ITransactionOwnership
{
    IDisposable Acquire();
}

// An OS-held exclusive file handle coordinates independent processes. A terminated
// process releases the handle, while the journal remains for the next owner to
// inspect and recover. The marker file itself is deliberately never treated as
// evidence of an active owner.
internal sealed class FileTransactionOwnership : ITransactionOwnership
{
    private readonly string path;
    internal FileTransactionOwnership(string path)
    {
        if (!Path.IsPathRooted(path)) throw new ArgumentException("Transaction lock path must be absolute.");
        this.path = Path.GetFullPath(path);
    }

    public IDisposable Acquire()
    {
        string parent = Path.GetDirectoryName(path);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        Directory.CreateDirectory(parent);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new InvalidDataException("Transaction lock is not a regular file.");
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { throw new InvalidDataException("Transaction lock directory disappeared."); }
        try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException ex) { throw new InvalidOperationException("Another transaction owns the installation or the lock is inaccessible.", ex); }
    }
}
