using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// A per-user, per-parent-session intent latch; it contains IDs and logon time only.
// A malformed or inaccessible latch blocks connection rather than being ignored.
internal sealed class FileSignOutIntentStore : ISignOutIntentStore
{
    private readonly string directory;
    internal FileSignOutIntentStore(string directory) { this.directory = directory; }
    private string PathFor(uint parent) { return Path.Combine(directory, "signout-" + parent + ".intent"); }

    public bool HasUnresolvedIntent(uint parentSessionId)
    {
        string path = PathFor(parentSessionId);
        try { File.GetAttributes(path); }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        byte[] record = File.ReadAllBytes(path);
        if (record.Length != 52) throw new InvalidDataException("Malformed sign-out intent.");
        byte[] payload = new byte[20]; Array.Copy(record, payload, payload.Length);
        using (var sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(payload);
            for (int i = 0; i < hash.Length; i++) if (hash[i] != record[payload.Length + i])
                throw new InvalidDataException("Sign-out intent checksum mismatch.");
        }
        using (var reader = new BinaryReader(new MemoryStream(payload)))
        {
            if (reader.ReadInt32() != 1 || reader.ReadUInt32() != parentSessionId ||
                reader.ReadUInt32() == uint.MaxValue || reader.ReadInt64() <= 0)
                throw new InvalidDataException("Invalid sign-out intent identity.");
        }
        return true;
    }

    public void RecordIntent(uint parentSessionId, ChildSessionIdentity child)
    {
        if (HasUnresolvedIntent(parentSessionId))
            throw new InvalidOperationException("An unresolved sign-out intent already exists.");
        byte[] payload;
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write(1); writer.Write(parentSessionId); writer.Write(child.SessionId); writer.Write(child.LogonTime);
            writer.Flush(); payload = stream.ToArray();
        }
        byte[] hash;
        using (var sha = SHA256.Create()) hash = sha.ComputeHash(payload);
        Directory.CreateDirectory(directory);
        string path = PathFor(parentSessionId);
        string tmp = path + ".new";
        using (var file = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        { file.Write(payload, 0, payload.Length); file.Write(hash, 0, hash.Length); file.Flush(true); }
        File.Move(tmp, path); // refuses to overwrite an unresolved intent
    }

    public void ResolveIntent(uint parentSessionId)
    {
        if (!HasUnresolvedIntent(parentSessionId)) throw new InvalidOperationException("No sign-out intent exists.");
        File.Delete(PathFor(parentSessionId));
        if (File.Exists(PathFor(parentSessionId))) throw new IOException("Sign-out intent deletion was not verified.");
    }

    // Explicit operator command only. It checks the same parent twice, performs no logoff,
    // and clears only the latch; the next launch independently rechecks for a child.
    internal bool ReconcileAbsentChild(IChildSessionApi api, uint parentSessionId)
    {
        if (api.CurrentSessionId != parentSessionId || !HasUnresolvedIntent(parentSessionId)) return false;
        if (api.ReadAssociatedChild().HasValue || api.ReadAssociatedChild().HasValue) return false;
        ResolveIntent(parentSessionId);
        return true;
    }
}
