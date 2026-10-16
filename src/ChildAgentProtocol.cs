using System;
using System.IO;
using System.Text;

internal enum ChildAgentOperation : byte
{ Status = 1, StartSunshine = 2, StopSunshine = 3, PairingGet = 4, PairingPost = 5,
  StartSteam = 6, RequestGame = 7, StopSteam = 8, StartSunshineLan = 9, Capabilities = 10 }

internal interface IChildAgentCommandHost
{
    string Exchange(ChildAgentOperation operation, string payload, int timeoutMs);
}
internal interface IChildAgentOperations : IDisposable
{
    string Execute(ChildAgentOperation operation, string payload);
}
internal sealed class ChildAgentCommandRejectedException : InvalidOperationException
{
    internal ChildAgentCommandRejectedException(string detail) : base(detail) { }
}

internal static class ChildAgentWire
{
    internal const int MaxPayload = 65536;
    internal static void WriteRequest(Stream stream, ChildAgentOperation operation, string payload)
    {
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(payload ?? "");
        if (!Enum.IsDefined(typeof(ChildAgentOperation), operation) || bytes.Length > MaxPayload)
            throw new InvalidDataException("Child agent command is invalid or too large.");
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
        { writer.Write((byte)operation); writer.Write(bytes.Length); writer.Write(bytes); writer.Flush(); }
    }
    internal static string ReadResponse(Stream stream)
    {
        using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
        {
            int status = reader.ReadByte(); int length = reader.ReadInt32();
            if ((status != 0 && status != 1) || length < 0 || length > MaxPayload)
                throw new InvalidDataException("Child agent response frame is invalid.");
            byte[] bytes = reader.ReadBytes(length);
            if (bytes.Length != length) throw new EndOfStreamException("Child agent response is incomplete.");
            string value = new UTF8Encoding(false, true).GetString(bytes);
            if (status != 0) throw new ChildAgentCommandRejectedException("Child agent rejected command: " + value);
            return value;
        }
    }
    internal static bool ServeOne(Stream stream, IChildAgentOperations operations, Func<bool> identityValid)
    {
        int kind = stream.ReadByte();
        if (kind < 0 || kind == 0x53) return false;
        using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
        {
            int length = reader.ReadInt32();
            if (length < 0 || length > MaxPayload || !Enum.IsDefined(typeof(ChildAgentOperation), (byte)kind))
                throw new InvalidDataException("Child agent command frame is invalid.");
            byte[] bytes = reader.ReadBytes(length);
            if (bytes.Length != length) throw new EndOfStreamException("Child agent command is incomplete.");
            string payload = new UTF8Encoding(false, true).GetString(bytes);
            string value; byte status;
            try
            {
                if (!identityValid()) throw new InvalidOperationException("Child session or parent ownership changed.");
                value = operations.Execute((ChildAgentOperation)kind, payload) ?? "";
                if (!identityValid()) throw new InvalidOperationException("Child session or parent ownership changed.");
                status = 0;
            }
            catch (Exception ex)
            {
                value = ex.GetType().Name + ": " + ex.Message;
                if (value.Length > 512) value = value.Substring(0, 512);
                status = 1;
            }
            byte[] response = new UTF8Encoding(false, true).GetBytes(value);
            if (response.Length > MaxPayload) throw new InvalidDataException("Child agent result exceeds its limit.");
            writer.Write(status); writer.Write(response.Length); writer.Write(response); writer.Flush();
            return true;
        }
    }
}
