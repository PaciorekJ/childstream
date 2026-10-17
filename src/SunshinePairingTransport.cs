using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

// A dedicated TLS connection avoids ambient proxies, HTTP credential caches,
// global certificate callbacks and framework-wide TLS protocol changes.
internal sealed class PinnedSunshinePairingTransport : IChildSunshineTransport
{
    private readonly Uri endpoint;
    private readonly string certificateSha256, username, password;
    private readonly IVerifiedChildSunshine owner;
    internal PinnedSunshinePairingTransport(Uri endpoint, string certificateSha256,
        string username, string password, IVerifiedChildSunshine owner)
    {
        if (endpoint == null || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.Host != "127.0.0.1" ||
            endpoint.AbsolutePath != "/" || !String.IsNullOrEmpty(endpoint.Query) ||
            endpoint.Port <= 0 || endpoint.Port > 65535 || owner == null ||
            String.IsNullOrWhiteSpace(username) || username.IndexOfAny(new [] { ':', '\r', '\n', '\0' }) >= 0 ||
            String.IsNullOrWhiteSpace(password) || password.IndexOfAny(new [] { '\r', '\n', '\0' }) >= 0 ||
            String.IsNullOrEmpty(certificateSha256) || !System.Text.RegularExpressions.Regex.IsMatch(
                certificateSha256, "\\A[0-9a-fA-F]{64}\\z"))
            throw new InvalidDataException("A verified loopback endpoint, certificate and dedicated credentials are required.");
        this.endpoint = endpoint; this.certificateSha256 = certificateSha256;
        this.username = username; this.password = password; this.owner = owner;
    }
    private bool CertificateMatches(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
    {
        if (certificate == null) return false;
        using (var sha = SHA256.Create())
        {
            string actual = BitConverter.ToString(sha.ComputeHash(certificate.GetRawCertData())).Replace("-", "");
            return String.Equals(actual, certificateSha256, StringComparison.OrdinalIgnoreCase);
        }
    }
    private static string ReadLine(Stream stream, int limit)
    {
        var bytes = new List<byte>();
        while (bytes.Count <= limit)
        {
            int next = stream.ReadByte();
            if (next < 0) throw new EndOfStreamException("Sunshine response ended during headers.");
            if (next == '\n')
            {
                if (bytes.Count == 0 || bytes[bytes.Count-1] != '\r') throw new InvalidDataException("Malformed HTTPS response line.");
                bytes.RemoveAt(bytes.Count-1);
                return Encoding.ASCII.GetString(bytes.ToArray());
            }
            bytes.Add((byte)next);
        }
        throw new InvalidDataException("Sunshine response header is too large.");
    }
    private static byte[] ReadExact(Stream stream, int length)
    {
        byte[] data = new byte[length]; int offset = 0;
        while (offset < length)
        {
            int count = stream.Read(data, offset, length-offset);
            if (count <= 0) throw new EndOfStreamException("Sunshine response body is incomplete.");
            offset += count;
        }
        return data;
    }
    private static string ReadResponse(Stream stream)
    {
        string status = ReadLine(stream, 256);
        if (status != "HTTP/1.1 200 OK" && status != "HTTP/1.0 200 OK")
            throw new InvalidOperationException("Verified Sunshine pairing endpoint did not return HTTP 200.");
        int headerBytes = 0, length = -1;
        bool json = false, chunked = false;
        while (true)
        {
            string line = ReadLine(stream, 2048); headerBytes += line.Length + 2;
            if (headerBytes > 8192) throw new InvalidDataException("Sunshine response headers exceed the limit.");
            if (line.Length == 0) break;
            int colon = line.IndexOf(':');
            if (colon <= 0) throw new InvalidDataException("Malformed Sunshine response header.");
            string name = line.Substring(0, colon).Trim(), value = line.Substring(colon+1).Trim();
            if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                json = value.StartsWith("application/json", StringComparison.OrdinalIgnoreCase);
            else if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                if (length >= 0 || !Int32.TryParse(value, out length) || length < 0 || length > 65536)
                    throw new InvalidDataException("Sunshine response length is invalid.");
            }
            else if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                chunked = value.Equals("chunked", StringComparison.OrdinalIgnoreCase);
        }
        if (!json || chunked || length < 0)
            throw new InvalidDataException("Sunshine pairing response requires JSON and a bounded Content-Length.");
        return new UTF8Encoding(false, true).GetString(ReadExact(stream, length));
    }
    public string Send(string method, string path, string jsonBody)
    {
        if (path != "/api/pin" || (method != "GET" && method != "POST") ||
            (method == "GET" && jsonBody != null) ||
            (method == "POST" && (String.IsNullOrEmpty(jsonBody) || Encoding.UTF8.GetByteCount(jsonBody) > 4096)))
            throw new InvalidOperationException("Only the pinned Sunshine pairing API is permitted.");
        return SendCore(method, path, jsonBody, true);
    }
    // The pinned Sunshine prerelease exposes this first-credential operation only
    // while its owned credential file has no configured username. A preexisting
    // account returns 401; no credential takeover or native fallback is tried.
    internal bool BootstrapFirstCredentials()
    {
        string body = new JavaScriptSerializer().Serialize(new Dictionary<string, string> {
            { "currentUsername", "" }, { "currentPassword", "" },
            { "newUsername", username }, { "newPassword", password },
            { "confirmNewPassword", password }
        });
        string response = SendCore("POST", "/api/password", body, false);
        return SunshinePairingProtocol.ParseApproval(response);
    }
    bool IChildSunshineTransport.BootstrapFirstCredentials() { return BootstrapFirstCredentials(); }
    private string SendCore(string method, string path, string jsonBody, bool authenticate)
    {
        if (path != "/api/pin" && path != "/api/password")
            throw new InvalidOperationException("Sunshine endpoint is outside the fixed allowlist.");
        owner.AssertStillOwned();
        using (var tcp = new TcpClient(AddressFamily.InterNetwork))
        {
            IAsyncResult pending = tcp.BeginConnect(IPAddress.Loopback, endpoint.Port, null, null);
            if (!pending.AsyncWaitHandle.WaitOne(5000)) throw new TimeoutException("Verified Sunshine endpoint did not connect.");
            tcp.EndConnect(pending);
            tcp.ReceiveTimeout = method == "POST" ? 30000 : 5000;
            tcp.SendTimeout = 5000;
            using (var tls = new SslStream(tcp.GetStream(), false, CertificateMatches))
            {
                tls.AuthenticateAsClient("127.0.0.1", null, SslProtocols.Tls12, false);
                tls.ReadTimeout = method == "POST" ? 30000 : 5000;
                tls.WriteTimeout = 5000;
                owner.AssertStillOwned();
                byte[] body = jsonBody == null ? new byte[0] : Encoding.UTF8.GetBytes(jsonBody);
                string headers = method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + endpoint.Port +
                    "\r\n" + (authenticate ? "Authorization: Basic " + Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(username + ":" + password)) + "\r\n" : "") +
                    "Accept: application/json\r\nConnection: close\r\n" +
                    (method == "POST" ? "Content-Type: application/json\r\nContent-Length: " + body.Length + "\r\n" : "") + "\r\n";
                byte[] prefix = Encoding.ASCII.GetBytes(headers);
                tls.Write(prefix, 0, prefix.Length);
                if (body.Length != 0) tls.Write(body, 0, body.Length);
                tls.Flush();
                string response = ReadResponse(tls);
                owner.AssertStillOwned();
                return response;
            }
        }
    }
}
