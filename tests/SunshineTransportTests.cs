using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

static class SunshineTransportTests
{
    private sealed class Owned : IVerifiedChildSunshine
    {
        internal bool Valid = true;
        internal int Calls;
        public string HostName { get { return "ChildStream"; } }
        public string ManualAddress { get { return "192.168.1.50"; } }
        public void AssertStillOwned() { Calls++; if (!Valid) throw new InvalidOperationException("Owner drifted."); }
    }
    private sealed class Fixture : IDisposable
    {
        private readonly string directory, metadata;
        private readonly Process server;
        internal readonly string Fingerprint;
        internal readonly Uri Endpoint;
        internal string Error { get { return File.Exists(metadata + ".error") ? File.ReadAllText(metadata + ".error") : null; } }
        internal string Captured
        {
            get
            {
                if (!server.WaitForExit(6000)) throw new TimeoutException("Fixture did not finish its one request.");
                if (File.Exists(metadata + ".error")) throw new Exception(File.ReadAllText(metadata + ".error"));
                return File.Exists(metadata + ".request") ? File.ReadAllText(metadata + ".request") : "";
            }
        }
        internal Fixture(int code, string response, int delayMs = 0)
        {
            string script = Environment.GetEnvironmentVariable("CHILDSTREAM_TLS_FIXTURE_SCRIPT");
            if (String.IsNullOrEmpty(script) || !File.Exists(script)) throw new InvalidOperationException("Fixture script missing.");
            directory = Path.Combine(Path.GetTempPath(), "ChildStreamTlsFixture-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory); metadata = Path.Combine(directory, "ready.txt");
            string responsePath = Path.Combine(directory, "response.txt");
            File.WriteAllText(responsePath, response, new UTF8Encoding(false));
            string arguments = "\"" + script + "\" --metadata \"" + metadata +
                "\" --code " + code + " --response-file \"" + responsePath + "\"" +
                " --delay " + delayMs;
            server = Process.Start(new ProcessStartInfo("python.exe", arguments) { UseShellExecute = false,
                CreateNoWindow = true, WorkingDirectory = directory });
            for (int i = 0; i < 100 && !File.Exists(metadata) && !server.HasExited; i++) Thread.Sleep(100);
            if (!File.Exists(metadata)) throw new TimeoutException("Ephemeral TLS fixture did not become ready.");
            string[] fields = File.ReadAllText(metadata).Split('|'); int port;
            if (fields.Length != 2 || !Int32.TryParse(fields[0], out port)) throw new InvalidDataException("Fixture identity malformed.");
            Fingerprint = fields[1]; Endpoint = new Uri("https://127.0.0.1:" + port + "/");
        }
        public void Dispose()
        {
            if (server != null)
            {
                if (!server.WaitForExit(6000)) { server.Kill(); server.WaitForExit(2000); }
                server.Dispose();
            }
            if (directory != null && directory.StartsWith(Path.GetTempPath() + "ChildStreamTlsFixture-",
                StringComparison.OrdinalIgnoreCase)) Directory.Delete(directory, true);
        }
    }
    private static int assertions;
    private static void Check(bool condition, string message)
    { assertions++; if (!condition) throw new Exception(message); }
    private static void Reject(Action action, string message)
    { bool rejected = false; try { action(); } catch { rejected = true; } Check(rejected, message); }
    public static int Main()
    {
        if (String.IsNullOrEmpty(Environment.GetEnvironmentVariable("CHILDSTREAM_TLS_FIXTURE_SCRIPT")))
        { Console.WriteLine("Ephemeral loopback TLS tests SKIPPED (socket fixture not enabled)."); return 0; }
        var owner = new Owned();
        using (var fixture = new Fixture(200, "{\"pairings\":[]}"))
        {
            var transport = new PinnedSunshinePairingTransport(fixture.Endpoint, fixture.Fingerprint, "owned", "secret", owner);
            string pending;
            try { pending = transport.Send("GET", "/api/pin", null); }
            catch { serverError(fixture); throw; }
            Check(pending == "{\"pairings\":[]}", "authenticated GET response");
            Check(fixture.Captured.StartsWith("GET /api/pin "), "exact GET path");
            Check(fixture.Captured.Contains("Authorization: Basic " + Convert.ToBase64String(
                Encoding.UTF8.GetBytes("owned:secret"))), "explicit Basic authentication");
            Check(owner.Calls >= 2, "owner checked around request");
        }
        using (var fixture = new Fixture(200, "{\"status\":true}"))
        {
            var transport = new PinnedSunshinePairingTransport(fixture.Endpoint, fixture.Fingerprint, "owned", "secret", owner);
            Check(transport.Send("POST", "/api/pin", "{\"pairing_id\":\"abc\"}").Contains("true"), "POST response");
            Check(fixture.Captured.Contains("BODY:{\"pairing_id\":\"abc\"}"), "selected request transmitted");
        }
        using (var fixture = new Fixture(200, "{}"))
            Reject(() => new PinnedSunshinePairingTransport(fixture.Endpoint, new string('0', 64), "owned", "secret", owner)
                .Send("GET", "/api/pin", null), "wrong TLS certificate rejected");
        using (var fixture = new Fixture(401, "{}"))
            Reject(() => new PinnedSunshinePairingTransport(fixture.Endpoint, fixture.Fingerprint, "owned", "wrong", owner)
                .Send("GET", "/api/pin", null), "authentication failure rejected");
        using (var fixture = new Fixture(302, "{}"))
            Reject(() => new PinnedSunshinePairingTransport(fixture.Endpoint, fixture.Fingerprint, "owned", "secret", owner)
                .Send("GET", "/api/pin", null), "authentication-bearing redirect rejected");
        using (var fixture = new Fixture(200, new string('x', 65537)))
            Reject(() => new PinnedSunshinePairingTransport(fixture.Endpoint, fixture.Fingerprint, "owned", "secret", owner)
                .Send("GET", "/api/pin", null), "oversized response rejected");
        using (var fixture = new Fixture(200, "{}", 7000))
            Reject(() => new PinnedSunshinePairingTransport(fixture.Endpoint, fixture.Fingerprint, "owned", "secret", owner)
                .Send("GET", "/api/pin", null), "bounded timeout");
        owner.Valid = false;
        Reject(() => new PinnedSunshinePairingTransport(new Uri("https://127.0.0.1:48090/"), new string('0',64),
            "owned", "secret", owner).Send("GET", "/api/pin", null), "owner drift before network rejected");
        Console.WriteLine("Ephemeral loopback TLS transport assertions passed: " + assertions);
        return 0;
    }
    private static void serverError(Fixture fixture)
    { Console.WriteLine("TLS fixture error: " + fixture.Error); }
}
