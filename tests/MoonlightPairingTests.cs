using System;
using System.IO;
using System.Web.Script.Serialization;

static class MoonlightPairingTests
{
    private static int cases;
    private const string IdA = "0123456789abcdef0123456789abcdef";
    private const string IdB = "fedcba9876543210fedcba9876543210";
    private static string Pairing(string id, string name, string address)
    { return "{\"id\":\"" + id + "\",\"name\":\"" + name + "\",\"address\":\"" + address + "\"}"; }
    private static string List(params string[] requests)
    { return "{\"pairings\":[" + String.Join(",", requests) + "]}"; }
    private static void Check(bool condition, string reason)
    { cases++; if (!condition) throw new Exception(reason); }
    private static void Reject<T>(Action action, string reason) where T : Exception
    {
        cases++;
        try { action(); } catch (T) { return; }
        throw new Exception(reason);
    }
    private sealed class Runtime : IVerifiedChildSunshine
    {
        internal bool Owned = true;
        internal int Checks;
        public string HostName { get { return "ChildStream-child-7"; } }
        public string ManualAddress { get { return "192.168.1.25:48050"; } }
        public void AssertStillOwned()
        {
            Checks++;
            if (!Owned) throw new InvalidOperationException("Synthetic runtime owner changed.");
        }
    }
    private sealed class Api : ISunshinePairingApi
    {
        internal string Pending = List(Pairing(IdA, "Phone", "192.168.1.40"));
        internal string Reply = "{\"status\":true}";
        internal int Gets, Posts;
        internal string Body;
        internal Action OnGet, OnPost;
        public string GetPendingJson() { Gets++; if (OnGet != null) OnGet(); return Pending; }
        public string SubmitPinJson(string body)
        { Posts++; Body = body; if (OnPost != null) OnPost(); return Reply; }
    }
    private sealed class Transport : IVerifiedSunshinePairingTransport
    {
        internal string Method, Path, Body;
        public string Send(string method, string path, string body)
        { Method = method; Path = path; Body = body; return method == "GET" ? List() : "{\"status\":true}"; }
    }
    private static void Protocol()
    {
        var transport = new Transport();
        var api = new SunshinePairingApi(transport);
        Check(api.GetPendingJson() == List() && transport.Method == "GET" &&
            transport.Path == "/api/pin" && transport.Body == null, "pending endpoint");
        Check(api.SubmitPinJson("{\"pairing_id\":\"x\"}") == "{\"status\":true}" &&
            transport.Method == "POST" && transport.Path == "/api/pin", "PIN endpoint");
        Reject<InvalidDataException>(() => api.SubmitPinJson(""), "empty PIN body rejected");
        Check(SunshinePairingProtocol.ParsePending(List()).Count == 0, "empty request list");
        Check(SunshinePairingProtocol.ParsePending(List(Pairing(IdA, "Phone", "192.168.1.40"))).Count == 1,
            "one request with metadata");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParsePending("{}"), "missing list");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParsePending("{"), "invalid JSON");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParsePending(
            List(Pairing("bad", "Phone", "192.168.1.40"))), "bad ID");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParsePending(
            List(Pairing(IdA, "Phone", "192.168.1.40"), Pairing(IdA.ToUpperInvariant(), "Other", "192.168.1.41"))),
            "duplicate ID");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParsePending(
            List(Pairing(IdA, "", "192.168.1.40"))), "missing name");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParsePending(
            List(Pairing(IdA, "Phone", ""))), "missing address");
        Check(!SunshinePairingProtocol.ValidPin("１２３４") && !SunshinePairingProtocol.ValidPin("12345") &&
            SunshinePairingProtocol.ValidPin("0123"), "ASCII four-digit PIN");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.BuildPinRequest(IdA, "12a4", "Phone"), "bad PIN body");
        Check(SunshinePairingProtocol.ParseApproval("{\"status\":true}"), "positive handshake");
        Check(!SunshinePairingProtocol.ParseApproval("{\"status\":false}"), "rejected handshake");
        Reject<InvalidDataException>(() => SunshinePairingProtocol.ParseApproval("{\"status\":\"true\"}"), "ambiguous status");
    }
    private static void Flow()
    {
        var runtime = new Runtime();
        var api = new Api();
        Reject<ArgumentNullException>(() => new MoonlightPairingCoordinator(null, api), "no unverified runtime");
        Reject<ArgumentNullException>(() => new MoonlightPairingCoordinator(runtime, null), "no implicit API");
        var flow = new MoonlightPairingCoordinator(runtime, api);
        Check(flow.HostName == "ChildStream-child-7" && flow.ManualAddress.Contains(":48050"), "verified host display");
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "refresh required");
        flow.Refresh();
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", false), "consent required");
        Check(api.Posts == 0, "consent refusal made no POST");
        flow.Refresh();
        Reject<InvalidOperationException>(() => flow.Approve(IdB, "1234", true), "unlisted request");
        Check(api.Posts == 0, "unlisted request made no POST");
        flow.Refresh();
        Check(flow.Approve(IdA, "0123", true), "one approved Moonlight handshake");
        var body = new JavaScriptSerializer().DeserializeObject(api.Body) as System.Collections.Generic.IDictionary<string, object>;
        Check((string)body["pairing_id"] == IdA && (string)body["pin"] == "0123" &&
            (string)body["name"] == "Phone", "exact ID and request shape");
        Check(api.Gets == 4 && api.Posts == 1 && runtime.Checks >= 8, "ownership rechecked around API operations");
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "0123", true), "snapshot consumed");
        flow.Refresh();
        api.Reply = "{\"status\":false}";
        Check(!flow.Approve(IdA, "1234", true), "wrong PIN or timeout is not success");
        flow.Refresh();
        api.Pending = List(Pairing(IdA, "Another", "192.168.1.40"));
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "name drift");
        Check(api.Posts == 2, "no POST after name drift");
        api.Pending = List(Pairing(IdA, "Phone", "192.168.1.40"));
        flow.Refresh();
        api.Pending = List(Pairing(IdA, "Phone", "192.168.1.41"));
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "address drift");
        Check(api.Posts == 2, "no POST after address drift");
        api.Pending = List(Pairing(IdA, "Phone", "192.168.1.40"));
        flow.Refresh();
        api.Pending = List(Pairing(IdB, "Phone", "192.168.1.40"));
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "request disappeared");
        Check(api.Posts == 2, "no POST after ID drift");
        api.Pending = List(Pairing(IdA, "Phone", "192.168.1.40"));
        flow.Refresh();
        runtime.Owned = false;
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "runtime drift");
        Check(api.Posts == 2, "no POST after ownership loss");
        runtime.Owned = true;
        flow.Refresh();
        api.OnGet = () => runtime.Owned = false;
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "runtime drift during refresh");
        Check(api.Posts == 2, "no POST after mid-read ownership loss");
        api.OnGet = null;
        runtime.Owned = true;
        flow.Refresh();
        api.OnPost = () => runtime.Owned = false;
        Reject<InvalidOperationException>(() => flow.Approve(IdA, "1234", true), "ambiguous result after POST");
        Check(api.Posts == 3, "at most one POST for selected request");
    }
    public static int Main()
    {
        Protocol(); Flow();
        Console.WriteLine("Moonlight pairing: " + cases + " offline assertions passed.");
        return 0;
    }
}
