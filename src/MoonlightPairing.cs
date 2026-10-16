using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

// Pairing is deliberately separate from child-session enablement and from
// Sunshine startup. A runtime can supply this capability only after its exact
// child generation, process, configuration root, TLS identity, and port owner
// have been verified. No native Sunshine endpoint is an acceptable fallback.
internal interface IVerifiedChildSunshine
{
    string HostName { get; }
    string ManualAddress { get; }
    void AssertStillOwned();
}

internal sealed class PendingMoonlightPairing
{
    internal readonly string Id, Name, Address;
    internal PendingMoonlightPairing(string id, string name, string address)
    { Id = id; Name = name; Address = address; }
}

internal interface ISunshinePairingApi
{
    string GetPendingJson();
    string SubmitPinJson(string requestJson);
}

// The transport must be created only for the verified child-owned HTTPS
// endpoint with its certificate pinned. This API adapter never discovers or
// selects a Sunshine process on its own.
internal interface IVerifiedSunshinePairingTransport
{
    string Send(string method, string path, string jsonBody);
}

internal sealed class SunshinePairingApi : ISunshinePairingApi
{
    private readonly IVerifiedSunshinePairingTransport transport;
    internal SunshinePairingApi(IVerifiedSunshinePairingTransport transport)
    {
        if (transport == null) throw new ArgumentNullException("transport");
        this.transport = transport;
    }
    public string GetPendingJson() { return transport.Send("GET", "/api/pin", null); }
    public string SubmitPinJson(string requestJson)
    {
        if (String.IsNullOrWhiteSpace(requestJson))
            throw new InvalidDataException("A selected PIN request is required.");
        return transport.Send("POST", "/api/pin", requestJson);
    }
}

internal static class SunshinePairingProtocol
{
    private static readonly Regex IdPattern = new Regex(@"\A[0-9a-fA-F]{32}\z", RegexOptions.CultureInvariant);
    private static readonly Regex PinPattern = new Regex(@"\A[0-9]{4}\z", RegexOptions.CultureInvariant);

    internal static bool ValidId(string value) { return value != null && IdPattern.IsMatch(value); }
    internal static bool ValidPin(string value) { return value != null && PinPattern.IsMatch(value); }

    internal static IList<PendingMoonlightPairing> ParsePending(string json)
    {
        if (String.IsNullOrWhiteSpace(json) || json.Length > 65536)
            throw new InvalidDataException("The pairing response is empty or too large.");
        object value;
        try { value = new JavaScriptSerializer { MaxJsonLength = 65536 }.DeserializeObject(json); }
        catch (Exception ex) { throw new InvalidDataException("The pairing response is invalid JSON.", ex); }
        var root = value as IDictionary<string, object>;
        object pairings;
        if (root == null || !root.TryGetValue("pairings", out pairings))
            throw new InvalidDataException("The pairing response has no request list.");
        var entries = pairings as object[];
        if (entries == null || entries.Length > 32)
            throw new InvalidDataException("The pairing request list is invalid.");
        var result = new List<PendingMoonlightPairing>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (object item in entries)
        {
            var entry = item as IDictionary<string, object>;
            object id, name, address;
            if (entry == null || !entry.TryGetValue("id", out id) ||
                !entry.TryGetValue("name", out name) || !entry.TryGetValue("address", out address))
                throw new InvalidDataException("A pairing request has missing fields.");
            string idText = id as string, nameText = name as string, addressText = address as string;
            if (!ValidId(idText) || !ids.Add(idText) || String.IsNullOrWhiteSpace(nameText) ||
                String.IsNullOrWhiteSpace(addressText) || Encoding.UTF8.GetByteCount(nameText) > 128 ||
                nameText.Length > 128 || addressText.Length > 128 ||
                nameText.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0 ||
                addressText.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                throw new InvalidDataException("A pairing request is malformed or ambiguous.");
            result.Add(new PendingMoonlightPairing(idText, nameText, addressText));
        }
        return result;
    }

    internal static string BuildPinRequest(string id, string pin, string name)
    {
        if (!ValidId(id) || !ValidPin(pin) || String.IsNullOrWhiteSpace(name) ||
            Encoding.UTF8.GetByteCount(name) > 128)
            throw new InvalidDataException("The selected pairing request or PIN is invalid.");
        return new JavaScriptSerializer().Serialize(new Dictionary<string, string> {
            { "pairing_id", id }, { "pin", pin }, { "name", name }
        });
    }

    internal static bool ParseApproval(string json)
    {
        if (String.IsNullOrWhiteSpace(json) || json.Length > 4096)
            throw new InvalidDataException("The pairing approval response is invalid.");
        object value;
        try { value = new JavaScriptSerializer().DeserializeObject(json); }
        catch (Exception ex) { throw new InvalidDataException("The pairing approval response is invalid JSON.", ex); }
        var root = value as IDictionary<string, object>;
        object status;
        if (root == null || !root.TryGetValue("status", out status) || !(status is bool))
            throw new InvalidDataException("The pairing approval result is ambiguous.");
        return (bool)status;
    }
}

internal sealed class MoonlightPairingCoordinator
{
    private readonly IVerifiedChildSunshine runtime;
    private readonly ISunshinePairingApi api;
    private IList<PendingMoonlightPairing> lastSeen;
    internal MoonlightPairingCoordinator(IVerifiedChildSunshine runtime, ISunshinePairingApi api)
    {
        if (runtime == null || api == null) throw new ArgumentNullException("Pairing runtime and API are required.");
        this.runtime = runtime; this.api = api;
    }
    internal string HostName { get { runtime.AssertStillOwned(); return runtime.HostName; } }
    internal string ManualAddress { get { runtime.AssertStillOwned(); return runtime.ManualAddress; } }

    internal IList<PendingMoonlightPairing> Refresh()
    {
        lastSeen = null;
        runtime.AssertStillOwned();
        IList<PendingMoonlightPairing> requests = SunshinePairingProtocol.ParsePending(api.GetPendingJson());
        runtime.AssertStillOwned();
        lastSeen = new List<PendingMoonlightPairing>(requests);
        return new List<PendingMoonlightPairing>(requests);
    }

    internal bool Approve(string selectedId, string pin, bool explicitConsent)
    {
        if (!explicitConsent) throw new InvalidOperationException("Explicit pairing approval is required.");
        if (!SunshinePairingProtocol.ValidId(selectedId) || !SunshinePairingProtocol.ValidPin(pin) || lastSeen == null)
            throw new InvalidOperationException("Refresh and select a valid request before approval.");
        PendingMoonlightPairing selected = null;
        foreach (var request in lastSeen)
            if (String.Equals(request.Id, selectedId, StringComparison.OrdinalIgnoreCase)) selected = request;
        lastSeen = null; // Every attempt consumes the displayed snapshot.
        if (selected == null) throw new InvalidOperationException("The selected request was not displayed.");
        runtime.AssertStillOwned();
        IList<PendingMoonlightPairing> current = SunshinePairingProtocol.ParsePending(api.GetPendingJson());
        runtime.AssertStillOwned();
        PendingMoonlightPairing matching = null;
        foreach (var request in current)
            if (String.Equals(request.Id, selected.Id, StringComparison.OrdinalIgnoreCase)) matching = request;
        if (matching == null || !String.Equals(matching.Name, selected.Name, StringComparison.Ordinal) ||
            !String.Equals(matching.Address, selected.Address, StringComparison.Ordinal))
            throw new InvalidOperationException("The selected Moonlight request changed; refresh before approving.");
        runtime.AssertStillOwned();
        string body = SunshinePairingProtocol.BuildPinRequest(selected.Id, pin, selected.Name);
        bool paired = SunshinePairingProtocol.ParseApproval(api.SubmitPinJson(body));
        runtime.AssertStillOwned();
        return paired; // Sunshine returns true only after the Moonlight handshake.
    }
}
