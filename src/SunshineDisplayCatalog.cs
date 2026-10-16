using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

internal sealed class SunshineDisplayObservation
{
    internal string Id, Name;
    internal bool Active;
}
internal static class SunshineDisplayCatalog
{
    private const string Marker = "Currently available display devices:";
    internal static IList<SunshineDisplayObservation> ParseOwnedLog(string log)
    {
        if (String.IsNullOrEmpty(log) || log.Length > 1024 * 1024)
            throw new InvalidDataException("Owned Sunshine display log is missing or too large.");
        int mark = log.LastIndexOf(Marker, StringComparison.Ordinal);
        int begin = mark < 0 ? -1 : log.IndexOf('[', mark + Marker.Length);
        if (begin < 0 || begin - mark > 128) throw new InvalidDataException("Owned Sunshine display catalog is absent.");
        int depth = 0, end = -1; bool quoted = false, escaped = false;
        for (int i = begin; i < log.Length && i - begin <= 65536; i++)
        {
            char ch = log[i];
            if (escaped) { escaped = false; continue; }
            if (quoted && ch == '\\') { escaped = true; continue; }
            if (ch == '"') { quoted = !quoted; continue; }
            if (quoted) continue;
            if (ch == '[') depth++;
            else if (ch == ']' && --depth == 0) { end = i; break; }
        }
        if (end < 0) throw new InvalidDataException("Owned Sunshine display catalog is incomplete.");
        object parsed;
        try { parsed = new JavaScriptSerializer { MaxJsonLength = 65536 }.DeserializeObject(log.Substring(begin, end-begin+1)); }
        catch (Exception ex) { throw new InvalidDataException("Owned Sunshine display catalog is malformed.", ex); }
        object[] entries = parsed as object[];
        if (entries == null || entries.Length == 0 || entries.Length > 32)
            throw new InvalidDataException("Owned Sunshine display catalog has an implausible count.");
        var result = new List<SunshineDisplayObservation>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (object value in entries)
        {
            var row = value as IDictionary<string, object>; object id, name, info;
            if (row == null || !row.TryGetValue("device_id", out id) ||
                !row.TryGetValue("display_name", out name) || !row.TryGetValue("info", out info))
                throw new InvalidDataException("Owned Sunshine display observation is incomplete.");
            string key = id as string, display = name as string; Guid guid;
            if (key == null || !Guid.TryParse(key, out guid) || display == null || !ids.Add(key))
                throw new InvalidDataException("Owned Sunshine display identity is invalid or duplicated.");
            result.Add(new SunshineDisplayObservation { Id = key, Name = display, Active = info != null });
        }
        return result;
    }
    internal static SunshineDisplayObservation RequireUniqueActive(string log)
    {
        SunshineDisplayObservation selected = null;
        foreach (var display in ParseOwnedLog(log))
            if (display.Active)
            {
                if (selected != null) throw new InvalidOperationException("Multiple active child displays require explicit selection.");
                selected = display;
            }
        if (selected == null) throw new InvalidOperationException("No active child display was observed by owned Sunshine.");
        return selected;
    }
}
