using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal sealed class ChildCapabilityCatalog
{
    internal sealed class Display
    { internal string Id, Name; public override string ToString()
      { return Name + "  ·  " + Id.Trim('{', '}').Substring(0, 8); } }
    internal readonly List<Display> Displays = new List<Display>();
    internal readonly List<string> Audio = new List<string>();
    internal readonly Dictionary<string, string> AudioNames = new Dictionary<string, string>(StringComparer.Ordinal);
    internal static ChildCapabilityCatalog Parse(string json)
    {
        if (String.IsNullOrEmpty(json) || json.Length > 8192)
            throw new InvalidDataException("Child capability response is missing or oversized.");
        var root = new JavaScriptSerializer().DeserializeObject(json) as IDictionary<string, object>;
        object rawDisplays, rawAudio, rawNames;
        if (root == null || (root.Count != 2 && root.Count != 3) ||
            !root.TryGetValue("displays", out rawDisplays) ||
            !root.TryGetValue("audio", out rawAudio))
            throw new InvalidDataException("Child capability response is malformed.");
        if (root.Count == 3 && !root.TryGetValue("audioNames", out rawNames))
            throw new InvalidDataException("Child audio label response is malformed.");
        var displays = rawDisplays as object[]; var audio = rawAudio as object[];
        if (displays == null || audio == null || displays.Length < 1 || displays.Length > 32 ||
            audio.Length < 1 || audio.Length > 64)
            throw new InvalidDataException("No bounded child display/audio choice exists.");
        var result = new ChildCapabilityCatalog();
        var displayIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var audioIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (object value in displays)
        {
            var item = value as IDictionary<string, object>; object id, name; Guid parsed;
            if (item == null || item.Count != 2 || !item.TryGetValue("id", out id) ||
                !item.TryGetValue("name", out name) || !(id is string) || !(name is string) ||
                !Guid.TryParse((string)id, out parsed) || !displayIds.Add((string)id) ||
                String.IsNullOrWhiteSpace((string)name) || ((string)name).Length > 128)
                throw new InvalidDataException("Child display choice is malformed or duplicated.");
            result.Displays.Add(new Display { Id = (string)id, Name = (string)name });
        }
        foreach (object value in audio)
            if (!(value is string) || String.IsNullOrWhiteSpace((string)value) ||
                ((string)value).Length > 256 || !audioIds.Add((string)value))
                throw new InvalidDataException("Child audio choice is malformed or duplicated.");
            else result.Audio.Add((string)value);
        if (root.TryGetValue("audioNames", out rawNames))
        {
            var names = rawNames as IDictionary<string, object>;
            if (names == null || names.Count > result.Audio.Count)
                throw new InvalidDataException("Child audio labels are malformed.");
            foreach (var pair in names)
            {
                string name = pair.Value as string;
                if (!audioIds.Contains(pair.Key) || String.IsNullOrWhiteSpace(name) ||
                    name.Length > 128 || name.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                    throw new InvalidDataException("Child audio label has no exact endpoint identity.");
                result.AudioNames.Add(pair.Key, name);
            }
        }
        return result;
    }
    internal string SelectionPayload(string display, string audio, string address)
    {
        if (!Displays.Exists(d => String.Equals(d.Id, display, StringComparison.OrdinalIgnoreCase)) ||
            !Audio.Contains(audio)) throw new InvalidDataException("Selection is not in the current child catalog.");
        if (address == null) return new JavaScriptSerializer().Serialize(new { display = display, audio = audio });
        return new JavaScriptSerializer().Serialize(new { display = display, audio = audio, address = address });
    }
}

internal sealed class CapabilitySelectionDialog : Form
{
    private sealed class AudioChoice
    {
        internal string Id, Name;
        public override string ToString() { return Name == null ? Id : Name + "  ·  " + Id; }
    }
    private readonly ChildCapabilityCatalog catalog;
    private readonly ListBox displays, audio;
    internal string SelectedDisplay { get { return ((ChildCapabilityCatalog.Display)displays.SelectedItem).Id; } }
    internal string SelectedAudio { get { return ((AudioChoice)audio.SelectedItem).Id; } }
    internal CapabilitySelectionDialog(ChildCapabilityCatalog catalog, bool simulated = false)
    {
        this.catalog = catalog;
        Text = simulated ? "ChildStream child devices — simulated" : "Select child display and audio";
        Width = 660; Height = 445; MinimumSize = new Size(580, 400);
        StartPosition = FormStartPosition.CenterParent;
        var note = new Label { Left = 20, Top = 16, Width = 610, Height = 48,
            Text = "Choose devices observed inside the exact child session. Sunshine captures the selected audio endpoint; " +
                "the game must render to it through an existing route. ChildStream does not change Windows defaults." };
        var displayLabel = new Label { Left = 20, Top = 74, Width = 295, Text = "Child display" };
        var audioLabel = new Label { Left = 335, Top = 74, Width = 295, Text = "Child audio endpoint" };
        displays = new ListBox { Left = 20, Top = 99, Width = 295, Height = 220,
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Bottom,
            AccessibleName = "Child observed display selection" };
        audio = new ListBox { Left = 335, Top = 99, Width = 295, Height = 220,
            Anchor = AnchorStyles.Top | AnchorStyles.Right | AnchorStyles.Bottom,
            AccessibleName = "Child observed audio selection" };
        foreach (var item in catalog.Displays) displays.Items.Add(item);
        foreach (string item in catalog.Audio)
        {
            string name;
            audio.Items.Add(new AudioChoice { Id = item,
                Name = catalog.AudioNames.TryGetValue(item, out name) ? name : null });
        }
        if (displays.Items.Count == 1) displays.SelectedIndex = 0;
        if (audio.Items.Count == 1) audio.SelectedIndex = 0;
        var confirm = new Button { Left = 405, Top = 335, Width = 105, Text = "Continue",
            DialogResult = DialogResult.OK, Enabled = displays.SelectedItem != null && audio.SelectedItem != null };
        var cancel = new Button { Left = 525, Top = 335, Width = 105, Text = "Cancel",
            DialogResult = DialogResult.Cancel };
        displays.SelectedIndexChanged += (s, e) => confirm.Enabled = displays.SelectedItem != null && audio.SelectedItem != null;
        audio.SelectedIndexChanged += (s, e) => confirm.Enabled = displays.SelectedItem != null && audio.SelectedItem != null;
        Controls.AddRange(new Control[] { note, displayLabel, audioLabel, displays, audio, confirm, cancel });
        AcceptButton = confirm; CancelButton = cancel;
    }
}
