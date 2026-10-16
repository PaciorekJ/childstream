using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

internal static class UiJourneyTests
{
    private static int checks;
    private static void Check(bool value, string label)
    { checks++; if (!value) throw new Exception(label); }
    private sealed class Installer : IProductInstallWorkflow
    {
        internal int Plans;
        public string Plan(string candidateZip, string reviewedSha256, string sunshineZip)
        { Plans++; return new string('a', 64); }
        public void Apply(string candidateZip, string reviewedSha256, string sunshineZip, string planHash)
        { throw new Exception("Mutation must not run in rendered fixture."); }
        public void Recover(string candidateZip, string reviewedSha256)
        { throw new Exception("Mutation must not run in rendered fixture."); }
        public void Uninstall(string candidateZip, string reviewedSha256)
        { throw new Exception("Mutation must not run in rendered fixture."); }
        public void FetchSunshine(string candidateZip, string reviewedSha256, string destination)
        { throw new Exception("Download must not run in rendered fixture."); }
    }
    private sealed class Setup : ISetupWorkflow
    {
        public string Execute(SetupRequest request) { return "LAN plan " + new string('b', 64); }
        public void RegisterOwnAgentTask() { throw new Exception("Fixture must not register tasks."); }
        public void RemoveOwnAgentTask() { throw new Exception("Fixture must not remove tasks."); }
    }
    private sealed class Runtime : IVerifiedChildSunshine
    {
        public string HostName { get { return "ChildStream"; } }
        public string ManualAddress { get { return "192.168.50.10:48089"; } }
        public void AssertStillOwned() { }
    }
    private sealed class Pairing : ISunshinePairingApi
    {
        public string GetPendingJson()
        { return "{\"pairings\":[{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"name\":\"Fire TV\",\"address\":\"192.168.50.24\"}]}"; }
        public string SubmitPinJson(string json) { return "{\"status\":false}"; }
    }
    private static T Find<T>(Control control, Func<T, bool> match) where T : Control
    {
        foreach (Control child in control.Controls)
        {
            T selected = child as T;
            if (selected != null && match(selected)) return selected;
            T nested = Find(child, match); if (nested != null) return nested;
        }
        return null;
    }
    private static void Save(Form form, string folder, string name)
    {
        form.StartPosition = FormStartPosition.Manual;
        form.Location = new Point(-2000, -2000);
        form.Show(); Application.DoEvents();
        using (var bitmap = new Bitmap(form.Width, form.Height))
        { form.DrawToBitmap(bitmap, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
          bitmap.Save(Path.Combine(folder, name + ".png")); }
    }
    private static void CheckVisibleControlsInside(Form form, string label)
    {
        foreach (Control control in form.Controls)
            if (control.Visible && control is Button)
                Check(form.ClientRectangle.Contains(control.Bounds), label + ": " + control.Text);
    }
    private static void ScaleFixtureFonts(Control root, float factor)
    {
        foreach (Control child in root.Controls)
        {
            child.Font = new Font(child.Font.FontFamily, child.Font.Size * factor, child.Font.Style);
            ScaleFixtureFonts(child, factor);
        }
    }
    [STAThread]
    public static int Main(string[] args)
    {
        Application.EnableVisualStyles();
        string folder = args.Length == 1 ? args[0] : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "screenshots");
        Directory.CreateDirectory(folder);
        var installer = new Installer();
        using (var form = new ProductInstallDialog(installer, true))
        {
            Save(form, folder, "install-first-run-simulated");
            var zip = Find<TextBox>(form, b => b.AccessibleName == "Candidate ZIP:");
            var digest = Find<TextBox>(form, b => b.AccessibleName == "Reviewed candidate SHA-256:");
            var archive = Find<TextBox>(form, b => b.AccessibleName == "Pinned Sunshine ZIP:");
            var planHash = Find<TextBox>(form, b => b.AccessibleName == "Exact install plan SHA-256:");
            var plan = Find<Button>(form, b => b.Text == "Review install");
            Check(zip != null && digest != null && archive != null && planHash != null && plan != null,
                "installation dialog exposes the source and separate approval inputs");
            zip.Text = "C:\\reviewed\\candidate.zip"; archive.Text = "C:\\reviewed\\Sunshine-Windows-AMD64-lite.zip";
            digest.Text = "invalid"; plan.PerformClick(); Application.DoEvents();
            Check(installer.Plans == 0, "invalid outer archive digest never reaches the install workflow");
            Save(form, folder, "install-blocked-simulated");
            digest.Text = new string('c', 64); plan.PerformClick();
            for (int i = 0; i < 100 && (planHash.Text.Length != 64 || !plan.Enabled); i++)
            { Application.DoEvents(); Thread.Sleep(10); }
            Check(installer.Plans == 1 && planHash.Text == new string('a', 64),
                "read-only production UI controller carries exact reviewed plan result");
            Save(form, folder, "install-plan-ready-simulated");
        }
        foreach (int percent in new[] { 150, 200 })
        using (var scaled = new ProductInstallDialog(new Installer(), true))
        {
            float factor = percent / 100f;
            scaled.Scale(new SizeF(factor, factor));
            ScaleFixtureFonts(scaled, factor);
            Save(scaled, folder, "install-" + percent + "-simulated");
            CheckVisibleControlsInside(scaled, "scaled install action remains on screen");
        }
        using (var setup = new SetupDialog(new Setup(), true))
        {
            Save(setup, folder, "scoped-setup-simulated");
            Check(Find<Button>(setup, b => b.Text == "Read LAN journal") != null &&
                Find<Button>(setup, b => b.Text == "Enable feature") != null,
                "LAN and child-feature approvals are visibly separate");
        }
        string json = "{\"displays\":[{\"id\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\",\"name\":\"Child Display 1\"}," +
            "{\"id\":\"{12100db6-5a9d-40c4-9c10-c3b1f606a632}\",\"name\":\"Child Display 2\"}]," +
            "\"audio\":[\"Child Audio 1\",\"Child Audio 2\"]}";
        ChildCapabilityCatalog catalog = ChildCapabilityCatalog.Parse(json);
        using (var chooser = new CapabilitySelectionDialog(catalog, true))
        {
            Save(chooser, folder, "multiple-child-devices-simulated");
            var boxes = new System.Collections.Generic.List<ListBox>();
            foreach (Control control in chooser.Controls) if (control is ListBox) boxes.Add((ListBox)control);
            Check(boxes.Count == 2 && boxes[0].SelectedIndex < 0 && boxes[1].SelectedIndex < 0,
                "multiple child devices require an explicit selection");
            boxes[0].SelectedIndex = 1; boxes[1].SelectedIndex = 1;
            Check(chooser.SelectedDisplay == catalog.Displays[1].Id && chooser.SelectedAudio == "Child Audio 2",
                "UI selection resolves exact child-observed IDs");
        }
        var coordinator = new MoonlightPairingCoordinator(new Runtime(), new Pairing());
        using (var pairing = new MoonlightPairingDialog(coordinator,
            coordinator.HostName, coordinator.ManualAddress))
        {
            pairing.Text += " — simulated fixture";
            Save(pairing, folder, "pairing-ready-simulated");
            var refresh = Find<Button>(pairing, b => b.Text == "Refresh requests");
            refresh.PerformClick();
            var list = Find<ListBox>(pairing, b => true);
            for (int i = 0; i < 100 && (list.Items.Count == 0 || !refresh.Enabled); i++)
            { Application.DoEvents(); Thread.Sleep(10); }
            Check(list.Items.Count == 1 && list.Items[0].ToString().Contains("Fire TV"),
                "real pairing dialog renders authenticated pending request fixture");
            Save(pairing, folder, "pairing-pending-simulated");
            FieldInfo statusField = typeof(MoonlightPairingDialog).GetField("status",
                BindingFlags.Instance | BindingFlags.NonPublic);
            ((Label)statusField.GetValue(pairing)).Text = "Pairing was rejected or timed out. Refresh and try again.";
            Save(pairing, folder, "pairing-rejected-simulated");
        }
        Console.WriteLine("Rendered simulated ChildStream journey assertions passed: " + checks);
        return 0;
    }
}
