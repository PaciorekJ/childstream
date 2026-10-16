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
        internal int Plans, Applies;
        internal bool AllowSimulatedApply;
        public bool IsInstalledApplication { get { return false; } }
        public string Plan(string candidateZip, string reviewedSha256, string sunshineZip)
        { Plans++; return new string('a', 64); }
        public void Apply(string candidateZip, string reviewedSha256, string sunshineZip, string planHash)
        { if (!AllowSimulatedApply) throw new Exception("Mutation must not run in rendered fixture.");
          Applies++; }
        public void Recover(string candidateZip, string reviewedSha256)
        { throw new Exception("Mutation must not run in rendered fixture."); }
        public void Uninstall(string candidateZip, string reviewedSha256)
        { throw new Exception("Mutation must not run in rendered fixture."); }
        public void FetchSunshine(string candidateZip, string reviewedSha256, string destination)
        { throw new Exception("Download must not run in rendered fixture."); }
        public void LaunchMaintenanceAfterExit(string candidateZip, string reviewedSha256,
            bool uninstall, int parentPid)
        { throw new Exception("Maintenance must not run in rendered fixture."); }
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
                Check(form.ClientRectangle.Contains(control.Bounds) ||
                    (form.AutoScroll && form.DisplayRectangle.Contains(control.Bounds)),
                    label + ": " + control.Text);
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
            installer.AllowSimulatedApply = true;
            var approve = Find<Button>(form, b => b.Text == "Approve install");
            var openInstalled = Find<Button>(form, b => b.Text == "Open installed app");
            approve.PerformClick();
            for (int i = 0; i < 100 && (installer.Applies == 0 || !openInstalled.Enabled); i++)
            { Application.DoEvents(); Thread.Sleep(10); }
            Check(installer.Applies == 1 && openInstalled.Enabled,
                "approved simulated file install exposes the installed-app handoff");
            Save(form, folder, "install-handoff-simulated");
        }
        var bundleFixture = new ProductBundle { Root = folder,
            CandidatePath = Path.Combine(folder, "payload", "ChildStream-candidate.zip"),
            SunshinePath = Path.Combine(folder, "payload", SunshineReleasePin.AssetName),
            CandidateSha256 = new string('e', 64), SourceSha = new string('d', 40) };
        var bundledInstaller = new Installer();
        using (var bundled = new ProductInstallDialog(bundledInstaller, true, bundleFixture))
        {
            Save(bundled, folder, "install-bundled-audio-plan-simulated");
            var zip = Find<TextBox>(bundled, b => b.AccessibleName == "Candidate ZIP:");
            var digest = Find<TextBox>(bundled, b => b.AccessibleName == "Reviewed candidate SHA-256:");
            var archive = Find<TextBox>(bundled, b => b.AccessibleName == "Pinned Sunshine ZIP:");
            var hash = Find<TextBox>(bundled, b => b.AccessibleName == "Exact install plan SHA-256:");
            for (int i = 0; i < 100 && hash.Text.Length != 64; i++)
            { Application.DoEvents(); Thread.Sleep(10); }
            Check(zip.Text == bundleFixture.CandidatePath && digest.Text == bundleFixture.CandidateSha256 &&
                archive.Text == bundleFixture.SunshinePath && hash.Text == new string('a', 64) &&
                bundledInstaller.Plans == 1 && zip.ReadOnly && digest.ReadOnly && archive.ReadOnly,
                "normal installer form auto-carries verified bundled payloads into read-only plan");
            Save(bundled, folder, "install-bundled-audio-ready-simulated");
        }
        foreach (int percent in new[] { 150, 200 })
        using (var scaled = new ProductInstallDialog(new Installer(), true))
        {
            float factor = percent / 100f;
            scaled.Scale(new SizeF(factor, factor));
            ScaleFixtureFonts(scaled, factor);
            scaled.Size = new Size(Math.Min(scaled.Width, 1000), Math.Min(scaled.Height, 700));
            Save(scaled, folder, "install-" + percent + "-simulated");
            CheckVisibleControlsInside(scaled, "scaled install action remains on screen");
            scaled.AutoScrollPosition = new Point(0, scaled.VerticalScroll.Maximum);
            Application.DoEvents();
            var uninstall = Find<Button>(scaled, b => b.Text == "Uninstall files");
            Check(uninstall != null && scaled.ClientRectangle.IntersectsWith(uninstall.Bounds),
                "scrolled high-DPI recovery action is reachable");
            Save(scaled, folder, "install-" + percent + "-recovery-simulated");
            scaled.AutoScrollPosition = new Point(scaled.HorizontalScroll.Maximum,
                scaled.VerticalScroll.Maximum);
            Application.DoEvents();
            var close = Find<Button>(scaled, b => b.Text == "Close");
            Check(close != null && scaled.ClientRectangle.IntersectsWith(close.Bounds),
                "scrolled high-DPI rightmost action is reachable");
        }
        using (var setup = new SetupDialog(new Setup(), true))
        {
            Save(setup, folder, "scoped-setup-simulated");
            Check(Find<Button>(setup, b => b.Text == "Read LAN journal") != null &&
                Find<Button>(setup, b => b.Text == "Enable feature") != null,
                "LAN and child-feature approvals are visibly separate");
        }
        int requested = 0;
        var local = new ToolStripMenuItem("Start ChildStream Sunshine") { Enabled = true };
        var lanAction = new ToolStripMenuItem("Start Sunshine on approved LAN…") { Enabled = false };
        var pairAction = new ToolStripMenuItem("Pair Moonlight…") { Enabled = false };
        var recoverAction = new ToolStripMenuItem("Recover failed ChildStream start") { Enabled = false };
        local.Click += (s, e) => requested++;
        using (var shell = new Form { Text = "ChildStream child desktop — simulated",
            Width = 1100, Height = 300 })
        {
            var bar = StreamingActionBar.Create(local, lanAction, pairAction, recoverAction);
            shell.Controls.Add(bar);
            shell.Controls.Add(new Label { Dock = DockStyle.Bottom, Height = 36,
                Text = "Verified child desktop. Choose local readiness or separately approved LAN streaming." });
            Save(shell, folder, "runtime-local-ready-simulated");
            ((ToolStripButton)bar.Items[0]).PerformClick();
            Check(requested == 1, "rendered guided action routes to the normal application command");
            local.Enabled = false; lanAction.Enabled = true;
            Check(!bar.Items[0].Enabled && bar.Items[1].Enabled,
                "guided LAN transition follows actual menu state");
            Save(shell, folder, "runtime-lan-reconfigure-simulated");
            lanAction.Enabled = false; pairAction.Enabled = false; recoverAction.Enabled = true;
            Check(bar.Items[3].Enabled && !bar.Items[2].Enabled,
                "uncertain recovery remains reachable without exposing pairing");
            Save(shell, folder, "runtime-recovery-simulated");
        }
        var guideItems = new [] {
            new ToolStripMenuItem("Review Windows setup…") { Enabled = true },
            new ToolStripMenuItem("Start ChildStream Sunshine") { Enabled = true },
            new ToolStripMenuItem("Start Sunshine on approved LAN…") { Enabled = false },
            new ToolStripMenuItem("Pair Moonlight…") { Enabled = false },
            new ToolStripMenuItem("Start Steam Big Picture in child") { Enabled = false },
            new ToolStripMenuItem("Request Minecraft Dungeons in child") { Enabled = false },
            new ToolStripMenuItem("Set game audio in child Volume Mixer…") { Enabled = false },
            new ToolStripMenuItem("Enable verified game audio…") { Enabled = false },
            new ToolStripMenuItem("Stop ChildStream streaming") { Enabled = false },
            new ToolStripMenuItem("Recover failed ChildStream start") { Enabled = false }
        };
        string guideStatus = "Verified child desktop. Choose local Sunshine readiness.";
        using (var guide = new ChildStreamGuideForm(() => guideStatus, guideItems, true))
        {
            Save(guide, folder, "guide-local-ready-simulated");
            guideItems[1].Enabled = false; guideItems[2].Enabled = true;
            guideStatus = "Local ChildStream Sunshine ready. Approve a scoped LAN plan for Moonlight.";
            guide.RefreshState(); Save(guide, folder, "guide-lan-reconfigure-simulated");
            guideItems[2].Enabled = false; guideItems[3].Enabled = true;
            guideItems[4].Enabled = true; guideItems[8].Enabled = true;
            guideItems[6].Enabled = true;
            guideStatus = "Exact game launched. Select Minecraft Dungeons output in child Volume Mixer; render session pending on {child-audio-2}.";
            guide.RefreshState(); Save(guide, folder, "guide-audio-route-pending-simulated");
            guideStatus = "WrongEndpoint: game renders to {child-audio}; Sunshine captures {child-audio-2}. Change only the game's output in child Volume Mixer.";
            guide.RefreshState(); Save(guide, folder, "guide-audio-route-wrong-simulated");
            guideItems[7].Enabled = true;
            guideStatus = "Exact game render observed on {child-audio-2}; enable verified game audio to restart only owned Sunshine.";
            guide.RefreshState(); Save(guide, folder, "guide-audio-ready-simulated");
            guideItems[7].Enabled = false;
            guideStatus = "Owned capture-only Sunshine is audio enabled; Moonlight reconnected to the same certificate and endpoint.";
            guide.RefreshState(); Save(guide, folder, "guide-audio-reconnect-simulated");
            guideItems[3].Enabled = guideItems[4].Enabled = guideItems[8].Enabled = false;
            guideItems[9].Enabled = true;
            guideStatus = "Selected child audio endpoint disappeared. Recover only the exact owned stream.";
            guide.RefreshState(); Save(guide, folder, "guide-audio-lost-simulated");
            guideItems[2].Enabled = false; guideItems[9].Enabled = true;
            guideStatus = "Owned startup outcome uncertain. Exact process recovery is required.";
            guide.RefreshState(); Save(guide, folder, "guide-recovery-simulated");
            Check(Find<Button>(guide, b => b.Text == "Recover start").Enabled &&
                !Find<Button>(guide, b => b.Text == "Pair Moonlight").Enabled,
                "production guide exposes recovery and keeps pairing disabled on uncertain runtime");
            var lost = ChildStreamingUiState.From(new System.Collections.Generic.Dictionary<string, object> {
                { "stage", "SunshineLost" }, { "lanPosture", "LocalOnly" } }, false);
            guideItems[9].Enabled = lost.Recover; guideItems[2].Enabled = lost.StartLan;
            guideStatus = "Owned local Sunshine exited. Reconcile its exact process before retrying.";
            guide.RefreshState(); Save(guide, folder, "guide-lost-recovery-simulated");
            Check(lost.Recover && !lost.StartLan && !lost.Pair &&
                Find<Button>(guide, b => b.Text == "Recover start").Enabled,
                "idle local process loss exposes exact recovery through real guided controls");
            var audioLost = ChildStreamingUiState.From(new System.Collections.Generic.Dictionary<string, object> {
                { "stage", "SunshineAudioLost" }, { "lanPosture", "LocalOnly" } }, false);
            Check(audioLost.Recover && !audioLost.Pair && !audioLost.StartLan,
                "lost selected audio endpoint exposes exact recovery without pairing");
            var withdrawn = ChildStreamingUiState.From(new System.Collections.Generic.Dictionary<string, object> {
                { "stage", "SunshineWithdrawn" }, { "lanPosture", "Withdrawn" } }, false);
            Check(withdrawn.StartLan && !withdrawn.Pair && !withdrawn.Recover,
                "withdrawn LAN listener offers a new approved start without stale pairing");
            CheckVisibleControlsInside(guide, "guided action remains visible");
        }
        string json = "{\"displays\":[{\"id\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\",\"name\":\"Child Display 1\"}," +
            "{\"id\":\"{12100db6-5a9d-40c4-9c10-c3b1f606a632}\",\"name\":\"Child Display 2\"}]," +
            "\"audio\":[\"{endpoint-1}\",\"{endpoint-2}\"]," +
            "\"audioNames\":{\"{endpoint-1}\":\"Speakers\",\"{endpoint-2}\":\"ChildStream Capture\"}}";
        ChildCapabilityCatalog catalog = ChildCapabilityCatalog.Parse(json);
        Check(catalog.AudioNames["{endpoint-2}"] == "ChildStream Capture" &&
            catalog.SelectionPayload(catalog.Displays[0].Id, "{endpoint-2}", null).Contains("{endpoint-2}"),
            "friendly labels cannot replace stable endpoint identities in the child selection payload");
        using (var chooser = new CapabilitySelectionDialog(catalog, true))
        {
            Save(chooser, folder, "multiple-child-devices-simulated");
            var boxes = new System.Collections.Generic.List<ListBox>();
            foreach (Control control in chooser.Controls) if (control is ListBox) boxes.Add((ListBox)control);
            Check(boxes.Count == 2 && boxes[0].SelectedIndex < 0 && boxes[1].SelectedIndex < 0,
                "multiple child devices require an explicit selection");
            boxes[0].SelectedIndex = 1; boxes[1].SelectedIndex = 1;
            Check(chooser.SelectedDisplay == catalog.Displays[1].Id && chooser.SelectedAudio == "{endpoint-2}" &&
                boxes[1].Items[1].ToString().Contains("ChildStream Capture"),
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
