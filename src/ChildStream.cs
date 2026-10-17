using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[ComImport, Guid("302D8188-0052-4807-806A-362B628F9AC5"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMsRdpExtendedSettings
{
    void put_Property([MarshalAs(UnmanagedType.BStr)] string name, ref object value);
    void get_Property([MarshalAs(UnmanagedType.BStr)] string name, out object value);
}

public class RdpBox : AxHost
{
    // Microsoft RDP Client Control (MsTscAx)
    public RdpBox() : base("8B918B82-7985-4C24-89DF-C33AD2BBFBCD") { }
    public object Ocx { get { return GetOcx(); } }
}

internal static class ChildRdpAudioPolicy
{
    // Microsoft RDP ActiveX: 1 leaves playback on the remote child computer.
    // This is necessary for the selected render endpoint to receive game sound.
    // It does not establish that the endpoint is private to that session.
    // Never fall back to mode 0 (parent viewer) or 2 (no server playback).
    internal static void Configure(object control)
    {
        if (control == null) throw new InvalidOperationException("RDP audio control is unavailable.");
        dynamic rdp = control;
        rdp.SecuredSettings2.AudioRedirectionMode = 1;
        rdp.AdvancedSettings7.AudioCaptureRedirectionMode = false;
        if ((int)rdp.SecuredSettings2.AudioRedirectionMode != 1 ||
            (bool)rdp.AdvancedSettings7.AudioCaptureRedirectionMode)
            throw new InvalidOperationException("RDP child audio redirection settings were not retained.");
    }
}

internal static class StreamingActionBar
{
    internal static ToolStrip Create(params ToolStripMenuItem[] actions)
    {
        var bar = new ToolStrip { Dock = DockStyle.Top, GripStyle = ToolStripGripStyle.Hidden,
            AccessibleName = "ChildStream guided streaming actions" };
        foreach (ToolStripMenuItem action in actions)
        {
            ToolStripMenuItem selected = action;
            var button = new ToolStripButton(action.Text) { Enabled = action.Enabled,
                ToolTipText = action.Text, DisplayStyle = ToolStripItemDisplayStyle.Text };
            selected.EnabledChanged += (s, e) => button.Enabled = selected.Enabled;
            button.Click += (s, e) => selected.PerformClick();
            bar.Items.Add(button);
        }
        return bar;
    }
}

internal sealed class ChildStreamingUiState
{
    internal bool StartLocal, StartLan, Stop, Recover, Pair, EnableAudio;
    internal static ChildStreamingUiState From(System.Collections.Generic.IDictionary<string, object> status,
        bool pairingAvailable)
    {
        if (status == null || !status.ContainsKey("stage") || !status.ContainsKey("lanPosture"))
            throw new InvalidDataException("Owned runtime status is incomplete.");
        string stage = Convert.ToString(status["stage"]);
        string posture = Convert.ToString(status["lanPosture"]);
        bool ready = stage == "SunshineReady";
        bool available = stage == "NoSunshine" || stage == "SunshineWithdrawn" ||
            stage == "SunshineAudioWithdrawn";
        bool lost = stage == "Uncertain" || stage == "SunshineLost" ||
            stage == "SunshineBoundaryLost" || stage == "SunshineAudioLost";
        if (!ready && !available && !lost)
            throw new InvalidDataException("Unrecognized owned runtime stage.");
        return new ChildStreamingUiState { StartLocal = available,
            StartLan = available || ready && posture == "LocalOnly",
            Stop = ready, Recover = lost, Pair = ready && pairingAvailable,
            EnableAudio = ready && Convert.ToString(status["audioMode"]) != "CaptureEnabled" &&
                Convert.ToString(status["gameAudio"]) == "GameRenderObserved" };
    }
}

internal sealed class ChildStreamGuideForm : Form
{
    private readonly Func<string> currentStatus;
    private readonly Label status;
    private readonly ToolStripMenuItem[] actions;
    private readonly Button[] buttons;
    private readonly Timer refresh;
    internal ChildStreamGuideForm(Func<string> currentStatus, ToolStripMenuItem[] actions,
        bool simulated = false)
    {
        if (currentStatus == null || actions == null || actions.Length != 10)
            throw new ArgumentException("Ten guided ChildStream actions are required.");
        this.currentStatus = currentStatus; this.actions = actions;
        Text = simulated ? "ChildStream guided play — simulated" : "ChildStream guided play";
        Width = 670; Height = 700; MinimumSize = new Size(620, 620);
        AutoScroll = true; StartPosition = FormStartPosition.CenterParent;
        var title = new Label { Left = 20, Top = 18, Width = 610, Height = 32,
            Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold),
            Text = "Set up, stream, and recover the child desktop" };
        status = new Label { Left = 20, Top = 56, Width = 610, Height = 54,
            BorderStyle = BorderStyle.FixedSingle };
        var instructions = new [] {
            "1. Review the separate Windows setup plan. Feature changes need approval.",
            "2. Start ChildStream Sunshine in the verified child session.",
            "3. Approve a scoped LAN plan, then switch to the phone/TV address.",
            "4. Open Moonlight on the phone or Fire TV and approve its PIN here.",
            "5. Start Steam Big Picture only after the child stream is verified.",
            "6. Request Minecraft Dungeons and observe it in the child session.",
            "7. In child Volume Mixer, select its output. ChildStream checks the exact game render session.",
            "8. Recheck the route and restart only owned Sunshine with capture-only audio.",
            "Stop only ChildStream-owned streaming. The child desktop stays open.",
            "If startup failed, reconcile the exact owned process before retrying." };
        var shortNames = new [] { "Review setup", "Start local", "Switch to LAN",
            "Pair Moonlight", "Start Steam", "Launch game", "Set game audio", "Enable game audio", "Stop streaming", "Recover start" };
        buttons = new Button[10];
        for (int i = 0; i < actions.Length; i++)
        {
            int row = i;
            int top = 122 + i * 51;
            var label = new Label { Left = 20, Top = top, Width = 408, Height = 40,
                Text = instructions[i] };
            var button = new Button { Left = 444, Top = top + 2, Width = 185,
                Height = 34, Text = shortNames[i], Enabled = actions[i].Enabled };
            button.Click += (s, e) => this.actions[row].PerformClick();
            buttons[i] = button;
            Controls.Add(label); Controls.Add(button);
        }
        Controls.Add(title); Controls.Add(status);
        RefreshState();
        refresh = new Timer { Interval = 1000 };
        refresh.Tick += (s, e) => RefreshState();
        Shown += (s, e) => refresh.Start();
        FormClosed += (s, e) => { refresh.Stop(); refresh.Dispose(); };
    }
    internal void RefreshState()
    {
        status.Text = currentStatus();
        for (int i = 0; i < actions.Length; i++) buttons[i].Enabled = actions[i].Enabled;
    }
}

static class Program
{
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSIsChildSessionsEnabled(out bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSGetChildSessionId(out uint sessionId);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSLogoffSession(IntPtr server, uint sessionId, bool wait);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);
    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WtsInfoExLevel1
    {
        public uint SessionId;
        public int SessionState;
        public int SessionFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string DomainName;
        public long LogonTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WtsInfoEx
    {
        public int Level;
        public WtsInfoExLevel1 Data;
    }

    sealed class WindowsChildSessionApi : IChildSessionApi
    {
        public uint CurrentSessionId { get { return (uint)Process.GetCurrentProcess().SessionId; } }

        public ChildSessionIdentity? ReadAssociatedChild()
        {
            uint sessionId;
            if (!WTSGetChildSessionId(out sessionId))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSGetChildSessionId failed");
            if (sessionId == uint.MaxValue) return null;

            IntPtr buffer;
            uint bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, 25, out buffer, out bytes))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSSessionInfoEx query failed");
            try
            {
                if (buffer == IntPtr.Zero || bytes < Marshal.SizeOf(typeof(WtsInfoEx)))
                    throw new InvalidOperationException("The child session information was incomplete.");
                WtsInfoEx info = (WtsInfoEx)Marshal.PtrToStructure(buffer, typeof(WtsInfoEx));
                if (info.Level != 1 || info.Data.SessionId != sessionId || info.Data.LogonTime <= 0)
                    throw new InvalidOperationException("The child session generation could not be verified.");
                return new ChildSessionIdentity(sessionId, info.Data.LogonTime);
            }
            finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
        }

        public bool Logoff(uint sessionId)
        {
            if (!WTSLogoffSession(IntPtr.Zero, sessionId, true))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSLogoffSession failed");
            return true;
        }
    }

    static string baseDir = AppDomain.CurrentDomain.BaseDirectory;
    static string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ChildStream", "launcher.log");
    static string intentDir = GetIntentDirectory();

    private static string PromptLanAddress(Form owner)
    {
        using (var dialog = new Form { Text = "ChildStream LAN streaming", Width = 480, Height = 225,
            StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog,
            MinimizeBox = false, MaximizeBox = false })
        {
            var description = new Label { Left = 18, Top = 16, Width = 430, Height = 55,
                Text = "Enter the exact private IPv4 address from the separately approved ChildStream LAN plan. " +
                    "The child runtime will reverify the scoped firewall and network boundary before launch." };
            var input = new TextBox { Left = 18, Top = 80, Width = 425, MaxLength = 45,
                AccessibleName = "Approved ChildStream LAN IPv4 address" };
            var confirm = new Button { Left = 260, Top = 119, Width = 85, Text = "Continue",
                DialogResult = DialogResult.OK };
            var cancel = new Button { Left = 355, Top = 119, Width = 85, Text = "Cancel",
                DialogResult = DialogResult.Cancel };
            dialog.Controls.AddRange(new Control[] { description, input, confirm, cancel });
            dialog.AcceptButton = confirm; dialog.CancelButton = cancel;
            return dialog.ShowDialog(owner) == DialogResult.OK ? input.Text.Trim() : null;
        }
    }

    static string GetIntentDirectory()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!Path.IsPathRooted(local)) throw new InvalidOperationException("Local application data path is unavailable.");
        return Path.Combine(local, "ChildStream", "session-intents");
    }

    static string RandomHex(int bytes)
    {
        byte[] value = new byte[bytes];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(value);
        return BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
    }

    static ChildAgentRequest CreateAgentRequest(uint parent, ChildSessionIdentity child)
    {
        int pid = Process.GetCurrentProcess().Id;
        ProductProcessIdentity image = new WindowsProductProcessHost().Read(pid);
        if (image == null || image.SessionId != (int)parent ||
            new WindowsRuntimeTokenReader().Read() != RuntimeTokenStatus.Limited)
            throw new InvalidOperationException("Limited parent process identity cannot be verified.");
        return new ChildAgentRequest { ParentSessionId = parent, Child = child,
            ParentPid = pid, ParentExecutableSha256 = image.ExecutableSha256,
            RequesterSid = WindowsIdentity.GetCurrent().User.Value,
            PipeName = "ChildStream-" + RandomHex(16), Nonce = RandomHex(32) };
    }

    static void Log(string msg)
    {
        try { Directory.CreateDirectory(Path.GetDirectoryName(logPath));
            File.AppendAllText(logPath, DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg + Environment.NewLine); } catch { }
    }

    static int[] ParseDisplayConfig(string value)
    {
        string[] parts = value.Trim().Split('x');
        if (parts.Length != 2 && parts.Length != 3)
            throw new FormatException("Expected WIDTHxHEIGHT or WIDTHxHEIGHTxSCALE.");
        int width, height, scale = 0;
        if (!int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out width) || width < 640 || width > 7680 ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out height) || height < 480 || height > 4320 ||
            (parts.Length == 3 && (!int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out scale) || scale < 100 || scale > 500)))
            throw new FormatException("Display dimensions or scale are outside supported bounds.");
        return new int[] { width, height, scale };
    }

    static int RemoveLegacyPasswordExplicitly()
    {
        var cleanup = new LegacyCredentialCleanup(Application.ExecutablePath,
            Path.Combine(baseDir, "cred.bin"), new WindowsLegacyFileAccess());
        LegacyCredentialStatus status = cleanup.Inspect();
        if (status == LegacyCredentialStatus.Present)
        {
            bool approved = MessageBox.Show("A file named cred.bin exists beside ChildStream.exe at:\n" +
                cleanup.CandidatePath + "\n\nIts provenance cannot be verified. Delete it only if you recognize this as the legacy ChildStream installation. Continue?", "ChildStream",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
            status = cleanup.RemoveWithApproval(approved);
        }
        string message = status == LegacyCredentialStatus.Absent ? "The legacy credential file is absent." :
            status == LegacyCredentialStatus.Removed ? "The legacy credential file was removed and its absence verified." :
            status == LegacyCredentialStatus.Cancelled ? "Credential cleanup was cancelled; no file was deleted." :
            status == LegacyCredentialStatus.Inaccessible ? "The legacy credential file is inaccessible. Check its permissions manually." :
            status == LegacyCredentialStatus.OutsideOwnedPath ? "The target is not a regular cred.bin beside ChildStream.exe. No file was deleted." :
            "Credential cleanup failed or could not be verified. No success is claimed.";
        MessageBox.Show(message, "ChildStream", MessageBoxButtons.OK,
            status == LegacyCredentialStatus.Absent || status == LegacyCredentialStatus.Removed ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        Log("explicit legacy credential cleanup: " + status);
        return status == LegacyCredentialStatus.Absent || status == LegacyCredentialStatus.Removed ? 0 : 1;
    }

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "-child-agent")
            return WindowsChildAgentEntry.Run(args[1]);
        if (args.Length > 0 && args[0] == "-enable")
        {
            MessageBox.Show("Child-session enablement requires the future transactional installer. No change was made.", "ChildStream");
            return 3;
        }
        if (args.Length > 0 && args[0] == "-check")
        {
            bool en2;
            if (!WTSIsChildSessionsEnabled(out en2)) return 2;
            Log("child sessions enabled = " + en2);
            return en2 ? 0 : 1;
        }
        if (args.Length > 0 && args[0] == "-resetpass") return RemoveLegacyPasswordExplicitly();
        if (args.Length > 0 && args[0] == "-reconcile-session")
        {
            try
            {
                uint parent = (uint)Process.GetCurrentProcess().SessionId;
                return new FileSignOutIntentStore(intentDir).ReconcileAbsentChild(new WindowsChildSessionApi(), parent) ? 0 : 4;
            }
            catch (Exception ex) { Log("session reconciliation failed: " + ex.Message); return 4; }
        }

        Application.EnableVisualStyles();
        var firstRun = new FirstRunController(new WindowsChildFeatureReader(),
            new WindowsRuntimeTokenReader(), new WindowsUnknownFeatureAttemptPolicy());
        using (var shell = new FirstRunForm(firstRun))
            if (shell.ShowDialog() != DialogResult.OK || !shell.StartSelected) return 0;
        if (!firstRun.CanStart) return 1;
        return RunViewer();
    }

    private static int RunViewer()
    {
        // A protected installed user with an exact approved limited task may
        // explicitly attempt connection when the feature query is inaccessible.
        // The live WTS association and ActiveX outcome remain authoritative.

        // Microsoft documents automatic child-session logon from an existing parent
        // session. Do not set UserName or ClearTextPassword on the RDP control.
        uint parentSessionId = (uint)Process.GetCurrentProcess().SessionId;
        var instanceMutex = new System.Threading.Mutex(false, @"Local\ChildStream.ParentSession." + parentSessionId);
        bool ownsInstance;
        try { ownsInstance = instanceMutex.WaitOne(0); }
        catch (System.Threading.AbandonedMutexException) { ownsInstance = true; }
        if (!ownsInstance) { instanceMutex.Dispose(); Log("another launcher owns this parent session"); return 5; }
        var lifecycle = new ChildSessionLifecycle(new WindowsChildSessionApi(), parentSessionId,
            new FileSignOutIntentStore(intentDir));
        var f = new Form { Text = "Child Session", Width = 1360, Height = 820 };
        Icon appIcon = SystemIcons.Application;
        try { appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        f.Icon = appIcon;
        var tray = new NotifyIcon { Icon = appIcon, Visible = true, Text = "Child Session" };
        dynamic ocx = null;
        WindowsChildTaskBootstrapHost agentHost = null;
        ChildAgentController agent = null;
        MoonlightPairingCoordinator pairingCoordinator = null;
        bool agentStartPending = false;
        bool runtimeActionPending = false;
        var statusBar = new StatusStrip();
        var statusText = new ToolStripStatusLabel("Waiting for a verified child desktop.");
        statusBar.Items.Add(statusText);
        var menu = new ContextMenuStrip();
        menu.Items.Add("Show", null, (s, e) => { f.Show(); f.WindowState = FormWindowState.Normal; f.Activate(); });
        var setupItem = new ToolStripMenuItem("Review Windows setup…");
        menu.Items.Add(setupItem);
        setupItem.Click += (s, e) =>
        { using (var dialog = new SetupDialog(new WindowsSetupWorkflow())) dialog.ShowDialog(f); };
        ToolStripMenuItem reconnectItem = new ToolStripMenuItem("Reconnect now");
        menu.Items.Add(reconnectItem);
        menu.Items.Add("Streaming readiness", null, (s, e) =>
        {
            string session = lifecycle.State == ChildLifecycleState.Connected && lifecycle.CheckConnectedIdentity()
                ? "Verified child session " + lifecycle.ObservedChild.Value.SessionId +
                  " (generation " + lifecycle.ObservedChild.Value.LogonTime + ")."
                : "No currently verified child desktop. State: " + lifecycle.State + ".";
            SunshineCollisionSnapshot collision = WindowsSunshineCollisionReader.Read();
            string conflict = SunshineStartupGate.Check(collision);
            MessageBox.Show(session + "\n" +
                (conflict ?? "No Sunshine service, process or default-family port collision was observed.") +
                "\nThe child runtime may start its own loopback Sunshine after exact session verification. " +
                "LAN streaming, independent capture, controllers and hardware rollback still require acceptance.",
                "ChildStream readiness", MessageBoxButtons.OK, MessageBoxIcon.Information);
        });
        menu.Items.Add("Inspect/remove legacy saved password", null, (s, e) => { RemoveLegacyPasswordExplicitly(); });
        var sunshineItem = new ToolStripMenuItem("Start ChildStream Sunshine") { Enabled = false };
        menu.Items.Add(sunshineItem);
        var lanSunshineItem = new ToolStripMenuItem("Start Sunshine on approved LAN…") { Enabled = false };
        menu.Items.Add(lanSunshineItem);
        var stopSunshineItem = new ToolStripMenuItem("Stop ChildStream streaming") { Enabled = false };
        var recoverSunshineItem = new ToolStripMenuItem("Recover failed ChildStream start") { Enabled = false };
        menu.Items.Add(stopSunshineItem); menu.Items.Add(recoverSunshineItem);
        var steamItem = new ToolStripMenuItem("Start Steam Big Picture in child") { Enabled = false };
        var gameItem = new ToolStripMenuItem("Request Minecraft Dungeons in child") { Enabled = false };
        var gameAudioItem = new ToolStripMenuItem("Set game audio in child Volume Mixer…") { Enabled = false };
        var enableGameAudioItem = new ToolStripMenuItem("Enable verified game audio…") { Enabled = false };
        var stopSteamItem = new ToolStripMenuItem("Stop exact owned child Steam/game") { Enabled = false };
        menu.Items.Add(steamItem); menu.Items.Add(gameItem); menu.Items.Add(gameAudioItem);
        menu.Items.Add(enableGameAudioItem); menu.Items.Add(stopSteamItem);
        var pairItem = new ToolStripMenuItem("Pair Moonlight…") { Enabled = false };
        menu.Items.Add(pairItem);
        pairItem.Click += async (s, e) =>
        {
            if (pairingCoordinator == null) return;
            try
            {
                string[] verified = await Task.Run(() => new [] { pairingCoordinator.HostName,
                    pairingCoordinator.ManualAddress });
                using (var dialog = new MoonlightPairingDialog(pairingCoordinator, verified[0], verified[1]))
                    dialog.ShowDialog(f);
            }
            catch (Exception ex)
            { statusText.Text = "Pairing ownership changed: " + ex.Message; pairItem.Enabled = false; pairingCoordinator = null; }
        };
        Func<Task<bool>> stopAgent = async () =>
        {
            if (agent == null) return true;
            try
            {
                var selected = agent;
                string state = await Task.Run(() => selected.Execute(ChildAgentOperation.Status, ""));
                var observed = new JavaScriptSerializer().DeserializeObject(state) as System.Collections.Generic.Dictionary<string, object>;
                if (observed == null || !observed.ContainsKey("steamStage") || !observed.ContainsKey("stage"))
                    throw new InvalidDataException("Child runtime status is incomplete.");
                string steamState = Convert.ToString(observed["steamStage"]);
                if (steamState != "NotStarted" && steamState != "Ended")
                    await Task.Run(() => selected.Execute(ChildAgentOperation.StopSteam, ""));
                if (Convert.ToString(observed["stage"]) == "SunshineReady" ||
                    Convert.ToString(observed["stage"]) == "SunshineBoundaryLost" ||
                    Convert.ToString(observed["stage"]) == "SunshineLost" ||
                    Convert.ToString(observed["stage"]) == "SunshineAudioLost")
                    await Task.Run(() => selected.Execute(ChildAgentOperation.StopSunshine, ""));
                if (Convert.ToString(observed["stage"]) == "Uncertain")
                    throw new InvalidOperationException("Resolve exact owned runtime uncertainty before closing the agent.");
                await Task.Run(() => selected.Stop());
                if (agentHost != null) agentHost.Dispose();
                agentHost = null; agent = null; pairingCoordinator = null;
                pairItem.Enabled = false; sunshineItem.Enabled = false; lanSunshineItem.Enabled = false;
                stopSunshineItem.Enabled = false; recoverSunshineItem.Enabled = false;
                steamItem.Enabled = false; gameItem.Enabled = false; stopSteamItem.Enabled = false;
                gameAudioItem.Enabled = false; enableGameAudioItem.Enabled = false;
                statusText.Text = "Child agent and owned Sunshine stopped. Child desktop remains available.";
                return true;
            }
            catch (Exception ex)
            {
                statusText.Text = "Child runtime stop is uncertain: " + ex.Message;
                Log(statusText.Text);
                MessageBox.Show(f, statusText.Text + "\nNo unrelated process was stopped.",
                    "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        };
        ToolStripMenuItem signOutItem = new ToolStripMenuItem("End session (sign out, closes games)");
        menu.Items.Add(signOutItem);
        signOutItem.Click += async (s, e) =>
        {
            int viewerState;
            try { viewerState = (int)ocx.Connected; }
            catch (Exception ex)
            {
                lifecycle.UnrecoverableError();
                Log("signout viewer-state check failed: " + ex.Message);
                MessageBox.Show("Viewer state could not be verified. No sign-out was attempted.", "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (lifecycle.State != ChildLifecycleState.Connected || viewerState != 1)
            {
                MessageBox.Show("Sign-out requires a connected, verified child session.", "ChildStream");
                return;
            }
            if (MessageBox.Show("Sign out the child session? All apps running in it will close.", "Child Session", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            if (!await stopAgent()) return;
            SignOutResult result = lifecycle.SignOut();
            Log("signout result: " + result + "; lifecycle: " + lifecycle.State + "; reason: " + lifecycle.FailureReason);
            if (result != SignOutResult.Complete)
            {
                reconnectItem.Enabled = false;
                signOutItem.Enabled = false;
                MessageBox.Show(result == SignOutResult.OutcomeUnknown
                    ? "Sign-out outcome is unknown. Automatic and manual reconnect are blocked. Inspect the child session before restarting the launcher."
                    : result == SignOutResult.PersistenceFailed
                    ? "Sign-out intent could not be saved. No sign-out was attempted. Reconnect is blocked.\n" + lifecycle.FailureReason
                    : "Child identity changed or could not be verified. No sign-out was attempted. Reconnect is blocked.\n" + lifecycle.FailureReason,
                    "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            tray.Visible = false;
            Application.Exit();
        };
        menu.Items.Add("Exit", null, async (s, e) =>
        { if (!await stopAgent()) return; tray.Visible = false; Application.Exit(); });
        tray.ContextMenuStrip = menu;
        tray.DoubleClick += (s, e) => { f.Show(); f.WindowState = FormWindowState.Normal; f.Activate(); };

        f.Resize += (s, e) => { if (f.WindowState == FormWindowState.Minimized) { f.Hide(); tray.ShowBalloonTip(1500, "Child Session", "Still running - session stays alive. Double-click to restore.", ToolTipIcon.Info); } };
        f.Show();

        var rdp = new RdpBox { Dock = DockStyle.Fill };
        f.Controls.Add(rdp);
        f.Controls.Add(statusBar);
        f.Controls.Add(StreamingActionBar.Create(setupItem, sunshineItem, lanSunshineItem,
            pairItem, steamItem, gameItem, gameAudioItem, enableGameAudioItem,
            stopSunshineItem, recoverSunshineItem));
        rdp.CreateControl();
        ocx = rdp.Ocx;

        Action bootstrapAgent = () =>
        {
            if (agent != null || agentStartPending || lifecycle.State != ChildLifecycleState.Connected ||
                !lifecycle.ObservedChild.HasValue) return;
            ChildSessionIdentity exactChild = lifecycle.ObservedChild.Value;
            agentStartPending = true;
            statusText.Text = "Starting the limited child runtime…";
            Task.Run(() =>
            {
                var host = new WindowsChildTaskBootstrapHost(new WindowsChildSessionApi(),
                    Application.ExecutablePath, CreateAgentRequest(parentSessionId, exactChild).ParentExecutableSha256);
                try
                {
                    ChildAgentRequest request = CreateAgentRequest(parentSessionId, exactChild);
                    var controller = new ChildAgentController(host, parentSessionId, exactChild,
                        Application.ExecutablePath, request.ParentExecutableSha256);
                    controller.Start(request);
                    return Tuple.Create(host, controller);
                }
                catch { host.Dispose(); throw; }
            }).ContinueWith(task =>
            {
                if (f.IsDisposed) { if (task.Status == TaskStatus.RanToCompletion) task.Result.Item1.Dispose(); return; }
                f.BeginInvoke((Action)(() =>
                {
                    agentStartPending = false;
                    if (task.IsFaulted || task.IsCanceled)
                    {
                        statusText.Text = "Child runtime unavailable: " +
                            (task.Exception == null ? "launch cancelled" : task.Exception.GetBaseException().Message);
                        Log(statusText.Text); return;
                    }
                    if (lifecycle.State != ChildLifecycleState.Connected || !lifecycle.ObservedChild.HasValue ||
                        !lifecycle.ObservedChild.Value.Equals(exactChild) || !lifecycle.CheckConnectedIdentity())
                    { task.Result.Item1.Dispose(); statusText.Text = "Child identity changed during runtime launch."; return; }
                    agentHost = task.Result.Item1; agent = task.Result.Item2;
                    sunshineItem.Enabled = true;
                    lanSunshineItem.Enabled = true;
                    recoverSunshineItem.Enabled = false;
                    statusText.Text = "Limited child agent verified. Start ChildStream Sunshine when ready.";
                }));
            });
        };
        Action<System.Collections.Generic.IDictionary<string, object>> applyStreamingState = observed =>
        {
            string stage = Convert.ToString(observed["stage"]);
            if (stage != "SunshineReady") pairingCoordinator = null;
            ChildStreamingUiState state = ChildStreamingUiState.From(observed,
                pairingCoordinator != null);
            sunshineItem.Enabled = !runtimeActionPending && state.StartLocal;
            lanSunshineItem.Enabled = !runtimeActionPending && state.StartLan;
            stopSunshineItem.Enabled = !runtimeActionPending && state.Stop;
            recoverSunshineItem.Enabled = !runtimeActionPending && state.Recover;
            pairItem.Enabled = !runtimeActionPending && state.Pair;
            gameAudioItem.Enabled = !runtimeActionPending &&
                Convert.ToString(observed.ContainsKey("steamStage") ? observed["steamStage"] : "") == "GameObserved" &&
                stage == "SunshineReady";
            enableGameAudioItem.Enabled = !runtimeActionPending && state.EnableAudio;
            if (stage == "SunshineWithdrawn")
                statusText.Text = "LAN boundary changed; exact owned Sunshine was withdrawn. Review LAN setup.";
            else if (stage == "SunshineAudioLost")
                statusText.Text = "Selected child audio endpoint disappeared. Recover only the exact ChildStream stream, then choose an active endpoint.";
            else if (stage == "SunshineAudioWithdrawn")
                statusText.Text = "Game audio evidence was lost. Exact owned Sunshine stopped; game and pairing remain. Choose an active endpoint and restart silently.";
            else if (stage == "SunshineLost" || stage == "SunshineBoundaryLost")
                statusText.Text = "Owned Sunshine was lost; reconcile its exact process before retrying.";
            else if (Convert.ToString(observed.ContainsKey("steamStage") ? observed["steamStage"] : "") == "GameObserved")
            {
                string route = Convert.ToString(observed.ContainsKey("gameAudio") ? observed["gameAudio"] : "ObservationIncomplete");
                string sink = Convert.ToString(observed.ContainsKey("captureEndpointName") ?
                    observed["captureEndpointName"] : observed.ContainsKey("captureEndpoint") ? observed["captureEndpoint"] : "");
                string kind = Convert.ToString(observed.ContainsKey("routeKind") ? observed["routeKind"] : "Unknown");
                string audioMode = Convert.ToString(observed.ContainsKey("audioMode") ? observed["audioMode"] : "");
                statusText.Text = route == "GameRenderIdle" && audioMode == "CaptureEnabled" ?
                    "The admitted game audio session is currently inactive on " + sink + "; owned capture-only Sunshine remains audio enabled. Physical isolation and playback remain unverified." :
                    route == "GameRenderObserved" ?
                    audioMode == "CaptureEnabled" ?
                    "Exact game render observed on " + sink + "; owned capture-only Sunshine is audio enabled. Physical isolation and playback remain unverified." :
                    "Exact game render observed on " + sink + " (" + kind + "). Select Enable verified game audio to restart only owned Sunshine." :
                    "Game audio: " + route + ". Sunshine is silent. Request child Volume Mixer, confirm the game's output as " + sink + ", then recheck.";
            }
        };
        Func<Task> refreshStreamingState = async () =>
        {
            if (agent == null || agent.Stage != ChildAgentStage.Ready) return;
            try
            {
                var selected = agent;
                var observed = await Task.Run(() => new ChildStreamingPresenter(selected,
                    lifecycle.ObservedChild.Value).Observe());
                if (agent == selected) applyStreamingState(observed);
            }
            catch
            {
                sunshineItem.Enabled = lanSunshineItem.Enabled = stopSunshineItem.Enabled = pairItem.Enabled = false;
                enableGameAudioItem.Enabled = false;
                pairingCoordinator = null; recoverSunshineItem.Enabled = !runtimeActionPending;
            }
        };
        Func<string, Task> startOwnedSunshine = async address =>
        {
            if (agent == null || lifecycle.State != ChildLifecycleState.Connected ||
                !lifecycle.CheckConnectedIdentity() || runtimeActionPending) return;
            runtimeActionPending = true;
            sunshineItem.Enabled = false; lanSunshineItem.Enabled = false;
            stopSunshineItem.Enabled = false; recoverSunshineItem.Enabled = false;
            pairItem.Enabled = false;
            statusText.Text = "Reading child display and audio choices…";
            try
            {
                var selectedAgent = agent;
                var presenter = new ChildStreamingPresenter(selectedAgent, lifecycle.ObservedChild.Value);
                ChildStreamingPreparation prepared = await Task.Run(() => presenter.Prepare(address));
                string selectedDisplay, selectedAudio;
                using (var chooser = new CapabilitySelectionDialog(prepared.Catalog))
                {
                    if (chooser.ShowDialog(f) != DialogResult.OK)
                    { statusText.Text = "Child device selection cancelled. No Sunshine start requested."; return; }
                    selectedDisplay = chooser.SelectedDisplay; selectedAudio = chooser.SelectedAudio;
                }
                bool interruption = prepared.Stage == "SunshineReady";
                if (interruption && MessageBox.Show(f,
                    "Changing ChildStream streaming will interrupt the current Moonlight stream. " +
                    "The child desktop, game and pairing identity stay in place. Stop only the exact owned " +
                    "Sunshine process and revalidate the selected devices?",
                    "Approve stream reconfiguration", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning) != DialogResult.Yes)
                { statusText.Text = "Streaming change cancelled; the current owned stream remains available."; return; }
                statusText.Text = "Verifying selected child devices and starting owned Sunshine…";
                var runtime = await Task.Run(() => presenter.Commit(prepared,
                    selectedDisplay, selectedAudio, interruption));
                pairingCoordinator = new MoonlightPairingCoordinator(runtime,
                    new AgentSunshinePairingApi(selectedAgent));
                steamItem.Enabled = true;
                statusText.Text = address == null
                    ? "ChildStream Sunshine verified locally. Select approved LAN streaming for phone or Fire TV."
                    : "ChildStream LAN rules and local pairing API verified. Moonlight streaming remains untested.";
            }
            catch (Exception ex)
            { statusText.Text = "ChildStream Sunshine unavailable: " + ex.Message; Log(statusText.Text); }
            finally { runtimeActionPending = false; Task refreshed = refreshStreamingState(); }
        };
        sunshineItem.Click += async (s, e) => await startOwnedSunshine(null);
        lanSunshineItem.Click += async (s, e) =>
        {
            string address = PromptLanAddress(f);
            if (address != null) await startOwnedSunshine(address);
        };
        stopSunshineItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity() || runtimeActionPending) return;
            runtimeActionPending = true; stopSunshineItem.Enabled = false;
            try
            {
                var presenter = new ChildStreamingPresenter(agent, lifecycle.ObservedChild.Value);
                await Task.Run(() => presenter.Stop());
                statusText.Text = "Exact owned Sunshine stopped; child desktop remains connected.";
            }
            catch (Exception ex)
            { statusText.Text = "Streaming stop needs recovery: " + ex.Message; }
            finally { runtimeActionPending = false; Task refreshed = refreshStreamingState(); }
        };
        recoverSunshineItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity() || runtimeActionPending) return;
            runtimeActionPending = true; recoverSunshineItem.Enabled = false;
            try
            {
                var presenter = new ChildStreamingPresenter(agent, lifecycle.ObservedChild.Value);
                await Task.Run(() => presenter.Recover());
                statusText.Text = "Exact failed start reconciled; choose streaming posture again.";
            }
            catch (Exception ex)
            { statusText.Text = "Recovery requires review: " + ex.Message; }
            finally { runtimeActionPending = false; Task refreshed = refreshStreamingState(); }
        };
        steamItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity()) return;
            steamItem.Enabled = false;
            try
            {
                await Task.Run(() => agent.Execute(ChildAgentOperation.StartSteam, ""));
                gameItem.Enabled = true; stopSteamItem.Enabled = true;
                statusText.Text = "Exact child Steam Big Picture process verified. Game is not yet observed.";
            }
            catch (Exception ex) { statusText.Text = "Child Steam unavailable: " + ex.Message; Log(statusText.Text); }
        };
        gameItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity()) return;
            gameItem.Enabled = false;
            try
            {
                string status = await Task.Run(() => agent.Execute(ChildAgentOperation.RequestGame, ""));
                statusText.Text = status.Contains("GameObserved") ?
                    "Exact Minecraft Dungeons child process observed." :
                    "Game request sent; process outcome is not yet verified. Review before shutdown.";
            }
            catch (Exception ex) { statusText.Text = "Game request failed or uncertain: " + ex.Message; Log(statusText.Text); }
        };
        gameAudioItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity() || runtimeActionPending) return;
            gameAudioItem.Enabled = false;
            try
            {
                var presenter = new ChildStreamingPresenter(agent, lifecycle.ObservedChild.Value);
                await Task.Run(() => presenter.OpenGameAudioRoute());
                statusText.Text = "Windows Volume Mixer requested in the child desktop. Confirm it appeared there, choose the selected endpoint, then enable audio after route observation.";
            }
            catch (Exception ex) { statusText.Text = "Child game audio route unavailable: " + ex.Message; }
            finally { Task refreshed = refreshStreamingState(); }
        };
        enableGameAudioItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity() || runtimeActionPending) return;
            if (MessageBox.Show(f,
                "This briefly disconnects Moonlight while ChildStream stops and restarts only its exact owned Sunshine process with capture-only audio. The game, child desktop and pairing identity stay in place. Continue?",
                "Enable game audio", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            runtimeActionPending = true; enableGameAudioItem.Enabled = false;
            try
            {
                var presenter = new ChildStreamingPresenter(agent, lifecycle.ObservedChild.Value);
                await Task.Run(() => presenter.EnableGameAudio());
                statusText.Text = "Exact game render rechecked; owned Sunshine restarted with capture-only audio. Reconnect Moonlight. Physical playback remains unverified.";
            }
            catch (Exception ex) { statusText.Text = "Game audio enable stopped or needs recovery: " + ex.Message; }
            finally { runtimeActionPending = false; Task refreshed = refreshStreamingState(); }
        };
        stopSteamItem.Click += async (s, e) =>
        {
            if (agent == null || !lifecycle.CheckConnectedIdentity()) return;
            stopSteamItem.Enabled = false;
            try
            {
                await Task.Run(() => agent.Execute(ChildAgentOperation.StopSteam, ""));
                gameItem.Enabled = false; statusText.Text = "Exact child game and Steam stop verified.";
            }
            catch (Exception ex)
            { statusText.Text = "Child Steam stop uncertain: " + ex.Message; Log(statusText.Text); stopSteamItem.Enabled = true; }
        };

        ChildStreamGuideForm guide = null;
        var guideItem = new ToolStripMenuItem("Guided steps…");
        guideItem.Click += (s, e) =>
        {
            if (guide == null || guide.IsDisposed)
                guide = new ChildStreamGuideForm(() => statusText.Text,
                    new[] { setupItem, sunshineItem, lanSunshineItem, pairItem,
                        steamItem, gameItem, gameAudioItem, enableGameAudioItem,
                        stopSunshineItem, recoverSunshineItem });
            guide.Show(f); guide.BringToFront();
        };
        menu.Items.Insert(1, guideItem);
        f.BeginInvoke((Action)(() => guideItem.PerformClick()));

        int last = -1;
        DateTime lastAttempt = DateTime.MinValue;
        Action connect = () =>
        {
            if (!lifecycle.TryBeginConnection())
            {
                Log("connection blocked in lifecycle state " + lifecycle.State + ": " + lifecycle.FailureReason);
                if (lifecycle.State == ChildLifecycleState.Error)
                    MessageBox.Show("Connection was blocked because the child identity could not be verified.\n" + lifecycle.FailureReason,
                        "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lastAttempt = DateTime.UtcNow;
            try
            {
                ocx.Server = "localhost";
                int dw = 1920, dh = 1080, scale = 0;
                try
                {
                    string cfg = Path.Combine(baseDir, "display.cfg");
                    if (File.Exists(cfg))
                    {
                        int[] display = ParseDisplayConfig(File.ReadAllText(cfg));
                        dw = display[0]; dh = display[1]; scale = display[2];
                    }
                }
                catch (Exception ex) { Log("display.cfg: " + ex.Message); }
                ocx.DesktopWidth = dw;
                ocx.DesktopHeight = dh;
                try { ocx.AdvancedSettings2.SmartSizing = true; } catch { }
                if (scale > 0)
                {
                    try
                    {
                        object ds = (uint)scale;
                        var extS = (IMsRdpExtendedSettings)rdp.Ocx;
                        extS.put_Property("DesktopScaleFactor", ref ds);
                        object dev = (uint)180;
                        extS.put_Property("DeviceScaleFactor", ref dev);
                        Log("scale " + scale + "% applied");
                    }
                    catch (Exception ex) { Log("scale: " + ex.Message); }
                }
                try { ocx.ColorDepth = 32; } catch { }
                try { ocx.AdvancedSettings7.EnableCredSspSupport = true; } catch { }
                ChildRdpAudioPolicy.Configure(rdp.Ocx);
                object v = true;
                var ext = (IMsRdpExtendedSettings)rdp.Ocx;
                ext.put_Property("ConnectToChildSession", ref v);
                if (!lifecycle.CheckConnectionPreflight())
                    throw new InvalidOperationException("Connection preflight failed: " + lifecycle.FailureReason);
                Log("connecting child session from parent " + parentSessionId + "...");
                ocx.Connect();
            }
            catch (Exception ex)
            {
                lifecycle.ConnectionAttemptFailed();
                Log("connect failed: " + ex.Message);
                MessageBox.Show("Child-session connection failed: " + ex.Message + "\nThe attempt may have created a child. Inspect its state before restarting.", "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        reconnectItem.Click += (s, e) =>
        {
            try
            {
                if ((int)ocx.Connected != 0)
                {
                    MessageBox.Show("The viewer is already connected.", "ChildStream");
                    return;
                }
                lifecycle.ObserveViewerDisconnected();
                connect(); // Same identity and terminal-state checks as automatic reconnect.
            }
            catch (Exception ex) { lifecycle.UnrecoverableError(); Log("reconnect: " + ex.Message); MessageBox.Show(ex.Message, "ChildStream"); }
        };

        bool runtimePollPending = false;
        var timer = new Timer { Interval = 2000 };
        timer.Tick += delegate
        {
            try
            {
                int state = (int)ocx.Connected;
                if (state != last)
                {
                    last = state;
                    Log("state -> " + state);
                    f.Text = state == 1 ? "Child Session - connected" : "Child Session - state " + state;
                }
                if (state == 1 && (lifecycle.State == ChildLifecycleState.Connecting || lifecycle.State == ChildLifecycleState.Reconnecting))
                {
                    if (!lifecycle.ObserveConnected())
                    {
                        Log("connected child rejected: " + lifecycle.FailureReason);
                        ocx.Disconnect();
                    }
                    else { Log("verified child session " + lifecycle.ObservedChild.Value.SessionId); bootstrapAgent(); }
                }
                else if (state == 0) lifecycle.ObserveViewerDisconnected();
                if (state == 1 && lifecycle.State == ChildLifecycleState.Connected &&
                    !lifecycle.CheckConnectedIdentity())
                {
                    Log("connected child identity lost: " + lifecycle.FailureReason);
                    ocx.Disconnect();
                }

                if (state == 0 && lifecycle.State == ChildLifecycleState.ViewerDisconnected &&
                    (DateTime.UtcNow - lastAttempt).TotalSeconds > 5)
                {
                    Log("auto-reconnect");
                    connect();
                }
                if (state == 0 && (lifecycle.State == ChildLifecycleState.Connecting || lifecycle.State == ChildLifecycleState.Reconnecting) &&
                    (DateTime.UtcNow - lastAttempt).TotalSeconds > 30)
                {
                    lifecycle.ConnectionAttemptFailed();
                    Log("connection outcome timed out; no automatic recreation");
                }
                if (lifecycle.State == ChildLifecycleState.Terminated || lifecycle.State == ChildLifecycleState.Error ||
                    lifecycle.State == ChildLifecycleState.SignOutOutcomeUnknown)
                {
                    reconnectItem.Enabled = false;
                    signOutItem.Enabled = false;
                }
                if (state == 1 && lifecycle.State == ChildLifecycleState.Connected &&
                    agent != null && !runtimePollPending && !runtimeActionPending)
                {
                    runtimePollPending = true;
                    ChildAgentController selectedAgent = agent;
                    Task.Run(() => selectedAgent.Execute(ChildAgentOperation.Status, ""))
                        .ContinueWith(task =>
                    {
                        if (f.IsDisposed) return;
                        f.BeginInvoke((Action)(() =>
                        {
                            runtimePollPending = false;
                            if (agent != selectedAgent || lifecycle.State != ChildLifecycleState.Connected) return;
                            if (task.IsFaulted || task.IsCanceled)
                            {
                                pairItem.Enabled = false; pairingCoordinator = null;
                                stopSunshineItem.Enabled = false; recoverSunshineItem.Enabled = true;
                                statusText.Text = "Child runtime status uncertain; review exact owned recovery.";
                                return;
                            }
                            var observed = new JavaScriptSerializer().DeserializeObject(task.Result) as
                                System.Collections.Generic.Dictionary<string, object>;
                            if (observed == null || !observed.ContainsKey("stage") ||
                                !observed.ContainsKey("lanPosture")) return;
                            applyStreamingState(observed);
                        }));
                    });
                }
            }
            catch (Exception ex)
            {
                lifecycle.UnrecoverableError();
                timer.Stop();
                Log("session monitoring failed: " + ex.Message);
                MessageBox.Show("Session monitoring failed: " + ex.Message + "\nRestart the launcher after checking the child-session state.", "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };
        timer.Start();

        bool closeAuthorized = false;
        f.FormClosing += async (s, e) =>
        {
            if (agent != null && !closeAuthorized)
            {
                e.Cancel = true;
                if (await stopAgent()) { closeAuthorized = true; f.Close(); }
                return;
            }
            timer.Stop(); tray.Visible = false;
            if (agentHost != null) agentHost.Dispose();
        };
        connect();
        Application.Run(f);
        instanceMutex.ReleaseMutex();
        instanceMutex.Dispose();
        return 0;
    }
}



