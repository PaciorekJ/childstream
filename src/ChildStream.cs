using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Globalization;
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

static class Program
{
    [DllImport("wtsapi32.dll")]
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
    static string logPath = Path.Combine(baseDir, "launcher.log");
    static string intentDir = GetIntentDirectory();

    static string GetIntentDirectory()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!Path.IsPathRooted(local)) throw new InvalidOperationException("Local application data path is unavailable.");
        return Path.Combine(local, "ChildStream", "session-intents");
    }

    static void Log(string msg)
    {
        try { File.AppendAllText(logPath, DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg + Environment.NewLine); } catch { }
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

        bool en;
        if (!WTSIsChildSessionsEnabled(out en))
        {
            MessageBox.Show("Cannot query child-session support. Check Windows edition and system logs.", "ChildStream");
            return 2;
        }
        Log("startup: child sessions enabled = " + en);
        if (!en)
        {
            MessageBox.Show("Child sessions are not enabled. Installation is blocked until the transactional installer is validated.", "ChildStream");
            return 1;
        }

        Application.EnableVisualStyles();

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
        var menu = new ContextMenuStrip();
        menu.Items.Add("Show", null, (s, e) => { f.Show(); f.WindowState = FormWindowState.Normal; f.Activate(); });
        ToolStripMenuItem reconnectItem = new ToolStripMenuItem("Reconnect now");
        menu.Items.Add(reconnectItem);
        menu.Items.Add("Inspect/remove legacy saved password", null, (s, e) => { RemoveLegacyPasswordExplicitly(); });
        ToolStripMenuItem signOutItem = new ToolStripMenuItem("End session (sign out, closes games)");
        menu.Items.Add(signOutItem);
        signOutItem.Click += (s, e) =>
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
        menu.Items.Add("Exit", null, (s, e) => { tray.Visible = false; Application.Exit(); });
        tray.ContextMenuStrip = menu;
        tray.DoubleClick += (s, e) => { f.Show(); f.WindowState = FormWindowState.Normal; f.Activate(); };

        f.Resize += (s, e) => { if (f.WindowState == FormWindowState.Minimized) { f.Hide(); tray.ShowBalloonTip(1500, "Child Session", "Still running - session stays alive. Double-click to restore.", ToolTipIcon.Info); } };
        f.Show();

        var rdp = new RdpBox { Dock = DockStyle.Fill };
        f.Controls.Add(rdp);
        rdp.CreateControl();
        ocx = rdp.Ocx;

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
                    else Log("verified child session " + lifecycle.ObservedChild.Value.SessionId);
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

        f.FormClosing += (s, e) => { timer.Stop(); tray.Visible = false; };
        connect();
        Application.Run(f);
        instanceMutex.ReleaseMutex();
        instanceMutex.Dispose();
        return 0;
    }
}



