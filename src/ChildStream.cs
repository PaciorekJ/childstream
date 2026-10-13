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

    static string baseDir = AppDomain.CurrentDomain.BaseDirectory;
    static string logPath = Path.Combine(baseDir, "launcher.log");
    static string credPath = Path.Combine(baseDir, "cred.bin"); // Legacy version only.

    static void Log(string msg)
    {
        try { File.AppendAllText(logPath, DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg + Environment.NewLine); } catch { }
    }

    static bool TryGetChildSession(out uint sessionId)
    {
        sessionId = uint.MaxValue;
        if (!WTSGetChildSessionId(out sessionId))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSGetChildSessionId failed");
        return sessionId != uint.MaxValue;
    }

    static bool IsOwnedChild(uint candidate, uint connectedChild, uint parent)
    {
        return candidate != uint.MaxValue && candidate != parent && candidate == connectedChild;
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

    static bool RemoveLegacyPassword()
    {
        try { if (File.Exists(credPath)) File.Delete(credPath); return true; }
        catch (IOException ex) { Log("legacy credential removal failed: " + ex.Message); return false; }
        catch (UnauthorizedAccessException ex) { Log("legacy credential removal failed: " + ex.Message); return false; }
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
        if (args.Length > 0 && args[0] == "-resetpass") return RemoveLegacyPassword() ? 0 : 1;

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
        if (!RemoveLegacyPassword())
            MessageBox.Show("Could not remove legacy cred.bin. Use -resetpass after fixing file permissions.", "ChildStream");
        uint parentSessionId = (uint)Process.GetCurrentProcess().SessionId;
        uint connectedChildId = uint.MaxValue;

        bool[] endRequested = { false };
        var f = new Form { Text = "Child Session", Width = 1360, Height = 820 };
        Icon appIcon = SystemIcons.Application;
        try { appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        f.Icon = appIcon;
        var tray = new NotifyIcon { Icon = appIcon, Visible = true, Text = "Child Session" };
        var menu = new ContextMenuStrip();
        menu.Items.Add("Show", null, (s, e) => { f.Show(); f.WindowState = FormWindowState.Normal; f.Activate(); });
        ToolStripMenuItem reconnectItem = new ToolStripMenuItem("Reconnect now");
        menu.Items.Add(reconnectItem);
        menu.Items.Add("Remove legacy saved password", null, (s, e) => {
            bool removed = RemoveLegacyPassword();
            tray.ShowBalloonTip(2000, "Child Session", removed ? "Legacy credential removed." : "Removal failed; check launcher.log.", removed ? ToolTipIcon.Info : ToolTipIcon.Error);
        });
        menu.Items.Add("End session (sign out, closes games)", null, (s, e) =>
        {
            if (MessageBox.Show("Sign out the child session? All apps running in it will close.", "Child Session", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                uint currentChild;
                if (!TryGetChildSession(out currentChild) || !IsOwnedChild(currentChild, connectedChildId, parentSessionId))
                    throw new InvalidOperationException("The connected child session could not be verified. Reconnect before signing out.");
                endRequested[0] = true;
                Log("signing out verified child session " + currentChild);
                if (!WTSLogoffSession(IntPtr.Zero, currentChild, true))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSLogoffSession failed");
            }
            catch (Exception ex) { endRequested[0] = false; Log("signout: " + ex.Message); MessageBox.Show(ex.Message, "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
            tray.Visible = false;
            Application.Exit();
        });
        menu.Items.Add("Exit", null, (s, e) => { tray.Visible = false; Application.Exit(); });
        tray.ContextMenuStrip = menu;
        tray.DoubleClick += (s, e) => { f.Show(); f.WindowState = FormWindowState.Normal; f.Activate(); };

        f.Resize += (s, e) => { if (f.WindowState == FormWindowState.Minimized) { f.Hide(); tray.ShowBalloonTip(1500, "Child Session", "Still running - session stays alive. Double-click to restore.", ToolTipIcon.Info); } };
        f.Show();

        var rdp = new RdpBox { Dock = DockStyle.Fill };
        f.Controls.Add(rdp);
        rdp.CreateControl();
        dynamic ocx = rdp.Ocx;

        bool wantReconnect = true;
        Action connect = () =>
        {
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
                Log("connecting child session from parent " + parentSessionId + "...");
                ocx.Connect();
            }
            catch (Exception ex)
            {
                wantReconnect = false;
                Log("connect failed: " + ex.Message);
                MessageBox.Show("Child-session connection failed: " + ex.Message + "\nCheck prerequisites, then use Reconnect now.", "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        reconnectItem.Click += (s, e) =>
        {
            try { wantReconnect = true; if ((int)ocx.Connected != 0) ocx.Disconnect(); else connect(); }
            catch (Exception ex) { Log("reconnect: " + ex.Message); MessageBox.Show(ex.Message, "ChildStream"); }
        };

        int last = -1;
        DateTime lastAttempt = DateTime.MinValue;
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
                    if (state == 1)
                    {
                        uint child;
                        if (TryGetChildSession(out child) && child != parentSessionId)
                        {
                            connectedChildId = child;
                            Log("verified child session " + child);
                        }
                    }
                }
                if (state == 0 && wantReconnect && !endRequested[0] && (DateTime.Now - lastAttempt).TotalSeconds > 5)
                {
                    if (connectedChildId != uint.MaxValue)
                    {
                        uint child;
                        if (!TryGetChildSession(out child) || child != connectedChildId)
                        {
                            wantReconnect = false;
                            Log("connected child session ended; automatic creation stopped");
                            tray.ShowBalloonTip(3000, "Child Session", "The child session ended. Restart the launcher to create another.", ToolTipIcon.Warning);
                            return;
                        }
                    }
                    lastAttempt = DateTime.Now;
                    Log("auto-reconnect");
                    connect();
                }
            }
            catch (Exception ex)
            {
                wantReconnect = false;
                timer.Stop();
                Log("session monitoring failed: " + ex.Message);
                MessageBox.Show("Session monitoring failed: " + ex.Message + "\nRestart the launcher after checking the child-session state.", "ChildStream", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };
        timer.Start();

        f.FormClosing += (s, e) => { wantReconnect = false; tray.Visible = false; };
        connect();
        Application.Run(f);
        return 0;
    }
}



