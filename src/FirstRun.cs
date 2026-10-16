using System;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;

internal enum ChildFeatureStatus { Enabled, Disabled, AccessDenied, UnableToVerify }
internal sealed class ChildFeatureObservation
{
    internal ChildFeatureStatus Status;
    internal int NativeError;
    internal string Description
    {
        get
        {
            if (Status == ChildFeatureStatus.Enabled) return "Child sessions: enabled (current Windows observation).";
            if (Status == ChildFeatureStatus.Disabled) return "Child sessions: disabled (current Windows observation).";
            return "Child sessions: unable to verify (Windows error " + NativeError + ").";
        }
    }
}
internal interface IChildFeatureReader { ChildFeatureObservation Read(); }
internal sealed class WindowsChildFeatureReader : IChildFeatureReader
{
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSIsChildSessionsEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);
    public ChildFeatureObservation Read()
    {
        bool enabled;
        if (WTSIsChildSessionsEnabled(out enabled))
            return new ChildFeatureObservation { Status = enabled ? ChildFeatureStatus.Enabled : ChildFeatureStatus.Disabled };
        int error = Marshal.GetLastWin32Error();
        return new ChildFeatureObservation { Status = error == 5 ? ChildFeatureStatus.AccessDenied :
            ChildFeatureStatus.UnableToVerify, NativeError = error };
    }
}
internal enum RuntimeTokenStatus { Limited, Elevated, UnableToVerify }
internal interface IRuntimeTokenReader { RuntimeTokenStatus Read(); }
internal sealed class WindowsRuntimeTokenReader : IRuntimeTokenReader
{
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int value, int length, out int returned);
    public RuntimeTokenStatus Read()
    {
        try
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity.User == null || identity.Token == IntPtr.Zero) return RuntimeTokenStatus.UnableToVerify;
                int elevated, returned;
                if (!GetTokenInformation(identity.Token, 20, out elevated, sizeof(int), out returned) || returned != sizeof(int))
                    return RuntimeTokenStatus.UnableToVerify;
                return elevated == 0 ? RuntimeTokenStatus.Limited : RuntimeTokenStatus.Elevated;
            }
        }
        catch { return RuntimeTokenStatus.UnableToVerify; }
    }
}
internal sealed class FirstRunController
{
    private readonly IChildFeatureReader feature;
    private readonly IRuntimeTokenReader token;
    internal ChildFeatureObservation Feature { get; private set; }
    internal RuntimeTokenStatus Token { get; private set; }
    internal bool CanStart { get { return Feature != null && Feature.Status == ChildFeatureStatus.Enabled && Token == RuntimeTokenStatus.Limited; } }
    internal FirstRunController(IChildFeatureReader feature, IRuntimeTokenReader token)
    {
        if (feature == null) throw new ArgumentNullException("feature");
        if (token == null) throw new ArgumentNullException("token");
        this.feature = feature; this.token = token;
    }
    internal void Refresh()
    {
        try { Feature = feature.Read(); }
        catch { Feature = new ChildFeatureObservation { Status = ChildFeatureStatus.UnableToVerify }; }
        try { Token = token.Read(); }
        catch { Token = RuntimeTokenStatus.UnableToVerify; }
    }
}

internal sealed class FirstRunForm : Form
{
    private readonly FirstRunController controller;
    private readonly Label feature, token, guidance;
    private readonly Button start, refresh, setup;
    internal bool StartSelected { get; private set; }
    internal FirstRunForm(FirstRunController controller, bool simulated = false)
    {
        this.controller = controller;
        Text = simulated ? "ChildStream — simulated test environment" : "ChildStream";
        Width = 620; Height = 310; MinimumSize = new Size(560, 290);
        StartPosition = FormStartPosition.CenterScreen;
        var title = new Label { Left = 20, Top = 18, Width = 555, Height = 32,
            Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Text = "ChildStream setup and session" };
        feature = new Label { Left = 20, Top = 62, Width = 555, Height = 25 };
        token = new Label { Left = 20, Top = 93, Width = 555, Height = 25 };
        guidance = new Label { Left = 20, Top = 127, Width = 555, Height = 65 };
        start = new Button { Left = 20, Top = 205, Width = 160, Height = 32, Text = "Start child desktop" };
        refresh = new Button { Left = 190, Top = 205, Width = 130, Height = 32, Text = "Refresh status" };
        setup = new Button { Left = 330, Top = 205, Width = 105, Height = 32, Text = "Setup…" };
        var close = new Button { Left = 445, Top = 205, Width = 130, Height = 32, Text = "Close" };
        Controls.AddRange(new Control[] { title, feature, token, guidance, start, refresh, setup, close });
        start.Click += (s, e) => { controller.Refresh(); RenderState(); if (!controller.CanStart) return;
            StartSelected = true; DialogResult = DialogResult.OK; Close(); };
        refresh.Click += (s, e) => { controller.Refresh(); RenderState(); };
        setup.Click += (s, e) => { using (var dialog = new SetupDialog(new WindowsSetupWorkflow(), simulated))
            dialog.ShowDialog(this); controller.Refresh(); RenderState(); };
        close.Click += (s, e) => Close();
        Shown += (s, e) => { controller.Refresh(); RenderState(); };
        RenderState();
    }
    internal void RenderState()
    {
        feature.Text = controller.Feature == null ? "Checking child-session feature…" : controller.Feature.Description;
        token.Text = "Runtime token: " + controller.Token + ".";
        start.Enabled = controller.CanStart;
        setup.Enabled = controller.Token == RuntimeTokenStatus.Limited;
        guidance.Text = controller.Token != RuntimeTokenStatus.Limited
            ? "Open the normal ChildStream application without elevation. Setup is a separate, explicit operation."
            : controller.Feature != null && controller.Feature.Status == ChildFeatureStatus.Disabled
            ? "First setup requires a separately approved feature plan. ChildStream will not change Windows automatically."
            : controller.Feature != null && controller.Feature.Status == ChildFeatureStatus.Enabled
            ? "Start a verified child desktop. Pairing and reconnect do not require Windows sign-out."
            : "The current feature state is unknown. Check access and refresh; previous setup evidence is not current state.";
    }
}
