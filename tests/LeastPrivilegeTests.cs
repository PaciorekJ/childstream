using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

static class LeastPrivilegeTests
{
    private sealed class Feature : IChildFeatureReader
    {
        internal ChildFeatureStatus Status;
        internal int Error;
        public ChildFeatureObservation Read() { return new ChildFeatureObservation { Status = Status, NativeError = Error }; }
    }
    private sealed class Token : IRuntimeTokenReader
    {
        internal RuntimeTokenStatus Status;
        public RuntimeTokenStatus Read() { return Status; }
    }
    private sealed class Attempt : IUnknownFeatureAttemptPolicy
    {
        internal bool Approved;
        public bool IsApprovedInstalledAttempt() { return Approved; }
    }
    private static int assertions;
    private static void Check(bool value, string description)
    { assertions++; if (!value) throw new Exception(description); }
    private static void Reject(Action action, string description)
    { bool rejected = false; try { action(); } catch { rejected = true; } Check(rejected, description); }

    [STAThread]
    public static int Main(string[] args)
    {
        Application.EnableVisualStyles();
        var feature = new Feature(); var token = new Token { Status = RuntimeTokenStatus.Limited };
        var controller = new FirstRunController(feature, token);
        string pictures = args.Length == 1 ? args[0] : null;
        if (pictures != null) Directory.CreateDirectory(pictures);
        foreach (ChildFeatureStatus status in new [] { ChildFeatureStatus.Enabled, ChildFeatureStatus.Disabled,
            ChildFeatureStatus.AccessDenied, ChildFeatureStatus.UnableToVerify })
        {
            feature.Status = status; feature.Error = status == ChildFeatureStatus.AccessDenied ? 5 : 1722;
            controller.Refresh();
            Check(controller.CanStart == (status == ChildFeatureStatus.Enabled), "feature gate " + status);
            Check(controller.Feature.Description.Contains(status == ChildFeatureStatus.Enabled ? "enabled" :
                status == ChildFeatureStatus.Disabled ? "disabled" : "unable to verify"), "feature status " + status);
            if (pictures != null)
            {
                using (var form = new FirstRunForm(controller, true))
                using (var image = new Bitmap(form.Width, form.Height))
                {
                    form.StartPosition = FormStartPosition.Manual;
                    form.Location = new Point(-2000, -2000);
                    form.Show(); Application.DoEvents(); form.RenderState();
                    form.DrawToBitmap(image, new Rectangle(0, 0, image.Width, image.Height));
                    form.Hide();
                    image.Save(Path.Combine(pictures, "first-run-" + status + ".png"));
                }
            }
        }
        feature.Status = ChildFeatureStatus.Enabled;
        foreach (RuntimeTokenStatus state in new [] { RuntimeTokenStatus.Elevated, RuntimeTokenStatus.UnableToVerify })
        { token.Status = state; controller.Refresh(); Check(!controller.CanStart, "runtime token " + state + " rejected"); }
        token.Status = RuntimeTokenStatus.Limited;
        var attempt = new Attempt();
        var installed = new FirstRunController(feature, token, attempt);
        feature.Status = ChildFeatureStatus.AccessDenied; installed.Refresh();
        Check(!installed.CanStart, "unknown feature without approved protected task is blocked");
        attempt.Approved = true; installed.Refresh();
        Check(installed.CanStart && installed.Feature.Status == ChildFeatureStatus.AccessDenied,
            "inaccessible feature permits explicit attempt without relabeling current state");
        feature.Status = ChildFeatureStatus.UnableToVerify; installed.Refresh();
        Check(installed.CanStart, "other inaccessible feature query can use exact approved attempt");
        feature.Status = ChildFeatureStatus.Disabled; installed.Refresh();
        Check(!installed.CanStart, "known disabled feature cannot use historical approval");
        token.Status = RuntimeTokenStatus.Elevated; feature.Status = ChildFeatureStatus.AccessDenied;
        installed.Refresh(); Check(!installed.CanStart, "approved attempt cannot elevate daily runtime");
        Reject(() => new PinnedSunshinePairingTransport(new Uri("https://localhost:47990/"),
            new string('0', 64), "user", "pass", new PairingRuntime()), "localhost DNS alias rejected");
        Reject(() => new PinnedSunshinePairingTransport(new Uri("https://127.0.0.1:47990/"),
            new string('0', 64), "user", "pass", null), "unowned pairing endpoint rejected");
        string displayLog = "Info: Currently available display devices:\n[{\"device_id\":\"{6b4f23ba-ef14-45ab-9c90-5d6c8f859f24}\",\"display_name\":\"\\\\.\\\\DISPLAY2\",\"info\":{\"primary\":true}}]";
        Check(SunshineDisplayCatalog.RequireUniqueActive(displayLog).Active, "owned Sunshine active display observed");
        Reject(() => SunshineDisplayCatalog.RequireUniqueActive(displayLog.Replace("}]", "},{\"device_id\":\"{12100db6-5a9d-40c4-9c10-c3b1f606a632}\",\"display_name\":\"DISPLAY3\",\"info\":{}}]")),
            "ambiguous active displays rejected");
        if (Environment.GetEnvironmentVariable("CHILDSTREAM_PRIVATE_IDENTITY_TEST") == "1")
        {
        string parent = Path.Combine(Path.GetTempPath(), "ChildStreamIdentityTests-" + Guid.NewGuid().ToString("N"));
        string owned = Path.Combine(parent, "ChildStream");
        Directory.CreateDirectory(owned);
        string native = Path.Combine(parent, "native-sunshine-state.txt");
        File.WriteAllText(native, "foreign-state-must-remain");
        try
        {
            string first;
            using (var store = new SunshineIdentityStore(owned))
            {
                first = store.GetOrCreateCredentials().Password;
                Reject(() => new SunshineIdentityStore(owned), "second identity writer rejected");
            }
            using (var store = new SunshineIdentityStore(owned))
                Check(store.GetOrCreateCredentials().Password == first, "pairing administrator identity persists across generations");
            Check(File.ReadAllText(native) == "foreign-state-must-remain", "native Sunshine fixture untouched");
            Check(!File.Exists(Path.Combine(owned, "admin.dpapi")), "secret stored only under private identity root");
        }
        finally
        {
            string full = Path.GetFullPath(parent);
            if (!full.StartsWith(Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar + "ChildStreamIdentityTests-", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Test cleanup root escaped the expected temp directory.");
            Directory.Delete(full, true);
        }
        }
        else Console.WriteLine("Private ACL/DPAPI identity test SKIPPED (restricted test token).");
        Console.WriteLine("Least-privilege UI/transport assertions passed: " + assertions +
            (pictures == null ? "" : "; rendered fixture screenshots: " + pictures));
        return 0;
    }
    private sealed class PairingRuntime : IVerifiedChildSunshine
    {
        public string HostName { get { return "ChildStream"; } }
        public string ManualAddress { get { return "192.168.1.10"; } }
        public void AssertStillOwned() { }
    }
}
