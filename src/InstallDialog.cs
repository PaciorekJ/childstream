using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

internal interface IProductInstallWorkflow
{
    string Plan(string candidateZip, string reviewedSha256, string sunshineZip);
    void Apply(string candidateZip, string reviewedSha256, string sunshineZip, string planHash);
    void Recover(string candidateZip, string reviewedSha256);
    void Uninstall(string candidateZip, string reviewedSha256);
    void FetchSunshine(string candidateZip, string reviewedSha256, string destination);
}

internal sealed class WindowsProductInstallWorkflow : IProductInstallWorkflow
{
    private static string Bootstrap(string candidateZip, string reviewedSha256)
    {
        ProductInstallPayload.ReadCandidate(candidateZip, reviewedSha256);
        string executable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ChildStreamBootstrap.exe");
        InstallerPolicy.ValidateCanonicalFilePath(executable);
        if (!File.Exists(executable)) throw new FileNotFoundException("Reviewed bootstrap executable is missing.", executable);
        using (var file = new FileStream(candidateZip, FileMode.Open, FileAccess.Read, FileShare.None))
        using (var zip = new ZipArchive(file, ZipArchiveMode.Read))
        {
            var entry = zip.GetEntry("bin/ChildStreamBootstrap.exe");
            if (entry == null || entry.Length < 1 || entry.Length > 8 * 1024 * 1024)
                throw new InvalidDataException("Reviewed candidate lacks its bootstrap executable.");
            using (var input = entry.Open())
            using (var sha = SHA256.Create())
                if (!String.Equals(ProductInstallPayload.Hex(sha.ComputeHash(input)),
                    SetupInstallTrust.Hash(executable), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Bootstrap executable differs from the reviewed candidate.");
        }
        return executable;
    }
    private static string Quote(string value)
    {
        if (value == null || value.IndexOf('"') >= 0 || value.IndexOf('\0') >= 0)
            throw new InvalidDataException("Bootstrap argument is malformed.");
        return "\"" + value + "\"";
    }
    private static string RunReadOnly(string executable, string arguments)
    {
        using (var process = Process.Start(new ProcessStartInfo(executable, arguments) {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(executable) }))
        {
            if (process == null) throw new InvalidOperationException("Bootstrap plan did not start.");
            Task<string> output = process.StandardOutput.ReadToEndAsync();
            Task<string> error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(120000))
            { process.Kill(); throw new TimeoutException("Read-only bootstrap plan timed out before any installation request."); }
            if (process.ExitCode != 0) throw new InvalidOperationException(error.Result);
            return output.Result;
        }
    }
    private static void RunApproved(string executable, string arguments)
    {
        using (var process = Process.Start(new ProcessStartInfo(executable, arguments) {
            UseShellExecute = true, Verb = "runas", WorkingDirectory = Path.GetDirectoryName(executable) }))
        {
            if (process == null) throw new InvalidOperationException("Approved bootstrap did not start.");
            if (!process.WaitForExit(600000))
                throw new TimeoutException("Bootstrap outcome is uncertain. Inspect the protected journal before retrying.");
            if (process.ExitCode != 0)
                throw new InvalidOperationException("Bootstrap did not complete. Inspect the protected journal before retrying.");
        }
    }
    public string Plan(string candidateZip, string reviewedSha256, string sunshineZip)
    {
        string executable = Bootstrap(candidateZip, reviewedSha256);
        string output = RunReadOnly(executable, "-plan " + Quote(candidateZip) + " " +
            Quote(reviewedSha256) + " " + Quote(sunshineZip));
        const string prefix = "ChildStream install plan SHA-256: ";
        int start = output.IndexOf(prefix, StringComparison.Ordinal);
        if (start < 0 || output.Length < start + prefix.Length + 64)
            throw new InvalidDataException("Bootstrap did not return a complete install plan hash.");
        string hash = output.Substring(start + prefix.Length, 64);
        if (!ProductInstallPayload.IsHex256(hash)) throw new InvalidDataException("Bootstrap plan hash is invalid.");
        return hash;
    }
    public void Apply(string candidateZip, string reviewedSha256, string sunshineZip, string planHash)
    {
        if (!ProductInstallPayload.IsHex256(planHash)) throw new InvalidDataException("Exact approved plan hash is required.");
        string executable = Bootstrap(candidateZip, reviewedSha256);
        RunApproved(executable, "-apply " + Quote(candidateZip) + " " + Quote(reviewedSha256) +
            " " + Quote(sunshineZip) + " " + Quote(planHash));
        SetupInstallTrust.RequireOwnedPath("ChildStream.exe");
        SetupInstallTrust.RequireOwnedPath("ChildStreamSetup.exe");
        SetupInstallTrust.RequireOwnedSunshine();
    }
    public void Recover(string candidateZip, string reviewedSha256)
    { RunApproved(Bootstrap(candidateZip, reviewedSha256), "-recover"); }
    public void Uninstall(string candidateZip, string reviewedSha256)
    { RunApproved(Bootstrap(candidateZip, reviewedSha256), "-uninstall"); }
    public void FetchSunshine(string candidateZip, string reviewedSha256, string destination)
    {
        string output = RunReadOnly(Bootstrap(candidateZip, reviewedSha256),
            "-fetch-sunshine " + Quote(destination));
        if (!output.Contains("SHA-256 verified")) throw new InvalidDataException("Pinned download result is incomplete.");
    }
}

internal sealed class ProductInstallDialog : Form
{
    private readonly IProductInstallWorkflow workflow;
    private readonly TextBox candidate, reviewedDigest, sunshine, planHash;
    private readonly Label outcome;
    private readonly Button[] buttons;
    private bool busy;
    internal ProductInstallDialog(IProductInstallWorkflow workflow, bool simulated = false)
    {
        this.workflow = workflow;
        Text = simulated ? "ChildStream software install — simulated" : "ChildStream software installation";
        Width = 760; Height = 555; MinimumSize = new Size(700, 520);
        StartPosition = FormStartPosition.CenterParent;
        var title = new Label { Left = 20, Top = 16, Width = 700, Height = 28,
            Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold),
            Text = "Install ChildStream's own protected files" };
        var description = new Label { Left = 20, Top = 50, Width = 700, Height = 60,
            Text = "Use the exact candidate ZIP SHA-256 from the reviewed CI artifact and the pinned Sunshine archive. " +
                "Planning is read-only. Applying requests Windows UAC separately. Installation does not enable child sessions or LAN access." };
        Label candidateLabel, digestLabel, sunshineLabel, planLabel;
        candidate = Field("Candidate ZIP:", 114, out candidateLabel);
        reviewedDigest = Field("Reviewed candidate SHA-256:", 177, out digestLabel);
        sunshine = Field("Pinned Sunshine ZIP:", 240, out sunshineLabel);
        planHash = Field("Exact install plan SHA-256:", 303, out planLabel);
        var plan = ButtonAt("Review install", 20, 376);
        var apply = ButtonAt("Approve install", 164, 376);
        var fetch = ButtonAt("Fetch Sunshine", 308, 376);
        var recover = ButtonAt("Recover", 452, 376);
        var close = ButtonAt("Close", 596, 376); close.DialogResult = DialogResult.Cancel;
        var uninstall = ButtonAt("Uninstall files", 20, 416);
        buttons = new[] { plan, apply, fetch, recover, close, uninstall };
        outcome = new Label { Left = 20, Top = 462, Width = 700, Height = 52,
            Text = "No installation has run. Per-user pairing identity is preserved during repair or uninstall." };
        Controls.AddRange(new Control[] { title, description, candidateLabel, candidate,
            digestLabel, reviewedDigest, sunshineLabel, sunshine, planLabel, planHash,
            plan, apply, fetch, recover, close, uninstall, outcome });
        CancelButton = close;
        plan.Click += async (s, e) => await Run("plan");
        apply.Click += async (s, e) => await Run("apply");
        fetch.Click += async (s, e) => await Run("fetch");
        recover.Click += async (s, e) => await Run("recover");
        uninstall.Click += async (s, e) => await Run("uninstall");
        FormClosing += (s, e) => { if (busy) { e.Cancel = true;
            outcome.Text = "Wait for the operation result. A timed-out mutation needs journal review."; } };
    }
    private TextBox Field(string label, int top, out Label caption)
    {
        caption = new Label { Left = 20, Top = top, Width = 700, Height = 20, Text = label };
        return new TextBox { Left = 20, Top = top + 22, Width = 700, Height = 25,
            AccessibleName = label, MaxLength = label.Contains("SHA") ? 64 : 1024 };
    }
    private static Button ButtonAt(string text, int x, int y)
    { return new Button { Left = x, Top = y, Width = 135, Height = 34, Text = text }; }
    private void SetBusy(bool value)
    {
        busy = value; UseWaitCursor = value;
        foreach (Button button in buttons) button.Enabled = !value;
        foreach (TextBox box in new[] { candidate, reviewedDigest, sunshine, planHash }) box.Enabled = !value;
    }
    private async Task Run(string action)
    {
        string zip = candidate.Text.Trim(), digest = reviewedDigest.Text.Trim(),
            archive = sunshine.Text.Trim(), hash = planHash.Text.Trim();
        if (!ProductInstallPayload.IsHex256(digest) ||
            ((action == "apply") && !ProductInstallPayload.IsHex256(hash)))
        { outcome.Text = "Enter the exact independently reviewed candidate and plan SHA-256 values."; return; }
        if (action == "apply" || action == "recover" || action == "uninstall")
            if (MessageBox.Show(this, action == "apply" ?
                "Approve only the reviewed ChildStream file and portable Sunshine plan " + hash +
                "? Windows UAC follows. No feature or LAN change is included." :
                (action == "recover" ? "Recover interrupted ChildStream-owned installation files? " :
                "Uninstall only exact ChildStream-owned installed files? ") +
                "Pairing identity remains unless removed separately.",
                "ChildStream software approval", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;
        SetBusy(true); outcome.Text = "Working on the exact reviewed ChildStream package…";
        try
        {
            if (action == "plan")
            { string value = await Task.Run(() => workflow.Plan(zip, digest, archive));
              planHash.Text = value; outcome.Text = "Read-only plan complete. Review the hash before approving installation."; }
            else if (action == "apply")
            { await Task.Run(() => workflow.Apply(zip, digest, archive, hash));
              outcome.Text = "Protected software layout verified. Open the installed ChildStream application to continue setup."; }
            else if (action == "recover")
            { await Task.Run(() => workflow.Recover(zip, digest));
              outcome.Text = "Exact owned software recovery completed. User pairing identity was preserved."; }
            else if (action == "uninstall")
            { await Task.Run(() => workflow.Uninstall(zip, digest));
              outcome.Text = "Exact owned software files removed. Recovery records and user pairing identity were preserved."; }
            else
            {
                using (var save = new SaveFileDialog { FileName = SunshineReleasePin.AssetName,
                    Filter = "Pinned Sunshine ZIP (*.zip)|*.zip", OverwritePrompt = false })
                {
                    if (save.ShowDialog(this) != DialogResult.OK) { outcome.Text = "Download cancelled."; return; }
                    await Task.Run(() => workflow.FetchSunshine(zip, digest, save.FileName));
                    sunshine.Text = save.FileName;
                    outcome.Text = "Pinned Sunshine bytes verified. Review the combined install plan next.";
                }
            }
        }
        catch (Win32Exception ex) { outcome.Text = ex.NativeErrorCode == 1223 ?
            "Windows UAC was cancelled. No completion was reported; inspect the journal before retrying." : ex.Message; }
        catch (TimeoutException ex) { outcome.Text = "Outcome uncertain: " + ex.Message; }
        catch (Exception ex) { outcome.Text = ex.GetType().Name + ": " + ex.Message; }
        finally { SetBusy(false); }
    }
}
