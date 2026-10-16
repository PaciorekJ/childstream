using System;
using System.ComponentModel;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

internal interface ISetupWorkflow
{
    string Execute(SetupRequest request);
    void RegisterOwnAgentTask();
    void RemoveOwnAgentTask();
}
internal sealed class WindowsSetupWorkflow : ISetupWorkflow
{
    public string Execute(SetupRequest request)
    { return new WindowsSetupGateway(new WindowsSetupElevationLauncher()).Execute(request); }
    public void RegisterOwnAgentTask()
    { WindowsChildAgentTaskSetup.ForCurrentLimitedUser().EnsureRegistered(true); }
    public void RemoveOwnAgentTask()
    { WindowsChildAgentTaskSetup.ForCurrentLimitedUser().Remove(true); }
}

internal sealed class SetupDialog : Form
{
    private readonly ISetupWorkflow workflow;
    private readonly TextBox planHash;
    private readonly Label outcome;
    private readonly Button[] actions;
    private bool busy;
    internal SetupDialog(ISetupWorkflow workflow, bool simulated = false)
    {
        this.workflow = workflow;
        Text = simulated ? "ChildStream setup — simulated test environment" : "ChildStream setup and recovery";
        Width = 730; Height = 480; MinimumSize = new Size(670, 450);
        StartPosition = FormStartPosition.CenterParent;
        var title = new Label { Left = 20, Top = 15, Width = 670, Height = 28,
            Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold),
            Text = "Scoped setup for the current Windows account" };
        var detail = new Label { Left = 20, Top = 47, Width = 670, Height = 55,
            Text = "Planning reads the connected-LAN safety gate. It does not enable child sessions. " +
                "Each journal or feature change needs a separate approval and UAC prompt. " +
                "ChildStream never signs out Windows automatically." };
        var hashLabel = new Label { Left = 20, Top = 110, Width = 180, Height = 22,
            Text = "Reviewed plan SHA-256:" };
        planHash = new TextBox { Left = 20, Top = 134, Width = 670, Height = 26,
            MaxLength = 64, AccessibleName = "Exact reviewed setup plan hash" };
        outcome = new Label { Left = 20, Top = 363, Width = 670, Height = 70,
            Text = "No setup operation has run. A past journal does not prove the current feature state." };
        var plan = ButtonAt("Read-only plan", 20, 176);
        var journal = ButtonAt("Read journal", 183, 176);
        var begin = ButtonAt("Begin approved plan", 346, 176);
        var prepare = ButtonAt("Enable feature", 509, 176);
        var restore = ButtonAt("Restore original", 20, 224);
        var task = ButtonAt("Prepare child agent", 183, 224);
        var remove = ButtonAt("Remove child agent", 346, 224);
        var close = ButtonAt("Close", 509, 224);
        var reviewed = ButtonAt("Reviewed restore", 20, 272);
        actions = new[] { plan, journal, begin, prepare, restore, task, remove, reviewed, close };
        Controls.AddRange(new Control[] { title, detail, hashLabel, planHash, outcome,
            plan, journal, begin, prepare, restore, task, remove, reviewed, close });
        plan.Click += async (s, e) => await Run(SetupOperation.PlanConnected);
        journal.Click += async (s, e) => await Run(SetupOperation.ReadJournal);
        begin.Click += async (s, e) => await Run(SetupOperation.BeginConnected);
        prepare.Click += async (s, e) => await Run(SetupOperation.PrepareFeature);
        restore.Click += async (s, e) => await Run(SetupOperation.RestoreOriginal);
        reviewed.Click += async (s, e) => await Run(SetupOperation.ReviewedRestore);
        task.Click += async (s, e) => await RunTask(false);
        remove.Click += async (s, e) => await RunTask(true);
        close.Click += (s, e) => Close();
        FormClosing += (s, e) => { if (busy) { e.Cancel = true;
            outcome.Text = "Wait for the current setup result. Its outcome may be uncertain if interrupted."; } };
    }
    private static Button ButtonAt(string text, int x, int y)
    { return new Button { Text = text, Left = x, Top = y, Width = 153, Height = 34 }; }
    private void SetBusy(bool busy)
    {
        this.busy = busy;
        foreach (Button button in actions) button.Enabled = !busy;
        planHash.Enabled = !busy;
        UseWaitCursor = busy;
    }
    private async Task Run(SetupOperation operation)
    {
        string hash = operation == SetupOperation.PlanConnected || operation == SetupOperation.ReadJournal
            ? "" : planHash.Text.Trim();
        var request = new SetupRequest { Operation = operation, ApprovedPlanHash = hash };
        try { request.Validate(); }
        catch (Exception ex) { outcome.Text = ex.Message; return; }
        if (operation != SetupOperation.PlanConnected && operation != SetupOperation.ReadJournal &&
            MessageBox.Show(this, "Authorize exactly " + operation + " for plan " + hash +
                "?\nA separate elevated helper will verify the current console and safety gates. " +
                (operation == SetupOperation.ReviewedRestore ?
                    "This acknowledges an ambiguous earlier feature write. Verify the journal and current Windows state first." :
                    "Feature preparation may require a later manual Windows sign-in."),
                "ChildStream setup approval", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;
        SetBusy(true); outcome.Text = "Waiting for the scoped helper. No automatic retry will occur.";
        try
        {
            string result = await Task.Run(() => workflow.Execute(request));
            if (result.StartsWith("Plan ", StringComparison.Ordinal) ||
                result.StartsWith("Journal ", StringComparison.Ordinal))
            {
                string candidate = result.Substring(result.IndexOf(' ') + 1);
                if (candidate.Length >= 64) planHash.Text = candidate.Substring(0, 64);
            }
            outcome.Text = result + "\nRefresh the feature observation after any approved change.";
        }
        catch (Win32Exception ex)
        { outcome.Text = ex.NativeErrorCode == 1223 ?
            "UAC was cancelled. No setup result was reported; inspect the journal before retrying a mutation." :
            ex.GetType().Name + ": " + ex.Message; }
        catch (TimeoutException ex) { outcome.Text = "Outcome uncertain: " + ex.Message; }
        catch (Exception ex) { outcome.Text = ex.GetType().Name + ": " + ex.Message; }
        finally { SetBusy(false); }
    }
    private async Task RunTask(bool remove)
    {
        if (MessageBox.Show(this, remove ? "Remove the exact stopped ChildStream agent task?" :
            "Register a demand-only child agent task for this limited user? No Administrator elevation is requested.",
            "ChildStream task approval", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        SetBusy(true);
        try
        {
            await Task.Run(() => { if (remove) workflow.RemoveOwnAgentTask();
                else workflow.RegisterOwnAgentTask(); });
            outcome.Text = remove ? "Exact stopped child agent task removal verified." :
                "Demand-only limited child agent task verified. No child session was created.";
        }
        catch (Exception ex) { outcome.Text = ex.GetType().Name + ": " + ex.Message; }
        finally { SetBusy(false); }
    }
}
