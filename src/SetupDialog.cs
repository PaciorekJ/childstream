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
    private readonly TextBox planHash, lanAddress;
    private readonly Label outcome;
    private readonly Button[] actions;
    private bool busy;
    internal SetupDialog(ISetupWorkflow workflow, bool simulated = false)
    {
        this.workflow = workflow;
        Text = simulated ? "ChildStream setup — simulated test environment" : "ChildStream setup and recovery";
        Width = 730; Height = 730; MinimumSize = new Size(670, 680);
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
        outcome = new Label { Left = 20, Top = 610, Width = 670, Height = 80,
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
        var rdpLabel = new Label { Left = 20, Top = 315, Width = 670, Height = 22,
            Text = "Separate pre-enable ordinary-RDP containment; live loopback qualification is still required:" };
        var rdpPlan = ButtonAt("Review RDP plan", 20, 344);
        var rdpApply = ButtonAt("Approve RDP blocks", 183, 344);
        var rdpRead = ButtonAt("Read RDP journal", 346, 344);
        var rdpRecover = ButtonAt("Restore RDP blocks", 509, 344);
        var lanLabel = new Label { Left = 20, Top = 403, Width = 670, Height = 22,
            Text = "Separate ChildStream LAN streaming approval (private IPv4 on this PC):" };
        lanAddress = new TextBox { Left = 20, Top = 428, Width = 320, Height = 26,
            MaxLength = 45, AccessibleName = "Exact selected ChildStream LAN IPv4 address" };
        var lanPlan = ButtonAt("Review LAN plan", 20, 473);
        var lanApply = ButtonAt("Approve LAN rules", 183, 473);
        var lanRecover = ButtonAt("Restore LAN rules", 346, 473);
        var lanJournal = ButtonAt("Read LAN journal", 509, 473);
        var lanNote = new Label { Left = 20, Top = 525, Width = 670, Height = 65,
            Text = "LAN rules are separate from the Windows child feature. Sunshine permits only local Web UI clients; " +
                "its Web UI port is excluded from the LAN allow rules. Current firewall and interface state must verify." };
        actions = new[] { plan, journal, begin, prepare, restore, task, remove, reviewed, close,
            lanPlan, lanApply, lanRecover, lanJournal, rdpPlan, rdpApply, rdpRead, rdpRecover };
        Controls.AddRange(new Control[] { title, detail, hashLabel, planHash, outcome,
            plan, journal, begin, prepare, restore, task, remove, reviewed, close,
            rdpLabel, rdpPlan, rdpApply, rdpRead, rdpRecover,
            lanLabel, lanAddress, lanPlan, lanApply, lanRecover, lanJournal, lanNote });
        plan.Click += async (s, e) => await Run(SetupOperation.PlanConnected);
        journal.Click += async (s, e) => await Run(SetupOperation.ReadJournal);
        begin.Click += async (s, e) => await Run(SetupOperation.BeginConnected);
        prepare.Click += async (s, e) => await Run(SetupOperation.PrepareFeature);
        restore.Click += async (s, e) => await Run(SetupOperation.RestoreOriginal);
        reviewed.Click += async (s, e) => await Run(SetupOperation.ReviewedRestore);
        lanPlan.Click += async (s, e) => await Run(SetupOperation.PlanLan);
        lanApply.Click += async (s, e) => await Run(SetupOperation.ApplyLan);
        lanRecover.Click += async (s, e) => await Run(SetupOperation.RecoverLan);
        lanJournal.Click += async (s, e) => await Run(SetupOperation.ReadLanJournal);
        rdpPlan.Click += async (s, e) => await Run(SetupOperation.PlanRdpContainment);
        rdpApply.Click += async (s, e) => await Run(SetupOperation.ApplyRdpContainment);
        rdpRead.Click += async (s, e) => await Run(SetupOperation.ReadRdpContainment);
        rdpRecover.Click += async (s, e) => await Run(SetupOperation.RecoverRdpContainment);
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
        lanAddress.Enabled = !busy;
        UseWaitCursor = busy;
    }
    private async Task Run(SetupOperation operation)
    {
        string hash = operation == SetupOperation.PlanConnected || operation == SetupOperation.ReadJournal ||
            operation == SetupOperation.PlanLan || operation == SetupOperation.ReadLanJournal ||
            operation == SetupOperation.PlanRdpContainment || operation == SetupOperation.ReadRdpContainment
            ? "" : planHash.Text.Trim();
        bool lan = operation == SetupOperation.PlanLan || operation == SetupOperation.ApplyLan ||
            operation == SetupOperation.RecoverLan || operation == SetupOperation.ReadLanJournal;
        var request = new SetupRequest { Operation = operation, ApprovedPlanHash = hash,
            LanAddress = lan ? lanAddress.Text.Trim() : "" };
        try { request.Validate(); }
        catch (Exception ex) { outcome.Text = ex.Message; return; }
        if (operation != SetupOperation.PlanConnected && operation != SetupOperation.ReadJournal &&
            operation != SetupOperation.PlanLan && operation != SetupOperation.ReadLanJournal &&
            operation != SetupOperation.PlanRdpContainment && operation != SetupOperation.ReadRdpContainment &&
            MessageBox.Show(this, "Authorize exactly " + operation + " for plan " + hash +
                "?\nA separate elevated helper will verify the current console and safety gates. " +
                (lan ? "Only the two scoped ChildStream LAN firewall rules are in this request. " :
                    operation == SetupOperation.ApplyRdpContainment || operation == SetupOperation.RecoverRdpContainment
                    ? "Only the two scoped ChildStream TermService block rules are in this request. " : "") +
                (operation == SetupOperation.ReviewedRestore ?
                    "This acknowledges an ambiguous earlier feature write. Verify the journal and current Windows state first." :
                    "Feature preparation may require a later manual Windows sign-in."),
                "ChildStream setup approval", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;
        SetBusy(true); outcome.Text = "Waiting for the scoped helper. No automatic retry will occur.";
        try
        {
            string result = await Task.Run(() => workflow.Execute(request));
            if (result.StartsWith("LAN plan ", StringComparison.Ordinal))
                planHash.Text = result.Substring("LAN plan ".Length, 64);
            else if (result.StartsWith("RDP plan ", StringComparison.Ordinal))
                planHash.Text = result.Substring("RDP plan ".Length, 64);
            else if (result.StartsWith("RDP journal ", StringComparison.Ordinal))
                planHash.Text = result.Substring("RDP journal ".Length, 64);
            else if (result.StartsWith("LAN journal ", StringComparison.Ordinal))
                planHash.Text = result.Substring("LAN journal ".Length, 64);
            else if (result.StartsWith("Plan ", StringComparison.Ordinal) ||
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
