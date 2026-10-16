using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

internal sealed class MoonlightPairingDialog : Form
{
    private readonly MoonlightPairingCoordinator coordinator;
    private readonly Label status;
    private readonly ListBox requests;
    private readonly TextBox pin;
    private readonly Button refresh, approve;
    private bool busy;

    private sealed class RequestRow
    {
        internal PendingMoonlightPairing Request;
        public override string ToString()
        { return Request.Name + "  •  " + Request.Address + "  •  " + Request.Id.Substring(0, 8); }
    }

    internal MoonlightPairingDialog(MoonlightPairingCoordinator verifiedCoordinator)
    {
        coordinator = verifiedCoordinator;
        Text = "Pair Moonlight with ChildStream";
        Width = 650; Height = 410; MinimumSize = new Size(580, 370);
        StartPosition = FormStartPosition.CenterParent;
        var instructions = new Label { Left = 16, Top = 14, Width = 600, Height = 66,
            Text = coordinator == null
                ? "ChildStream has no verified child-session Sunshine runtime. Pairing is unavailable. The existing native Sunshine instance will not be used."
                : "Open Moonlight on your phone or Fire TV. Select the verified ChildStream host, or add it manually at " + coordinator.ManualAddress +
                  ". When Moonlight displays a PIN, select its matching request below and enter that PIN here." };
        status = new Label { Left = 16, Top = 82, Width = 600, Height = 36,
            Text = coordinator == null ? "Waiting for Stage A/B and child runtime acceptance." : "Verified host: " + coordinator.HostName };
        requests = new ListBox { Left = 16, Top = 122, Width = 600, Height = 150, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
        refresh = new Button { Left = 16, Top = 282, Width = 150, Text = "Refresh requests", Enabled = coordinator != null };
        pin = new TextBox { Left = 184, Top = 284, Width = 100, MaxLength = 4, UseSystemPasswordChar = true, Enabled = coordinator != null };
        approve = new Button { Left = 300, Top = 282, Width = 170, Text = "Approve selected PIN", Enabled = coordinator != null };
        var close = new Button { Left = 490, Top = 282, Width = 125, Text = "Close", DialogResult = DialogResult.Cancel };
        Controls.AddRange(new Control[] { instructions, status, requests, refresh, pin, approve, close });
        CancelButton = close;
        refresh.Click += (s, e) => RefreshRequests();
        approve.Click += (s, e) => ApproveSelected();
    }

    private void SetBusy(bool value)
    {
        busy = value; refresh.Enabled = coordinator != null && !value;
        approve.Enabled = coordinator != null && !value;
        requests.Enabled = !value; pin.Enabled = coordinator != null && !value;
    }

    private async void RefreshRequests()
    {
        if (busy || coordinator == null) return;
        SetBusy(true); status.Text = "Checking the verified ChildStream host…";
        try
        {
            IList<PendingMoonlightPairing> found = await Task.Run(() => coordinator.Refresh());
            if (IsDisposed) return;
            requests.Items.Clear();
            foreach (var request in found) requests.Items.Add(new RequestRow { Request = request });
            status.Text = found.Count == 0 ? "No Moonlight PIN request is pending." :
                "Select the request matching the Moonlight device and enter its displayed PIN.";
        }
        catch (Exception) { if (!IsDisposed) status.Text = "Could not verify the ChildStream pairing request. No PIN was sent."; }
        finally { if (!IsDisposed) SetBusy(false); }
    }

    private async void ApproveSelected()
    {
        if (busy || coordinator == null) return;
        var row = requests.SelectedItem as RequestRow;
        string enteredPin = pin.Text;
        pin.Clear();
        if (row == null || !SunshinePairingProtocol.ValidPin(enteredPin))
        { status.Text = "Select a pending request and enter Moonlight's four-digit PIN."; return; }
        if (MessageBox.Show(this, "Approve " + row.Request.Name + " at " + row.Request.Address +
            " for the verified ChildStream host?", "Approve Moonlight pairing",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        SetBusy(true); status.Text = "Waiting for Moonlight's pairing handshake…";
        try
        {
            bool paired = await Task.Run(() => coordinator.Approve(row.Request.Id, enteredPin, true));
            if (IsDisposed) return;
            requests.Items.Clear();
            status.Text = paired ? "Moonlight pairing completed. Select Desktop in Moonlight to stream." :
                "Pairing was rejected or timed out. Refresh and try again.";
        }
        catch (Exception) { if (!IsDisposed) status.Text = "Pairing could not be verified. Refresh before trying again."; }
        finally { if (!IsDisposed) SetBusy(false); }
    }
}
