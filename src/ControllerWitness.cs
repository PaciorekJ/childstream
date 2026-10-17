using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web.Script.Serialization;

// Standalone, opt-in read-only observer. It never creates a controller,
// changes device visibility, or attributes an XInput slot to a virtual target.
internal struct ControllerSlotState
{
    internal uint Error, Packet;
    internal ushort Buttons;
    internal byte LeftTrigger, RightTrigger;
    internal short LeftX, LeftY, RightX, RightY;
}
internal interface IControllerSlotReader { ControllerSlotState Read(uint slot); }

internal sealed class WindowsXInputSlotReader : IControllerSlotReader
{
    [StructLayout(LayoutKind.Sequential)] private struct Gamepad
    { public ushort Buttons; public byte LeftTrigger, RightTrigger;
      public short LeftX, LeftY, RightX, RightY; }
    [StructLayout(LayoutKind.Sequential)] private struct State
    { public uint Packet; public Gamepad Gamepad; }
    [DllImport("xinput1_4.dll", EntryPoint = "XInputGetState")]
    private static extern uint GetState(uint slot, out State state);
    public ControllerSlotState Read(uint slot)
    {
        State state;
        uint result = GetState(slot, out state); // XInput returns the code; GetLastError is unrelated.
        return new ControllerSlotState { Error = result, Packet = result == 0 ? state.Packet : 0,
            Buttons = result == 0 ? state.Gamepad.Buttons : (ushort)0,
            LeftTrigger = result == 0 ? state.Gamepad.LeftTrigger : (byte)0,
            RightTrigger = result == 0 ? state.Gamepad.RightTrigger : (byte)0,
            LeftX = result == 0 ? state.Gamepad.LeftX : (short)0,
            LeftY = result == 0 ? state.Gamepad.LeftY : (short)0,
            RightX = result == 0 ? state.Gamepad.RightX : (short)0,
            RightY = result == 0 ? state.Gamepad.RightY : (short)0 };
    }
}

internal sealed class ControllerWitnessFrame
{
    internal string TargetA, TargetB;
    internal int Pid, Session;
    internal long Logon, MonotonicTicks;
    internal uint Slot;
    internal ControllerSlotState State;
    internal string Result { get { return State.Error == 0 ? "Connected" :
        State.Error == 1167 ? "Absent" : "ReadError"; } }
}

internal sealed class ControllerWitness
{
    private readonly IControllerSlotReader reader;
    internal ControllerWitness(IControllerSlotReader reader) { this.reader = reader; }
    internal ControllerWitnessFrame[] Observe(string targetA, string targetB,
        int pid, int session, long logon, long ticks)
    {
        if (String.IsNullOrWhiteSpace(targetA) || String.IsNullOrWhiteSpace(targetB) ||
            targetA == targetB || pid <= 0 || session <= 0 || logon <= 0 || ticks < 0)
            throw new ArgumentException("Two distinct declared target IDs and exact observer identity are required.");
        var frames = new ControllerWitnessFrame[4];
        for (uint slot = 0; slot < 4; slot++)
            frames[slot] = new ControllerWitnessFrame { TargetA = targetA, TargetB = targetB,
                Pid = pid, Session = session, Logon = logon, MonotonicTicks = ticks,
                Slot = slot, State = reader.Read(slot) };
        return frames;
    }
    // Synthetic challenge analysis only: a provider must first establish
    // which owned target produced each exclusive pulse. XInput itself does
    // not expose a virtual target's PnP identity or WTS ownership.
    internal static bool MatchDistinctPulses(ControllerWitnessFrame[] baseline,
        ControllerWitnessFrame[] pulseA, ControllerWitnessFrame[] pulseB,
        ushort aButton, ushort bButton, out int slotA, out int slotB)
    {
        slotA = slotB = -1;
        if (baseline == null || pulseA == null || pulseB == null || baseline.Length != 4 ||
            pulseA.Length != 4 || pulseB.Length != 4 || aButton == 0 || bButton == 0 ||
            aButton == bButton) return false;
        for (int i = 0; i < 4; i++)
        {
            var before = baseline[i]; var first = pulseA[i]; var second = pulseB[i];
            if (before.Slot != i || first.Slot != i || second.Slot != i ||
                before.Pid <= 0 || before.Pid != first.Pid || before.Pid != second.Pid ||
                before.Session != first.Session || before.Session != second.Session ||
                before.Logon != first.Logon || before.Logon != second.Logon ||
                String.IsNullOrWhiteSpace(before.TargetA) ||
                String.IsNullOrWhiteSpace(before.TargetB) || before.TargetA == before.TargetB ||
                before.TargetA != first.TargetA || before.TargetA != second.TargetA ||
                before.TargetB != first.TargetB || before.TargetB != second.TargetB ||
                before.Result == "ReadError" || first.Result == "ReadError" ||
                second.Result == "ReadError" || first.MonotonicTicks <= before.MonotonicTicks ||
                second.MonotonicTicks <= first.MonotonicTicks) return false;
            bool a = before.Result == "Connected" && first.Result == "Connected" &&
                second.Result == "Connected" &&
                (before.State.Buttons & aButton) == 0 &&
                (first.State.Buttons & aButton) != 0 && (second.State.Buttons & aButton) == 0;
            bool b = before.Result == "Connected" && first.Result == "Connected" &&
                second.Result == "Connected" &&
                (before.State.Buttons & bButton) == 0 &&
                (second.State.Buttons & bButton) != 0 && (first.State.Buttons & bButton) == 0;
            if (a) { if (slotA >= 0) return false; slotA = i; }
            if (b) { if (slotB >= 0) return false; slotB = i; }
        }
        return slotA >= 0 && slotB >= 0 && slotA != slotB;
    }
}

internal static class ControllerWitnessProgram
{
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    private static extern bool WtsQuery(IntPtr server, uint session, int infoClass, out IntPtr data, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr data);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsLevel1
    { public uint SessionId; public int State, Flags;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string Station;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string Domain;
      public long LogonTime; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsInfoEx { public uint Level; public WtsLevel1 Data; }
    private static long LogonTime(int session)
    {
        IntPtr data; int bytes;
        if (!WtsQuery(IntPtr.Zero, (uint)session, 25, out data, out bytes))
            throw new InvalidOperationException("Observer WTS logon generation is unavailable.");
        try
        {
            if (data == IntPtr.Zero || bytes < Marshal.SizeOf(typeof(WtsInfoEx)))
                throw new InvalidOperationException("Observer WTS generation is incomplete.");
            var info = (WtsInfoEx)Marshal.PtrToStructure(data, typeof(WtsInfoEx));
            if (info.Level != 1 || info.Data.SessionId != session || info.Data.LogonTime <= 0)
                throw new InvalidOperationException("Observer WTS generation is ambiguous.");
            return info.Data.LogonTime;
        }
        finally { if (data != IntPtr.Zero) WTSFreeMemory(data); }
    }
    public static int Main(string[] args)
    {
        // Ordinary startup never calls this entry point. The executable is
        // packaged as a review tool and must be invoked separately later.
        if (args.Length != 7 || args[0] != "--observe" || args[1] != "--session" ||
            args[3] != "--logon" || args[5] != "--targets") return 2;
        int expectedSession; long expectedLogon;
        string[] targets = args[6].Split(',');
        if (!Int32.TryParse(args[2], out expectedSession) ||
            !Int64.TryParse(args[4], out expectedLogon) || targets.Length != 2 ||
            String.IsNullOrWhiteSpace(targets[0]) || String.IsNullOrWhiteSpace(targets[1]) ||
            targets[0] == targets[1]) return 2;
        try
        {
            using (var process = Process.GetCurrentProcess())
            {
                int session = process.SessionId; long logon = LogonTime(session);
                if (session != expectedSession || logon != expectedLogon)
                    throw new InvalidOperationException("Observer is outside the approved exact session generation.");
                var witness = new ControllerWitness(new WindowsXInputSlotReader());
                var json = new JavaScriptSerializer();
                for (int sample = 0; sample < 20; sample++)
                {
                    var frames = witness.Observe(targets[0], targets[1], process.Id,
                        session, logon, Stopwatch.GetTimestamp());
                    foreach (var frame in frames)
                        Console.WriteLine(json.Serialize(new { schema = "ChildStream.ControllerWitness.v1",
                            pid = frame.Pid, session = frame.Session, logon = frame.Logon,
                            monotonicTicks = frame.MonotonicTicks, stopwatchFrequency = Stopwatch.Frequency,
                            targetADeclared = frame.TargetA, targetBDeclared = frame.TargetB,
                            targetAttribution = "UnresolvedByXInput", slot = frame.Slot,
                            apiResult = frame.State.Error, result = frame.Result,
                            packet = frame.State.Packet, buttons = frame.State.Buttons,
                            leftTrigger = frame.State.LeftTrigger, rightTrigger = frame.State.RightTrigger,
                            leftX = frame.State.LeftX, leftY = frame.State.LeftY,
                            rightX = frame.State.RightX, rightY = frame.State.RightY }));
                    Thread.Sleep(100);
                }
            }
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 3; }
    }
}
