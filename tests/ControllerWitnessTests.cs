using System;

internal static class ControllerWitnessTests
{
    private sealed class Reader : IControllerSlotReader
    {
        internal readonly ControllerSlotState[] States = new ControllerSlotState[4];
        public ControllerSlotState Read(uint slot) { return States[slot]; }
    }
    private static int checks;
    private static void Check(bool value, string message)
    { checks++; if (!value) throw new Exception(message); }
    public static int Main()
    {
        var reader = new Reader(); var witness = new ControllerWitness(reader);
        reader.States[0] = new ControllerSlotState { Error = 1167 };
        reader.States[1] = new ControllerSlotState { Error = 0, Packet = 4 };
        reader.States[2] = new ControllerSlotState { Error = 0, Packet = 8 };
        reader.States[3] = new ControllerSlotState { Error = 5 };
        var baseline = witness.Observe("owned-target-A", "owned-target-B", 50, 2, 900, 100);
        Check(baseline[0].Result == "Absent" && baseline[3].Result == "ReadError" &&
            baseline[1].Result == "Connected", "returned XInput code distinguishes absence from read failure");
        Check(baseline[1].Pid == 50 && baseline[1].Session == 2 && baseline[1].Logon == 900 &&
            baseline[1].MonotonicTicks == 100 && baseline[1].Slot == 1,
            "each sample retains own exact session generation and monotonic observation time");
        reader.States[3] = new ControllerSlotState { Error = 1167 };
        baseline = witness.Observe("owned-target-A", "owned-target-B", 50, 2, 900, 100);
        reader.States[1] = new ControllerSlotState { Error = 0, Buttons = 0x1000, Packet = 5 };
        var pulseA = witness.Observe("owned-target-A", "owned-target-B", 50, 2, 900, 200);
        reader.States[1] = new ControllerSlotState { Error = 0, Packet = 6 };
        reader.States[2] = new ControllerSlotState { Error = 0, Buttons = 0x2000, Packet = 9 };
        var pulseB = witness.Observe("owned-target-A", "owned-target-B", 50, 2, 900, 300);
        int slotA, slotB;
        Check(ControllerWitness.MatchDistinctPulses(baseline, pulseA, pulseB,
            0x1000, 0x2000, out slotA, out slotB) && slotA == 1 && slotB == 2,
            "two distinct declared targets correlate to separate synthetic pulse slots");
        pulseB[2].Logon++;
        Check(!ControllerWitness.MatchDistinctPulses(baseline, pulseA, pulseB,
            0x1000, 0x2000, out slotA, out slotB),
            "reused session ID with changed logon generation cannot inherit controller mapping");
        pulseB[2].Logon--;
        pulseB[2].State.Error = 1167;
        Check(!ControllerWitness.MatchDistinctPulses(baseline, pulseA, pulseB,
            0x1000, 0x2000, out slotA, out slotB),
            "disconnect loses the target mapping until a new exclusive challenge");
        pulseB[2].State.Error = 0;
        var reconnect = witness.Observe("owned-target-A", "owned-target-B", 50, 2, 900, 400);
        Check(reconnect[2].Result == "Connected" && reconnect[2].State.Buttons == 0x2000,
            "reconnect is observed as a new reading, never assumed from prior slot state");
        pulseA[0].State.Error = 5;
        Check(!ControllerWitness.MatchDistinctPulses(baseline, pulseA, pulseB,
            0x1000, 0x2000, out slotA, out slotB),
            "any relevant XInput read error invalidates the whole synthetic challenge");
        Console.WriteLine("Controller witness synthetic assertions passed: " + checks);
        return 0;
    }
}
