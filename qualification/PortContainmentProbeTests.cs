// REVIEW-ONLY PREPARATION — LIVE EXECUTION NOT AUTHORIZED.
// All network and host effects are substituted. This test opens no socket.
using System;
using System.Collections.Generic;
using System.Net.Sockets;

internal sealed class FakePortProbeRuntime : IPortProbeRuntime
{
    internal int Calls;
    internal PortProbeOptions Last;
    public void Run(PortProbeOptions options, Action<string> emit)
    { Calls++; Last = options; emit("FAKE_RUNTIME"); }
}

internal static class PortContainmentProbeTests
{
    private static int checks;
    private static void Check(bool good, string name)
    { checks++; if (!good) throw new Exception("Synthetic regression: " + name); }
    private static string[] Command(string protocol, string local, string lan, string port,
        string seconds, string attempts)
    { return new[] { "receive", "--reviewed-live-approval", "YES", "--protocol", protocol,
        "--local", local, "--lan", lan, "--port", port, "--seconds", seconds,
        "--max-attempts", attempts }; }
    private static void Rejected(string[] command, string name)
    {
        var fake = new FakePortProbeRuntime();
        var output = new List<string>();
        Check(PortContainmentProbeProgram.Run(command, fake, output.Add) == 2 && fake.Calls == 0,
            name + " does not invoke socket runtime");
    }
    private static void Main()
    {
        var fake = new FakePortProbeRuntime();
        var output = new List<string>();
        Check(PortContainmentProbeProgram.Run(new string[0], fake, output.Add) == 0 &&
            fake.Calls == 0 && output[0] == PortContainmentProbeProgram.Label,
            "default is no-op help");
        output.Clear();
        Check(PortContainmentProbeProgram.Run(new[] { "--help" }, fake, output.Add) == 0 &&
            fake.Calls == 0, "help is no-op");
        var v4 = Command("TCP", "127.0.0.1", "192.0.2.10", "3389", "30", "4");
        Check(PortContainmentProbeProgram.Run(v4, fake, output.Add) == 0 && fake.Calls == 1 &&
            fake.Last.Protocol == ProtocolType.Tcp && fake.Last.Port == 3389 &&
            fake.Last.Seconds == 30 && fake.Last.MaxAttempts == 4,
            "explicit v4 TCP options reach substituted runtime");
        var v6 = Command("UDP", "::1", "2001:db8::10", "3389", "60", "8");
        Check(PortContainmentProbeProgram.Run(v6, fake, output.Add) == 0 && fake.Calls == 2 &&
            fake.Last.Protocol == ProtocolType.Udp && fake.Last.Lan.AddressFamily ==
            AddressFamily.InterNetworkV6, "explicit v6 UDP options reach substituted runtime");
        v4[2] = "NO";
        Rejected(v4, "absent approval marker");
        Rejected(Command("TCP", "127.0.0.1", "127.0.0.1", "3389", "30", "4"),
            "loopback as LAN");
        Rejected(Command("TCP", "127.0.0.1", "0.0.0.0", "3389", "30", "4"),
            "wildcard LAN");
        Rejected(Command("TCP", "127.0.0.1", "::ffff:192.0.2.10", "3389", "30", "4"),
            "mapped or mixed-family address");
        Rejected(Command("UDP", "::1", "fe80::1", "3389", "30", "4"),
            "unscoped IPv6 link-local");
        Rejected(Command("TCP", "127.0.0.1", "192.0.2.10", "0", "30", "4"),
            "invalid port");
        Rejected(Command("TCP", "127.0.0.1", "192.0.2.10", "3389", "121", "4"),
            "duration bound");
        Rejected(Command("UDP", "127.0.0.1", "192.0.2.10", "3389", "30", "9"),
            "attempt bound");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, false, true, true, true) ==
            "SUPPORTS TESTED RULE", "complete matching drop and local control");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, true, true, true, true) ==
            "REJECTS TESTED RULE OR SETUP", "unexpected remote reception");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, false, true, false, true) ==
            "REJECTS TESTED RULE OR SETUP", "local path blocked");
        Check(PortProbeVerdict.ClassifyEnforcement(true, false, false, true, true, true) ==
            "INCONCLUSIVE", "timeout or other-filter drop insufficient");
        Check(PortProbeVerdict.ClassifyEnforcement(true, true, false, true, true, false) ==
            "INCONCLUSIVE", "missing event coverage");
        Check(PortProbeVerdict.ClassifyCleanup(false) == "INCOMPLETE" &&
            PortProbeVerdict.ClassifyEnforcement(true, true, false, true, true, true) ==
            "SUPPORTS TESTED RULE", "cleanup reported separately from enforcement");
        Check(PortProbeVerdict.ClassifyEnforcement(false, false, false, false, false, false) ==
            "INCONCLUSIVE", "unavailable sender is inconclusive");
        DateTime start = new DateTime(2026, 10, 18, 0, 0, 0, DateTimeKind.Utc);
        Check(PortProbeBudget.Continue(start, start.AddSeconds(30), 0, 4, false),
            "budget initially allows observation");
        Check(!PortProbeBudget.Continue(start.AddSeconds(30), start.AddSeconds(30), 0, 4, false),
            "deadline stops observation");
        Check(!PortProbeBudget.Continue(start, start.AddSeconds(30), 4, 4, false),
            "attempt cap stops observation");
        Check(!PortProbeBudget.Continue(start, start.AddSeconds(30), 0, 4, true),
            "cancellation stops observation");
        Console.WriteLine("Port containment synthetic checks passed: " + checks);
    }
}
