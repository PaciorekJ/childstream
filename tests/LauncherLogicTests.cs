using System;
using System.Reflection;

static class LauncherLogicTests
{
    static MethodInfo Method(string name)
    {
        var result = typeof(Program).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static);
        if (result == null) throw new Exception("Missing method: " + name);
        return result;
    }

    static void Check(bool expected, uint candidate, uint connected, uint parent)
    {
        bool actual = (bool)Method("IsOwnedChild").Invoke(null, new object[] { candidate, connected, parent });
        if (actual != expected) throw new Exception("Session ownership mismatch: " + candidate);
    }

    static void Display(string input, bool valid)
    {
        try
        {
            int[] result = (int[])Method("ParseDisplayConfig").Invoke(null, new object[] { input });
            if (!valid || result[0] < 640 || result[1] < 480) throw new Exception("Invalid display config accepted: " + input);
        }
        catch (TargetInvocationException ex)
        {
            if (valid || !(ex.InnerException is FormatException)) throw;
        }
    }

    public static int Main()
    {
        Check(true, 7, 7, 1);
        Check(false, 7, 8, 1);
        Check(false, 1, 1, 1);
        Check(false, uint.MaxValue, uint.MaxValue, 1);
        Display("1920x1080", true);
        Display("2800x1272x225", true);
        Display("-1x1080", false);
        Display("1920x0", false);
        Display("1920x1080x0", false);
        Display("1920x1080x225x9", false);
        Console.WriteLine("10 offline launcher logic cases passed");
        return 0;
    }
}
