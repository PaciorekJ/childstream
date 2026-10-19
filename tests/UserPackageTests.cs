using System;
using System.IO;

internal static class UserPackageTests
{
    internal static int Main(string[] args)
    {
        try
        {
            if (args.Length != 1) throw new ArgumentException("Extracted user package directory required.");
            ProductBundle bundle = ProductBundle.Read(args[0]);
            if (!File.Exists(bundle.CandidatePath) || !File.Exists(bundle.SunshinePath) ||
                bundle.SourceSha.Length != 40 ||
                WindowsProductInstallWorkflow.SelectBootstrapPath(args[0], bundle.CandidatePath,
                    Path.Combine(args[0], "uninstalled-Program-Files-fixture"), false) !=
                    Path.Combine(args[0], "ChildStreamBootstrap.exe") ||
                WindowsProductInstallWorkflow.SelectBootstrapPath(
                    Path.Combine(args[0], "installed-Program-Files-fixture"), bundle.CandidatePath,
                    Path.Combine(args[0], "installed-Program-Files-fixture"), true) !=
                    Path.Combine(args[0], "ChildStreamBootstrap.exe"))
                throw new InvalidDataException("Extracted package does not connect to its bootstrap and payloads.");
            Console.WriteLine("Extracted user package admitted by production bundle and installer bootstrap: " + bundle.SourceSha);
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
