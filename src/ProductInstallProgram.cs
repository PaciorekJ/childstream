using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

// Standalone asInvoker bootstrap shipped in the reviewed candidate. Planning
// needs no elevation. Apply and reversal require a separately elevated console
// invocation and exact approved hash. No command changes the child feature,
// network policy, tasks, drivers, services, or user pairing identity.
internal static class ProductInstallProgram
{
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WTSGetActiveConsoleSessionId();
    private static string Root()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!Path.IsPathRooted(programFiles)) throw new InvalidOperationException("Program Files is unavailable.");
        string root = Path.Combine(programFiles, "ChildStream");
        InstallerPolicy.ValidateCanonicalFilePath(root, true);
        SetupInstallTrust.VerifyProtectedAcl(Directory.GetAccessControl(programFiles));
        if (Directory.Exists(root)) SetupInstallTrust.VerifyProtectedAcl(Directory.GetAccessControl(root));
        else if (File.Exists(root)) throw new InvalidOperationException("A file occupies the ChildStream installation root.");
        return root;
    }
    private static void RequireAdministratorConsole()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator) ||
            Process.GetCurrentProcess().SessionId <= 0 ||
            (uint)Process.GetCurrentProcess().SessionId != WTSGetActiveConsoleSessionId())
            throw new UnauthorizedAccessException("Installation or reversal requires a separately approved Administrator physical-console invocation.");
    }
    private static ProductInstallCoordinator Coordinator(string root)
    {
        string journal = Path.Combine(root, "install.journal");
        var host = new WindowsOwnedInstallerHost(root, journal);
        return new ProductInstallCoordinator(new InstallerEngine(host, new FileJournalStore(journal),
            new InstallerPolicy(root), new FileTransactionOwnership(Path.Combine(root, "install.lock"))),
            root, InstallPrivilege.Administrator);
    }
    private static FileStream AdmitSunshine(string path, string root)
    {
        var package = SunshineReleasePin.Create(Path.Combine(root, "versions", SunshineReleasePin.Version),
            Path.Combine(root, "identity"));
        return package.Admit(path, new PinnedSunshineReleaseVerifier());
    }
    private static LanFirewallTransaction Lan(string root, bool requireExecutable = true)
    {
        string executable = Path.Combine(root, "versions", SunshineReleasePin.Version, "sunshine.exe");
        InstallerPolicy.ValidateCanonicalFilePath(executable);
        if (requireExecutable) SetupInstallTrust.VerifyProtectedAcl(File.GetAccessControl(executable));
        else SetupInstallTrust.VerifyProtectedAcl(File.GetAccessControl(
            Path.Combine(root, "lan-firewall.journal")));
        return new LanFirewallTransaction(new WindowsLanFirewallHost(), root, executable,
            new SunshinePortFamily(48089));
    }
    private static void VerifyInstalledTrust(string root)
    {
        foreach (string path in new[] { root, Path.Combine(root, "scripts"),
            Path.Combine(root, "versions"), Path.Combine(root, "versions", SunshineReleasePin.Version) })
            SetupInstallTrust.VerifyProtectedAcl(Directory.GetAccessControl(path));
        foreach (string leaf in new[] { "ChildStream.exe", "ChildStreamSetup.exe",
            "ChildStreamBootstrap.exe",
            "feasibility-inventory.ps1", "rdp-containment-observe.ps1" }) SetupInstallTrust.RequireOwnedPath(leaf);
        string sunshine = Path.Combine(root, "versions", SunshineReleasePin.Version, "sunshine.exe");
        SetupInstallTrust.VerifyProtectedAcl(File.GetAccessControl(sunshine));
    }
    private static void WaitForInstalledParent(string value)
    {
        int pid;
        if (!Int32.TryParse(value, out pid) || pid <= 0 || pid == Process.GetCurrentProcess().Id)
            throw new InvalidDataException("Installed application PID is invalid.");
        try
        {
            using (Process parent = Process.GetProcessById(pid))
            {
                if (parent.HasExited) return;
                string expected = Path.Combine(Root(), "ChildStream.exe");
                if (!String.Equals(Path.GetFullPath(parent.MainModule.FileName), expected,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Maintenance parent is not the installed ChildStream app.");
                if (!parent.WaitForExit(120000))
                    throw new TimeoutException("Installed ChildStream did not exit; no files were reversed.");
            }
        }
        catch (ArgumentException) { } // The exact PID exited before the helper obtained a handle.
    }
    private static void ReverseOwnedFiles()
    {
        string root = Root();
        string setup = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData), "ChildStream", "setup");
        if (Directory.Exists(setup))
            foreach (string requester in Directory.GetDirectories(setup))
            {
                InstallerPolicy.ValidateCanonicalFilePath(requester, true);
                if (File.Exists(Path.Combine(requester, "rdp-containment.journal")))
                    throw new InvalidOperationException("Recover exact requester-owned RDP containment before reversing installed code.");
            }
        if (WindowsRdpContainmentHost.AnyOwnedPolicyRule())
            throw new InvalidOperationException("ChildStream RDP containment rules still exist; restore them before uninstall.");
        if (File.Exists(Path.Combine(root, "lan-firewall.journal"))) Lan(root, false).Recover();
        Coordinator(root).RecoverOrUninstall();
        Console.WriteLine("Exact ChildStream-owned installation bytes reversed. Per-user pairing identity remains.");
    }
    internal static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && (args[0] == "-recover" || args[0] == "-uninstall"))
            {
                RequireAdministratorConsole();
                ReverseOwnedFiles();
                return 0;
            }
            if (args.Length == 2 && (args[0] == "-recover-after-parent" ||
                args[0] == "-uninstall-after-parent"))
            {
                RequireAdministratorConsole();
                WaitForInstalledParent(args[1]);
                ReverseOwnedFiles();
                return 0;
            }
            if (args.Length == 1 && args[0] == "-recover-lan")
            {
                RequireAdministratorConsole(); Lan(Root(), false).Recover();
                Console.WriteLine("Exact ChildStream LAN rules reversed and verified."); return 0;
            }
            if ((args.Length == 2 && args[0] == "-plan-lan") ||
                (args.Length == 3 && args[0] == "-apply-lan"))
            {
                bool mutation = args[0] == "-apply-lan";
                if (mutation) RequireAdministratorConsole();
                string root = Root();
                LanFirewallTransaction lan = Lan(root);
                if (mutation && lan.ApprovedNoOp(args[1], args[2]))
                { Console.WriteLine("Exact ChildStream LAN firewall rules remain verified."); return 0; }
                LanFirewallPlan plan = lan.Plan(args[1], SunshineReleasePin.ExecutableSha256);
                if (mutation)
                { lan.Apply(plan, args[2]); Console.WriteLine("Exact ChildStream LAN firewall rules applied and verified."); }
                else
                { Console.WriteLine("ChildStream LAN plan SHA-256: " + plan.Hash);
                  Console.WriteLine("Scope: pinned ChildStream Sunshine, Private profile, selected local IPv4 and subnet; Web UI port excluded."); }
                return 0;
            }
            if (args.Length == 2 && args[0] == "-fetch-sunshine")
            {
                // This is an explicit package fetch, never an install or feature change.
                PinnedSunshineDownload.Fetch(args[1]);
                Console.WriteLine("Pinned Sunshine archive downloaded and SHA-256 verified.");
                return 0;
            }
            if ((args.Length == 4 || args.Length == 5) &&
                (args[0] == "-plan" || args[0] == "-apply" || args[0] == "-repair") &&
                (args[0] == "-plan" ? args.Length == 4 : args.Length == 5))
            {
                bool mutation = args[0] != "-plan";
                if (mutation) RequireAdministratorConsole();
                string root = Root();
                ProductInstallPayload candidate = ProductInstallPayload.ReadCandidate(args[1], args[2]);
                using (FileStream archive = AdmitSunshine(args[3], root))
                {
                    ProductInstallCoordinator coordinator = Coordinator(root);
                    ProductInstallPlan plan = args[0] == "-repair"
                        ? coordinator.PlanCommitted(candidate, archive,
                            new FileJournalStore(Path.Combine(root, "install.journal")).Load())
                        : coordinator.Plan(candidate, archive);
                    if (!mutation)
                    {
                        Console.WriteLine("ChildStream install plan SHA-256: " + plan.Hash);
                        Console.WriteLine("Scope: five fixed owned files and pinned portable Sunshine. No Windows feature, task or firewall change.");
                    }
                    else
                    {
                        coordinator.Apply(plan, candidate, archive, args[4]);
                        VerifyInstalledTrust(root);
                        Console.WriteLine(args[0] == "-repair"
                            ? "Committed ChildStream payload verified intact. Missing or changed owned files require reviewed recovery and a new plan."
                            : "Protected ChildStream payload installed and exact ACL/hash checks passed.");
                    }
                }
                return 0;
            }
            Console.Error.WriteLine("Usage: -plan <candidate.zip> <reviewed-candidate-sha256> <pinned-sunshine.zip> | -apply/-repair <same> <approved-plan-sha256> | -recover | -uninstall | -fetch-sunshine <new-file-path> | -plan-lan <private-ip> | -apply-lan <private-ip> <plan-sha256> | -recover-lan");
            return 2;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message); return 3; }
    }
}

internal static class PinnedSunshineDownload
{
    internal static void Fetch(string destination)
    {
        InstallerPolicy.ValidateCanonicalFilePath(destination);
        if (File.Exists(destination) || Directory.Exists(destination) ||
            !String.Equals(Path.GetFileName(destination), SunshineReleasePin.AssetName, StringComparison.Ordinal))
            throw new InvalidOperationException("Download requires an absent, exact pinned asset filename.");
        string parent = Path.GetDirectoryName(destination);
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException("The chosen download directory must exist.");
        string partial = destination + ".childstream-partial";
        InstallerPolicy.ValidateCanonicalFilePath(partial);
        if (File.Exists(partial)) throw new InvalidOperationException("An interrupted owned download needs manual review.");
        var request = (HttpWebRequest)WebRequest.Create(SunshineReleasePin.AssetUrl);
        request.Method = "GET"; request.AllowAutoRedirect = true; request.MaximumAutomaticRedirections = 5;
        request.Timeout = 30000; request.ReadWriteTimeout = 30000;
        using (var response = (HttpWebResponse)request.GetResponse())
        {
            if (response.StatusCode != HttpStatusCode.OK || response.ResponseUri.Scheme != Uri.UriSchemeHttps ||
                !(response.ResponseUri.Host == "github.com" ||
                  response.ResponseUri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Pinned release download redirected outside approved HTTPS hosts.");
            using (var input = response.GetResponseStream())
            using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                byte[] buffer = new byte[65536]; long total = 0; int count;
                using (var sha = SHA256.Create())
                {
                    while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        total += count;
                        if (total > 1024L * 1024 * 1024) throw new InvalidDataException("Pinned asset exceeds 1 GiB.");
                        sha.TransformBlock(buffer, 0, count, null, 0);
                        output.Write(buffer, 0, count);
                    }
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    output.Flush(true);
                    if (!String.Equals(ProductInstallPayload.Hex(sha.Hash), SunshineReleasePin.ArchiveSha256,
                        StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Pinned Sunshine archive digest mismatch.");
                }
            }
        }
        File.Move(partial, destination); // Never overwrite an existing package.
    }
}
