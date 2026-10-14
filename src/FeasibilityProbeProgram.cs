using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

internal static class ProbePrivateState
{
    internal static string DirectoryPath
    {
        get
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!Path.IsPathRooted(local)) throw new InvalidOperationException("Local application data path is unavailable.");
            return Path.GetFullPath(Path.Combine(local, "ChildStream-Feasibility"));
        }
    }
    private static bool Permitted(IdentityReference identity)
    {
        string sid = identity.Translate(typeof(SecurityIdentifier)).Value;
        return sid == WindowsIdentity.GetCurrent().User.Value || sid == "S-1-5-18" || sid == "S-1-5-32-544";
    }
    private static void VerifyAcl(FileSystemSecurity security, string kind)
    {
        if (!Permitted(security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException("Probe " + kind + " owner is unsafe.");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !Permitted(rule.IdentityReference))
                throw new UnauthorizedAccessException("Probe " + kind + " grants an unapproved principal access.");
    }
    internal static void Verify(bool create)
    {
        VerifyAt(DirectoryPath, create);
    }
    internal static void VerifyAt(string path, bool create)
    {
        InstallerPolicy.ValidateCanonicalFilePath(path, true);
        if (!Directory.Exists(path))
        {
            if (!create) throw new DirectoryNotFoundException("Private probe state has not been created.");
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (string sid in new[] { WindowsIdentity.GetCurrent().User.Value, "S-1-5-18", "S-1-5-32-544" })
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                    FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(path, acl);
        }
        InstallerPolicy.ValidateCanonicalFilePath(path, true);
        var security = Directory.GetAccessControl(path, AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected)
            throw new UnauthorizedAccessException("Probe state directory ownership or inheritance is unsafe.");
        VerifyAcl(security, "directory");
        if (Directory.GetDirectories(path).Length != 0) throw new InvalidDataException("Unexpected probe state directory.");
        foreach (string file in Directory.GetFiles(path))
        {
            string name = Path.GetFileName(file);
            if (name != "probe.journal" && name != "probe.journal.new" && name != "probe.journal.prior" && name != "probe.lock" &&
                !name.StartsWith("probe.journal.interrupted-", StringComparison.Ordinal))
                throw new InvalidDataException("Unexpected probe state file.");
            InstallerPolicy.ValidateCanonicalFilePath(file);
            VerifyAcl(File.GetAccessControl(file, AccessControlSections.Access | AccessControlSections.Owner), "file");
        }
    }
}

internal static class FeasibilityProbeProgram
{
    private static void Usage()
    {
        Console.WriteLine("Commands: plan | begin HASH | prepare-a | status | verify-a | approve-b HASH | connect-once | confirm-console | end-child ID:LOGON | restore | restore-reviewed | repair-journal");
        Console.WriteLine("All commands must run at the physical console. No automatic elevation or sign-out is performed.");
    }
    private static void Print(ProbeJournal journal)
    {
        Console.WriteLine("Stage=" + journal.Stage + " Plan=" + journal.Plan.Hash +
            " OriginalFeature=" + journal.Plan.Original.FeatureEnabled +
            " Parent=" + journal.ActiveParentId + ":" + journal.ActiveParentLogonTime +
            " Child=" + (journal.PositiveChild.HasValue
                ? journal.PositiveChild.Value.SessionId + ":" + journal.PositiveChild.Value.LogonTime : "none") +
            " Auth=" + journal.AuthenticationOutcome + " Error=" + journal.ErrorCode);
    }
    [STAThread]
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0) { Usage(); return 2; }
            string command = args[0].ToLowerInvariant();
            if (command == "help") { Usage(); return 0; }
            string script = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                "..", "..", "scripts", "feasibility-inventory.ps1"));
            var host = new WindowsFeasibilityHost(new ScriptProbeInventory(script), new ProbeNative());
            if (command == "plan")
            {
                var readOnly = new FeasibilityProbe(host, null, null).Plan();
                Console.WriteLine("Plan=" + readOnly.Hash + " OriginalFeature=" + readOnly.Original.FeatureEnabled +
                    " Parent=" + readOnly.Original.ParentSessionId + ":" + readOnly.Original.ParentLogonTime +
                    " ChildApi=" + readOnly.Original.ChildAccess + "/" + readOnly.Original.ChildApiErrorCode +
                    " IndependentSessions=" + readOnly.Original.IndependentNoUnexpectedSessions +
                    " LocalRdpPostureAccepted=" + readOnly.Original.LocalRdpPostureAccepted);
                return 0;
            }
            ProbePrivateState.Verify(command == "begin");
            string dir = ProbePrivateState.DirectoryPath;
            var store = new FileProbeStore(Path.Combine(dir, "probe.journal"));
            var probe = new FeasibilityProbe(host, store,
                new FileTransactionOwnership(Path.Combine(dir, "probe.lock")));
            ProbeJournal result;
            switch (command)
            {
                case "begin":
                    if (args.Length != 2) throw new ArgumentException("Use begin with the reviewed exact plan hash.");
                    var plan = probe.Plan(); result = probe.Begin(plan, args[1], true); break;
                case "prepare-a": result = probe.PrepareFeature(); break;
                case "verify-a": result = probe.ResumeAfterFreshLogon(); break;
                case "approve-b":
                    if (args.Length != 2) throw new ArgumentException("Use approve-b with the reviewed exact plan hash.");
                    result = probe.ApproveStageB(args[1], true); break;
                case "connect-once": result = probe.ConnectOnce(); break;
                case "confirm-console": result = probe.ConfirmConsoleUsable(true); break;
                case "end-child":
                    if (args.Length != 2) throw new ArgumentException("Use end-child ID:LOGON from the journal.");
                    var existing = store.Load();
                    if (existing == null || !existing.PositiveChild.HasValue ||
                        args[1] != existing.PositiveChild.Value.SessionId + ":" + existing.PositiveChild.Value.LogonTime)
                        throw new InvalidOperationException("Exact child ID and generation approval does not match the journal.");
                    result = probe.EndPositiveChild(true); break;
                case "restore": result = probe.RestoreOriginal(); break;
                case "restore-reviewed": result = probe.RestoreOriginal(true); break;
                case "repair-journal": result = probe.ResolveInterruptedJournal(); break;
                case "status": result = store.Load(); break;
                default: Usage(); return 2;
            }
            if (result == null) Console.WriteLine("No probe journal exists."); else Print(result);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
            return 1;
        }
    }
}
