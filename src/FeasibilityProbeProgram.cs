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
    private const string IsolationConfirmation = "I-CONFIRM-PHYSICAL-ISOLATION";
    private const string InteractionConfirmation = "I-OBSERVED-INDEPENDENT-DESKTOP";
    private static bool Confirmed(string[] args, int index)
    { return args.Length == index + 1 && args[index] == IsolationConfirmation; }
    private static void Usage()
    {
        Console.WriteLine("Connected posture: plan | begin HASH | prepare-a | verify-a | restore | restore-reviewed");
        Console.WriteLine("Isolated Stage A: plan-isolated CONFIRM | begin-isolated HASH CONFIRM | prepare-isolated CONFIRM | verify-isolated CONFIRM | restore-isolated CONFIRM | restore-isolated-reviewed CONFIRM | reconnect-check CONFIRM");
        Console.WriteLine("External-boundary Stage A: plan-boundary CONFIRM | begin-boundary HASH CONFIRM | prepare-boundary CONFIRM | verify-boundary CONFIRM | restore-boundary CONFIRM | restore-boundary-reviewed CONFIRM | reconnect-boundary-check CONFIRM");
        Console.WriteLine("Isolated Stage B (separate approval): approve-b-boundary HASH CONFIRM | connect-once-boundary CONFIRM | confirm-interaction-boundary ID:LOGON CONFIRM " + InteractionConfirmation + " | end-child-boundary ID:LOGON CONFIRM");
        Console.WriteLine("Isolated recovery: reconcile-connection-boundary CONFIRM | end-child-boundary-reviewed ID:LOGON CONFIRM (separate review required)");
        Console.WriteLine("CONFIRM is the literal " + IsolationConfirmation + ". Other commands: status | approve-b HASH | connect-once | confirm-console | end-child ID:LOGON | repair-journal");
        Console.WriteLine("All commands must run at the physical console. No automatic elevation or sign-out is performed.");
    }
    private static void Print(ProbeJournal journal)
    {
        Console.WriteLine("Stage=" + journal.Stage + " Plan=" + journal.Plan.Hash +
            " OriginalFeature=" + journal.Plan.Original.FeatureEnabled +
            " Parent=" + journal.ActiveParentId + ":" + journal.ActiveParentLogonTime +
            " Child=" + (journal.PositiveChild.HasValue
                ? journal.PositiveChild.Value.SessionId + ":" + journal.PositiveChild.Value.LogonTime : "none") +
            " Posture=" + journal.Plan.Original.NetworkPosture +
            " NetworkDeviation=" + journal.NetworkDeviationObserved +
            " NetworkRecoveryReviewed=" + journal.NetworkRecoveryReviewed +
            " DeviationReason=" + journal.NetworkDeviationReason +
            " Auth=" + journal.AuthenticationOutcome + " Error=" + journal.ErrorCode);
    }
    private static void RequirePosture(IProbeStore store, ProbeNetworkPosture expected)
    {
        ProbeJournal existing = store.Load();
        if (existing == null || existing.Plan.Original.NetworkPosture != expected)
            throw new InvalidOperationException("This command requires the matching probe posture and journal.");
    }
    private static void RequireExactChild(IProbeStore store, string value)
    {
        ProbeJournal existing = store.Load();
        if (existing == null || !existing.PositiveChild.HasValue ||
            value != existing.PositiveChild.Value.SessionId + ":" + existing.PositiveChild.Value.LogonTime)
            throw new InvalidOperationException("Exact child ID and generation approval does not match the journal.");
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
                if (args.Length != 1) throw new ArgumentException("Use plan without extra arguments.");
                var readOnly = new FeasibilityProbe(host, null, null).Plan();
                Console.WriteLine("Plan=" + readOnly.Hash + " OriginalFeature=" + readOnly.Original.FeatureEnabled +
                    " Parent=" + readOnly.Original.ParentSessionId + ":" + readOnly.Original.ParentLogonTime +
                    " ChildApi=" + readOnly.Original.ChildAccess + "/" + readOnly.Original.ChildApiErrorCode +
                    " IndependentSessions=" + readOnly.Original.IndependentNoUnexpectedSessions +
                    " LocalRdpPostureAccepted=" + readOnly.Original.LocalRdpPostureAccepted);
                return 0;
            }
            if (command == "plan-isolated" || command == "plan-boundary")
            {
                if (!Confirmed(args, 1)) throw new ArgumentException("Explicit physical isolation confirmation is required.");
                ProbeNetworkPosture requested = command == "plan-isolated"
                    ? ProbeNetworkPosture.NetworkIsolated : ProbeNetworkPosture.ExternalNetworkIsolated;
                var readOnly = new FeasibilityProbe(host, null, null).Plan(
                    requested, true);
                Console.WriteLine("Plan=" + readOnly.Hash + " Posture=" + requested +
                    " NetworkIsolationAccepted=" + (requested == ProbeNetworkPosture.NetworkIsolated
                        ? readOnly.Original.NetworkIsolationAccepted : readOnly.Original.BoundaryAccepted) +
                    " RdpPolicyDenied=" + readOnly.Original.RdpPolicyDenied +
                    " Parent=" + readOnly.Original.ParentSessionId + ":" + readOnly.Original.ParentLogonTime);
                return 0;
            }
            ProbePrivateState.Verify(command == "begin" || command == "begin-isolated" || command == "begin-boundary");
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
                case "begin-isolated":
                    if (args.Length != 3 || !Confirmed(args, 2))
                        throw new ArgumentException("Use begin-isolated with the reviewed hash and physical isolation confirmation.");
                    var isolatedPlan = probe.Plan(ProbeNetworkPosture.NetworkIsolated, true);
                    result = probe.Begin(isolatedPlan, args[1], true); break;
                case "begin-boundary":
                    if (args.Length != 3 || !Confirmed(args, 2))
                        throw new ArgumentException("Use begin-boundary with the reviewed hash and physical isolation confirmation.");
                    var boundaryPlan = probe.Plan(ProbeNetworkPosture.ExternalNetworkIsolated, true);
                    result = probe.Begin(boundaryPlan, args[1], true); break;
                case "prepare-a":
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.PrepareFeature(); break;
                case "prepare-isolated":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.NetworkIsolated);
                    result = probe.PrepareFeature(true); break;
                case "prepare-boundary":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.PrepareFeature(true); break;
                case "verify-a":
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.ResumeAfterFreshLogon(); break;
                case "verify-isolated":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.NetworkIsolated);
                    result = probe.ResumeAfterFreshLogon(true); break;
                case "verify-boundary":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.ResumeAfterFreshLogon(true); break;
                case "approve-b":
                    if (args.Length != 2) throw new ArgumentException("Use approve-b with the reviewed exact plan hash.");
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.ApproveStageB(args[1], true); break;
                case "approve-b-boundary":
                    if (args.Length != 3 || !Confirmed(args, 2))
                        throw new ArgumentException("Use approve-b-boundary with the reviewed hash and renewed physical isolation confirmation.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.ApproveStageB(args[1], true, true); break;
                case "connect-once":
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.ConnectOnce(); break;
                case "connect-once-boundary":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Renewed physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.ConnectOnce(true); break;
                case "confirm-console":
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.ConfirmConsoleUsable(true); break;
                case "confirm-interaction-boundary":
                    if (args.Length != 4 || args[2] != IsolationConfirmation || args[3] != InteractionConfirmation)
                        throw new ArgumentException("Exact child, physical isolation, and observed interaction confirmations are required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    RequireExactChild(store, args[1]);
                    result = probe.ConfirmConsoleUsable(true, true); break;
                case "end-child":
                    if (args.Length != 2) throw new ArgumentException("Use end-child ID:LOGON from the journal.");
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    RequireExactChild(store, args[1]);
                    result = probe.EndPositiveChild(true); break;
                case "end-child-boundary":
                    if (args.Length != 3 || !Confirmed(args, 2))
                        throw new ArgumentException("Exact child and renewed physical isolation confirmation are required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    RequireExactChild(store, args[1]);
                    result = probe.EndPositiveChild(true, true); break;
                case "reconcile-connection-boundary":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Renewed physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.ReconcileInterruptedConnection(true); break;
                case "end-child-boundary-reviewed":
                    if (args.Length != 3 || !Confirmed(args, 2))
                        throw new ArgumentException("Exact child and renewed physical isolation confirmation are required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    RequireExactChild(store, args[1]);
                    result = probe.EndPositiveChildReviewed(true, true); break;
                case "restore":
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.RestoreOriginal(); break;
                case "restore-reviewed":
                    RequirePosture(store, ProbeNetworkPosture.ConnectedRdpGuard);
                    result = probe.RestoreOriginal(true); break;
                case "restore-isolated":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    var isolatedRestore = store.Load();
                    if (isolatedRestore == null ||
                        isolatedRestore.Plan.Original.NetworkPosture != ProbeNetworkPosture.NetworkIsolated)
                        throw new InvalidOperationException("This command requires an isolated probe journal.");
                    result = probe.RestoreOriginal(false, false, true); break;
                case "restore-isolated-reviewed":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    var reviewedRestore = store.Load();
                    if (reviewedRestore == null ||
                        reviewedRestore.Plan.Original.NetworkPosture != ProbeNetworkPosture.NetworkIsolated)
                        throw new InvalidOperationException("This command requires an isolated probe journal.");
                    result = probe.RestoreOriginal(true, true, true); break;
                case "restore-boundary":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.RestoreOriginal(false, false, true); break;
                case "restore-boundary-reviewed":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    result = probe.RestoreOriginal(true, true, true); break;
                case "reconnect-check":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    RequirePosture(store, ProbeNetworkPosture.NetworkIsolated);
                    goto case "reconnect-boundary-check";
                case "reconnect-boundary-check":
                    if (!Confirmed(args, 1)) throw new ArgumentException("Physical isolation confirmation is required.");
                    if (command == "reconnect-boundary-check")
                        RequirePosture(store, ProbeNetworkPosture.ExternalNetworkIsolated);
                    var assessment = probe.AssessReconnect(true);
                    Console.WriteLine("ReconnectReady=" + assessment.Ready +
                        " FeatureRestored=" + assessment.FeatureRestored +
                        " ChildExcluded=" + assessment.ChildExcluded +
                        " NetworkIsolated=" + assessment.NetworkIsolated +
                        " RdpPolicyDenied=" + assessment.RdpPolicyDenied +
                        " TermServiceStopped=" + assessment.TermServiceStopped +
                        " RdpListenersAbsent=" + assessment.RdpListenersAbsent +
                        " InfrastructureRestored=" + assessment.InfrastructureRestored +
                        " JournalRestored=" + assessment.JournalRestored);
                    return assessment.Ready ? 0 : 1;
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
