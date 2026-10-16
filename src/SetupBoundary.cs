using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

internal enum SetupOperation : byte { PlanConnected = 1, BeginConnected = 2, PrepareFeature = 3,
    RestoreOriginal = 4, ReadJournal = 5, ReviewedRestore = 6,
    PlanLan = 7, ApplyLan = 8, RecoverLan = 9, ReadLanJournal = 10 }

internal sealed class SetupRequest
{
    internal SetupOperation Operation;
    internal string ApprovedPlanHash = "";
    internal string LanAddress = "";
    internal void Validate()
    {
        bool lan = Operation == SetupOperation.PlanLan || Operation == SetupOperation.ApplyLan ||
            Operation == SetupOperation.RecoverLan || Operation == SetupOperation.ReadLanJournal;
        bool readOnly = Operation == SetupOperation.PlanConnected || Operation == SetupOperation.ReadJournal ||
            Operation == SetupOperation.PlanLan || Operation == SetupOperation.ReadLanJournal;
        if (lan)
        {
            System.Net.IPAddress address;
            if (!System.Net.IPAddress.TryParse(LanAddress, out address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                LanAddress.Length > 45)
                throw new InvalidDataException("LAN setup requires one concrete IPv4 address.");
        }
        if (!Enum.IsDefined(typeof(SetupOperation), Operation) || ApprovedPlanHash == null ||
            (!lan && !String.IsNullOrEmpty(LanAddress)) ||
            (readOnly && ApprovedPlanHash.Length != 0) ||
            (!readOnly &&
                !System.Text.RegularExpressions.Regex.IsMatch(
                ApprovedPlanHash, "\\A[0-9a-fA-F]{64}\\z")))
            throw new InvalidDataException("Only a fixed setup operation and exact plan SHA-256 are accepted.");
    }
}

internal static class SetupWire
{
    internal static void SendRequest(Stream stream, SetupRequest request)
    {
        request.Validate();
        using (var writer = new BinaryWriter(stream, Encoding.ASCII, true))
        { writer.Write((byte)request.Operation); writer.Write((byte)request.ApprovedPlanHash.Length);
          writer.Write(Encoding.ASCII.GetBytes(request.ApprovedPlanHash));
          writer.Write((byte)request.LanAddress.Length); writer.Write(Encoding.ASCII.GetBytes(request.LanAddress));
          writer.Flush(); }
    }
    internal static SetupRequest ReadRequest(Stream stream)
    {
        using (var reader = new BinaryReader(stream, Encoding.ASCII, true))
        {
            SetupOperation operation = (SetupOperation)reader.ReadByte();
            int length = reader.ReadByte();
            if (length != 0 && length != 64) throw new InvalidDataException("Setup request length is invalid.");
            byte[] bytes = reader.ReadBytes(length);
            if (bytes.Length != length) throw new EndOfStreamException("Setup request is incomplete.");
            int addressLength = reader.ReadByte();
            if (addressLength > 45) throw new InvalidDataException("Setup LAN address length is invalid.");
            byte[] address = reader.ReadBytes(addressLength);
            if (address.Length != addressLength) throw new EndOfStreamException("Setup LAN address is incomplete.");
            var request = new SetupRequest { Operation = operation,
                ApprovedPlanHash = Encoding.ASCII.GetString(bytes),
                LanAddress = Encoding.ASCII.GetString(address) };
            request.Validate(); return request;
        }
    }
    internal static void SendResult(Stream stream, bool accepted, string result)
    {
        if (result == null) result = "";
        if (result.Length > 512) result = result.Substring(0, 512);
        byte[] bytes = Encoding.UTF8.GetBytes(result);
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
        { writer.Write((byte)(accepted ? 0 : 1)); writer.Write((ushort)bytes.Length);
          writer.Write(bytes); writer.Flush(); }
    }
    internal static string ReadResult(Stream stream)
    {
        using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
        {
            byte status = reader.ReadByte();
            int length = reader.ReadUInt16();
            if (length > 2048 || (status != 0 && status != 1))
                throw new InvalidDataException("Setup result is malformed.");
            byte[] bytes = reader.ReadBytes(length);
            if (bytes.Length != length) throw new EndOfStreamException("Setup result is incomplete.");
            string result = new UTF8Encoding(false, true).GetString(bytes);
            if (status != 0) throw new InvalidOperationException(result);
            return result;
        }
    }
}

internal static class SetupPeerPolicy
{
    internal static void RequireElevatedConsole(RuntimeTokenStatus helperToken, bool administrator,
        int helperSession, int expectedSession, uint activeConsole)
    {
        if (helperToken != RuntimeTokenStatus.Elevated || !administrator ||
            helperSession != expectedSession || expectedSession <= 0 ||
            (uint)expectedSession != activeConsole)
            throw new UnauthorizedAccessException("Setup requires an elevated physical-console Administrator token.");
    }
    internal static void RequireRequester(ProductProcessIdentity process, ProcessTokenObservation token,
        int expectedPid, int expectedSession, string expectedSid, string expectedPath, string expectedHash)
    {
        if (process == null || token == null || process.Pid != expectedPid ||
            process.SessionId != expectedSession || process.StartTimeUtcTicks <= 0 ||
            !String.Equals(process.ExecutablePath, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(process.ExecutableSha256, expectedHash, StringComparison.OrdinalIgnoreCase) ||
            token.Elevation != RuntimeTokenStatus.Limited || token.Sid != expectedSid)
            throw new UnauthorizedAccessException("The requesting limited user or protected application changed.");
    }
    internal static void RequireAuthenticatedHelper(ProductProcessIdentity process,
        ProcessTokenObservation token, int launchedPid, int expectedSession,
        string expectedPath, string expectedHash)
    {
        if (process == null || token == null || process.Pid != launchedPid ||
            process.SessionId != expectedSession || process.StartTimeUtcTicks <= 0 ||
            !String.Equals(process.ExecutablePath, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(process.ExecutableSha256, expectedHash, StringComparison.OrdinalIgnoreCase) ||
            token.Elevation != RuntimeTokenStatus.Elevated)
            throw new UnauthorizedAccessException("Setup helper is not the exact elevated protected process.");
    }
}

internal sealed class SetupTransaction
{
    private readonly FeasibilityProbe probe;
    private readonly IProbeStore store;
    private readonly LanFirewallTransaction lan;
    private readonly string lanExecutableHash;
    internal SetupTransaction(FeasibilityProbe probe, IProbeStore store,
        LanFirewallTransaction lan = null)
    { this.probe = probe; this.store = store; this.lan = lan;
      lanExecutableHash = SunshineReleasePin.ExecutableSha256; }
#if TEST_ONLY
    internal SetupTransaction(LanFirewallTransaction lan, string fixtureExecutableHash)
    { this.lan = lan; lanExecutableHash = fixtureExecutableHash; }
#endif
    internal string Execute(SetupRequest request, bool explicitlyApproved)
    {
        request.Validate();
        if (request.Operation == SetupOperation.PlanLan || request.Operation == SetupOperation.ApplyLan ||
            request.Operation == SetupOperation.RecoverLan || request.Operation == SetupOperation.ReadLanJournal)
        {
            if (lan == null) throw new InvalidOperationException("The protected ChildStream LAN transaction is unavailable.");
            if (request.Operation == SetupOperation.PlanLan)
                return "LAN plan " + lan.Plan(request.LanAddress, lanExecutableHash).Hash;
            if (request.Operation == SetupOperation.ReadLanJournal)
                return "LAN journal " + lan.ReadJournalHash(request.LanAddress) +
                    "; verified=" + lan.Verify(request.LanAddress);
            if (!explicitlyApproved) throw new InvalidOperationException("The exact LAN transition was not approved.");
            if (request.Operation == SetupOperation.ApplyLan)
            {
                if (lan.ApprovedNoOp(request.LanAddress, request.ApprovedPlanHash))
                    return "LAN rules verified for " + request.LanAddress;
                lan.Apply(lan.Plan(request.LanAddress, lanExecutableHash),
                    request.ApprovedPlanHash);
                return "LAN rules verified for " + request.LanAddress;
            }
            lan.RecoverApproved(request.LanAddress, request.ApprovedPlanHash);
            return "LAN rules restored for " + request.LanAddress;
        }
        if (request.Operation == SetupOperation.PlanConnected)
        {
            ProbePlan plan = probe.Plan(ProbeNetworkPosture.ConnectedRdpGuard);
            return "Plan " + plan.Hash + "; feature=" + plan.Original.FeatureEnabled +
                "; parent=" + plan.Original.ParentSessionId + ":" + plan.Original.ParentLogonTime;
        }
        if (request.Operation == SetupOperation.ReadJournal)
        {
            ProbeJournal journal = store == null ? null : store.Load();
            return journal == null ? "No ChildStream setup journal for this requester." :
                "Journal " + journal.Plan.Hash + "; stage=" + journal.Stage;
        }
        if (!explicitlyApproved) throw new InvalidOperationException("The exact setup transition was not approved.");
        if (request.Operation == SetupOperation.BeginConnected)
        {
            ProbePlan plan = probe.Plan(ProbeNetworkPosture.ConnectedRdpGuard);
            ProbeJournal begun = probe.Begin(plan, request.ApprovedPlanHash, true);
            return "Journal " + begun.Plan.Hash + "; stage=" + begun.Stage;
        }
        ProbeJournal existing = store.Load();
        if (existing == null || !String.Equals(existing.Plan.Hash, request.ApprovedPlanHash,
            StringComparison.OrdinalIgnoreCase) ||
            existing.Plan.Original.NetworkPosture != ProbeNetworkPosture.ConnectedRdpGuard)
            throw new InvalidOperationException("No exact connected-plan journal exists for this requester.");
        ProbeJournal outcome = request.Operation == SetupOperation.PrepareFeature
            ? probe.PrepareFeature() : probe.RestoreOriginal(
                request.Operation == SetupOperation.ReviewedRestore);
        return "Journal " + outcome.Plan.Hash + "; stage=" + outcome.Stage;
    }
}

internal static class SetupInstallTrust
{
    private static bool TrustedOwner(string sid)
    { return sid == "S-1-5-18" || sid == "S-1-5-32-544" ||
        sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; }
    internal static void VerifyProtectedAcl(FileSystemSecurity security)
    {
        if (security == null || !TrustedOwner(security.GetOwner(typeof(SecurityIdentifier)).Value))
            throw new UnauthorizedAccessException("Installed code has an untrusted owner.");
        // FileSystemRights.Write/Modify/FullControl are composites. In
        // particular FullControl intersects ReadAndExecute, so testing it as a
        // mask incorrectly rejects every normal standard-user reader.
        const FileSystemRights mutation = FileSystemRights.WriteData |
            FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes |
            FileSystemRights.WriteAttributes | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        const FileSystemRights readable = FileSystemRights.ReadData | FileSystemRights.ExecuteFile |
            FileSystemRights.ReadExtendedAttributes | FileSystemRights.ReadAttributes |
            FileSystemRights.ReadPermissions | FileSystemRights.Synchronize;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            string sid = rule.IdentityReference.Value;
            if (!TrustedOwner(sid) && ((rule.FileSystemRights & mutation) != 0 ||
                (rule.FileSystemRights & ~readable) != 0))
                throw new UnauthorizedAccessException("Installed code is mutable by an untrusted principal.");
        }
    }
    internal static string RequireOwnedPath(string leaf)
    {
        if (leaf != "ChildStream.exe" && leaf != "ChildStreamSetup.exe" &&
            leaf != "feasibility-inventory.ps1")
            throw new InvalidOperationException("Unknown setup binary or script.");
        string root = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ChildStream"));
        string path = leaf.EndsWith(".ps1", StringComparison.Ordinal)
            ? Path.Combine(root, "scripts", leaf) : Path.Combine(root, leaf);
        InstallerPolicy.ValidateCanonicalFilePath(path);
        if (!File.Exists(path)) throw new FileNotFoundException("Protected ChildStream install is incomplete.", path);
        foreach (string item in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            root, Path.GetDirectoryName(path), path })
        {
            var security = File.Exists(item) ? (FileSystemSecurity)File.GetAccessControl(item) :
                Directory.GetAccessControl(item);
            VerifyProtectedAcl(security);
        }
        return path;
    }
    internal static string RequireOwnedSunshine()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string root = Path.Combine(programFiles, "ChildStream");
        string versions = Path.Combine(root, "versions");
        string version = Path.Combine(versions, SunshineReleasePin.Version);
        string sunshine = Path.Combine(version, "sunshine.exe");
        InstallerPolicy.ValidateCanonicalFilePath(sunshine);
        foreach (string directory in new[] { programFiles, root, versions, version })
            VerifyProtectedAcl(Directory.GetAccessControl(directory));
        VerifyProtectedAcl(File.GetAccessControl(sunshine));
        if (!String.Equals(Hash(sunshine), SunshineReleasePin.ExecutableSha256,
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Portable ChildStream Sunshine executable differs from the build pin.");
        return sunshine;
    }
    internal static string Hash(string path)
    {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
    }
    internal static string AccountHash(string sid)
    {
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(new SecurityIdentifier(sid).Value)))
                .Replace("-", "").ToLowerInvariant();
    }
}

internal static class SetupPrivateJournal
{
    private static DirectorySecurity PrivateAcl()
    {
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        var admins = new SecurityIdentifier("S-1-5-32-544"); acl.SetOwner(admins);
        foreach (string sid in new[] { "S-1-5-18", "S-1-5-32-544" })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }
    private static void VerifyPrivateAcl(FileSystemSecurity security, bool directory)
    {
        if (directory && !security.AreAccessRulesProtected)
            throw new UnauthorizedAccessException("Setup journal directory inherits unknown access.");
        if (directory)
        {
            string owner = security.GetOwner(typeof(SecurityIdentifier)).Value;
            if (owner != "S-1-5-32-544" && owner != "S-1-5-18")
                throw new UnauthorizedAccessException("Setup journal directory owner is not Administrators or SYSTEM.");
        }
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Value != "S-1-5-18" && rule.IdentityReference.Value != "S-1-5-32-544")
                throw new UnauthorizedAccessException("Setup journal grants access outside Administrators and SYSTEM.");
    }
    internal static string PathFor(string requesterSid, bool create)
    {
        new SecurityIdentifier(requesterSid);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string owned = Path.Combine(programData, "ChildStream");
        string basePath = Path.Combine(owned, "setup");
        string path = Path.Combine(basePath, requesterSid);
        InstallerPolicy.ValidateCanonicalFilePath(path, true);
        foreach (string directory in new[] { owned, basePath, path })
        {
            if (!Directory.Exists(directory))
            {
                if (!create) return null;
                Directory.CreateDirectory(directory, PrivateAcl());
            }
            InstallerPolicy.ValidateCanonicalFilePath(directory, true);
            VerifyPrivateAcl(Directory.GetAccessControl(directory,
                AccessControlSections.Access | AccessControlSections.Owner), true);
        }
        foreach (string nested in Directory.GetDirectories(path))
            throw new InvalidDataException("Unexpected setup journal subdirectory: " + Path.GetFileName(nested));
        foreach (string file in Directory.GetFiles(path))
        {
            string name = Path.GetFileName(file);
            if (name != "probe.journal" && name != "probe.journal.new" && name != "probe.journal.prior" &&
                name != "probe.lock" && !name.StartsWith("probe.journal.interrupted-", StringComparison.Ordinal))
                throw new InvalidDataException("Unexpected setup journal file: " + name);
            InstallerPolicy.ValidateCanonicalFilePath(file);
            VerifyPrivateAcl(File.GetAccessControl(file, AccessControlSections.Access | AccessControlSections.Owner), false);
        }
        return path;
    }
}

internal static class SetupHelperProgram
{
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint pid);
    private static string RequireHex(string value, int length)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(value ?? "", "\\A[0-9a-fA-F]{" + length + "}\\z"))
            throw new InvalidDataException("Setup launch token is malformed.");
        return value.ToLowerInvariant();
    }
    internal static int Main(string[] args)
    {
        try
        {
            if (args.Length != 6 || args[0] != "-setup-helper") return 2;
            string pipeName = "ChildStream-Setup-" + RequireHex(args[1], 32);
            int parentPid, parentSession;
            if (!Int32.TryParse(args[2], out parentPid) || parentPid <= 0 ||
                !Int32.TryParse(args[4], out parentSession) || parentSession <= 0)
                throw new InvalidDataException("Setup parent identity is invalid.");
            string requesterSid = new SecurityIdentifier(args[3]).Value;
            string expectedParentHash = RequireHex(args[5], 64);
            SetupPeerPolicy.RequireElevatedConsole(new WindowsRuntimeTokenReader().Read(),
                new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),
                Process.GetCurrentProcess().SessionId, parentSession, WTSGetActiveConsoleSessionId());
            string appPath = SetupInstallTrust.RequireOwnedPath("ChildStream.exe");
            string ownPath = SetupInstallTrust.RequireOwnedPath("ChildStreamSetup.exe");
            if (!String.Equals(Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName), ownPath,
                StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Setup helper image changed.");
            string script = SetupInstallTrust.RequireOwnedPath("feasibility-inventory.ps1");
            var parent = new WindowsProductProcessHost().Read(parentPid);
            var token = WindowsProcessToken.Read(parentPid);
            SetupPeerPolicy.RequireRequester(parent, token, parentPid, parentSession, requesterSid,
                appPath, expectedParentHash);
            if (!String.Equals(SetupInstallTrust.Hash(appPath), expectedParentHash, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Protected application bytes changed before helper authentication.");
            using (var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                pipe.Connect(30000);
                uint serverPid;
                if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out serverPid) || serverPid != parentPid)
                    throw new UnauthorizedAccessException("Setup pipe server is not the requesting application.");
                using (var bounded = new BoundedPipe(pipe, 30000))
                {
                SetupRequest request = SetupWire.ReadRequest(bounded);
                bool approved = request.Operation == SetupOperation.PlanConnected ||
                    request.Operation == SetupOperation.ReadJournal ||
                    request.Operation == SetupOperation.PlanLan ||
                    request.Operation == SetupOperation.ReadLanJournal ||
                    MessageBox.Show("Approve this exact ChildStream operation?\n" + request.Operation +
                        "\nPlan SHA-256: " + request.ApprovedPlanHash + "\nRequesting SID: " + requesterSid +
                        (String.IsNullOrEmpty(request.LanAddress) ? "" : "\nSelected LAN IPv4: " + request.LanAddress) +
                        "\nAdministrator SID: " + WindowsIdentity.GetCurrent().User.Value +
                        (request.Operation == SetupOperation.ApplyLan || request.Operation == SetupOperation.RecoverLan
                            ? "\nThis changes only the two exact ChildStream-owned LAN firewall rules; no RDP or sign-out change."
                            : "\nNo sign-out or RDP/firewall change is part of this request."),
                        "ChildStream privileged setup", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
                try
                {
                    if (!approved) throw new OperationCanceledException("Privileged operation was not approved.");
                    parent = new WindowsProductProcessHost().Read(parentPid);
                    token = WindowsProcessToken.Read(parentPid);
                    SetupPeerPolicy.RequireRequester(parent, token, parentPid, parentSession, requesterSid,
                        appPath, expectedParentHash);
                    // A read-only plan creates no journal. All later transitions use
                    // the same private, durable requester-scoped probe journal.
                    bool lanOperation = request.Operation == SetupOperation.PlanLan ||
                        request.Operation == SetupOperation.ApplyLan ||
                        request.Operation == SetupOperation.RecoverLan ||
                        request.Operation == SetupOperation.ReadLanJournal;
                    string dir = request.Operation == SetupOperation.PlanConnected || lanOperation ? null :
                        SetupPrivateJournal.PathFor(requesterSid, request.Operation == SetupOperation.BeginConnected);
                    var store = dir == null ? null : new FileProbeStore(Path.Combine(dir, "probe.journal"));
                    var host = new WindowsFeasibilityHost(new ScriptProbeInventory(script), new ProbeNative(),
                        null, SetupInstallTrust.AccountHash(requesterSid));
                    var probe = new FeasibilityProbe(host, store, dir == null ? null :
                        new FileTransactionOwnership(Path.Combine(dir, "probe.lock")));
                    string installedRoot = Path.Combine(Environment.GetFolderPath(
                        Environment.SpecialFolder.ProgramFiles), "ChildStream");
                    string lanExecutable = request.Operation == SetupOperation.PlanLan ||
                        request.Operation == SetupOperation.ApplyLan ? SetupInstallTrust.RequireOwnedSunshine() :
                        Path.Combine(installedRoot, "versions", SunshineReleasePin.Version, "sunshine.exe");
                    if (request.Operation == SetupOperation.RecoverLan ||
                        request.Operation == SetupOperation.ReadLanJournal)
                        SetupInstallTrust.VerifyProtectedAcl(File.GetAccessControl(
                            Path.Combine(installedRoot, "lan-firewall.journal")));
                    LanFirewallTransaction lan = lanOperation ?
                        new LanFirewallTransaction(new WindowsLanFirewallHost(), installedRoot,
                            lanExecutable, new SunshinePortFamily(48089)) : null;
                    string result = new SetupTransaction(probe, store, lan).Execute(request, approved);
                    bounded.ResetDeadline(30000);
                    SetupWire.SendResult(bounded, true, result);
                }
                catch (Exception ex) { bounded.ResetDeadline(30000);
                    SetupWire.SendResult(bounded, false, ex.GetType().Name + ": " + ex.Message); }
                }
            }
            return 0;
        }
        catch { return 3; }
    }
}

internal interface ISetupElevationLauncher { Process Launch(string path, string arguments); }
internal sealed class WindowsSetupElevationLauncher : ISetupElevationLauncher
{
    public Process Launch(string path, string arguments)
    {
        return Process.Start(new ProcessStartInfo(path, arguments) {
            UseShellExecute = true, Verb = "runas", WorkingDirectory = Path.GetDirectoryName(path) });
    }
}

internal sealed class WindowsSetupGateway
{
    private readonly ISetupElevationLauncher elevation;
    internal WindowsSetupGateway(ISetupElevationLauncher elevation) { this.elevation = elevation; }
    internal string Execute(SetupRequest request)
    {
        request.Validate();
        if (new WindowsRuntimeTokenReader().Read() != RuntimeTokenStatus.Limited ||
            (uint)Process.GetCurrentProcess().SessionId != WTSGetActiveConsoleSessionId())
            throw new UnauthorizedAccessException("Only the limited physical-console application may request setup.");
        string app = SetupInstallTrust.RequireOwnedPath("ChildStream.exe");
        string helper = SetupInstallTrust.RequireOwnedPath("ChildStreamSetup.exe");
        if (!String.Equals(Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName), app,
            StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Requesting app is not the protected installation.");
        byte[] nonce = new byte[16]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(nonce);
        string name = BitConverter.ToString(nonce).Replace("-", "").ToLowerInvariant();
        int pid = Process.GetCurrentProcess().Id, session = Process.GetCurrentProcess().SessionId;
        string sid = WindowsIdentity.GetCurrent().User.Value, appHash = SetupInstallTrust.Hash(app),
            helperHash = SetupInstallTrust.Hash(helper);
        var security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
        foreach (string allow in new[] { sid, "S-1-5-32-544", "S-1-5-18" })
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(allow),
                PipeAccessRights.ReadWrite, AccessControlType.Allow));
        using (var pipe = new NamedPipeServerStream("ChildStream-Setup-" + name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security))
        {
            string arguments = "-setup-helper " + name + " " + pid + " " + sid + " " + session + " " + appHash;
            using (Process launched = elevation.Launch(helper, arguments))
            {
                if (launched == null) throw new InvalidOperationException("Setup helper did not start.");
                BoundedPipe.WaitForConnection(pipe, 90000);
                uint clientPid;
                if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out clientPid) || clientPid != launched.Id ||
                    !String.Equals(SetupInstallTrust.Hash(helper), helperHash, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("Setup helper peer or executable changed.");
                var peer = WindowsProcessToken.Read((int)clientPid);
                var image = new WindowsProductProcessHost().Read((int)clientPid);
                SetupPeerPolicy.RequireAuthenticatedHelper(image, peer, launched.Id, session, helper, helperHash);
                using (var bounded = new BoundedPipe(pipe, 240000))
                {
                    SetupWire.SendRequest(bounded, request);
                    // After dispatch, any deadline is an uncertain outcome. The
                    // wrapper closes its pipe on expiry; never retry a write.
                    return SetupWire.ReadResult(bounded);
                }
            }
        }
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint pid);
}
