using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;

// This protocol carries no credential. The nonce is a correlation value, not
// authority to create a Windows session or to bypass the product's live gate.
internal sealed class ChildAgentRequest
{
    internal uint ParentSessionId;
    internal ChildSessionIdentity Child;
    internal string PipeName;
    internal string Nonce;
    internal int ParentPid;
    internal string ParentExecutableSha256;
    internal string RequesterSid;

    internal string Encode()
    {
        Validate();
        using (var bytes = new MemoryStream())
        using (var writer = new BinaryWriter(bytes, Encoding.UTF8))
        {
            writer.Write(2); writer.Write(ParentSessionId); writer.Write(Child.SessionId);
            writer.Write(Child.LogonTime); writer.Write(PipeName); writer.Write(Nonce);
            writer.Write(ParentPid); writer.Write(ParentExecutableSha256); writer.Write(RequesterSid);
            writer.Flush();
            return Convert.ToBase64String(bytes.ToArray());
        }
    }

    internal static ChildAgentRequest Decode(string value)
    {
        if (String.IsNullOrEmpty(value) || value.Length > 1024)
            throw new InvalidDataException("Child agent request is missing or too large.");
        byte[] bytes = Convert.FromBase64String(value);
        using (var reader = new BinaryReader(new MemoryStream(bytes), Encoding.UTF8))
        {
            if (reader.ReadInt32() != 2) throw new InvalidDataException("Unsupported child agent request version.");
            var request = new ChildAgentRequest { ParentSessionId = reader.ReadUInt32(),
                Child = new ChildSessionIdentity(reader.ReadUInt32(), reader.ReadInt64()),
                PipeName = reader.ReadString(), Nonce = reader.ReadString(),
                ParentPid = reader.ReadInt32(), ParentExecutableSha256 = reader.ReadString(),
                RequesterSid = reader.ReadString() };
            if (reader.BaseStream.Position != reader.BaseStream.Length)
                throw new InvalidDataException("Child agent request has trailing data.");
            request.Validate();
            return request;
        }
    }

    internal void Validate()
    {
        if (ParentSessionId == 0 || Child.SessionId == 0 || Child.SessionId == uint.MaxValue ||
            ParentSessionId == Child.SessionId || Child.LogonTime <= 0 ||
            String.IsNullOrEmpty(PipeName) || PipeName.Length > 120 ||
            !System.Text.RegularExpressions.Regex.IsMatch(PipeName, "\\AChildStream-[0-9a-f]{32}\\z") ||
            String.IsNullOrEmpty(Nonce) ||
            !System.Text.RegularExpressions.Regex.IsMatch(Nonce, "\\A[0-9a-f]{64}\\z") ||
            ParentPid <= 0 || String.IsNullOrEmpty(ParentExecutableSha256) ||
            !System.Text.RegularExpressions.Regex.IsMatch(ParentExecutableSha256, "\\A[0-9a-fA-F]{64}\\z") ||
            String.IsNullOrEmpty(RequesterSid) || !System.Text.RegularExpressions.Regex.IsMatch(
                RequesterSid, "\\AS-1-[0-9-]{5,100}\\z"))
            throw new InvalidDataException("Child agent request has invalid session or correlation identity.");
    }
}

internal sealed class ChildAgentHello
{
    internal string Nonce;
    internal int Pid;
    internal ChildSessionIdentity Child;
}

internal interface IChildBootstrapHost
{
    ChildSessionIdentity? ReadAssociatedChild();
    long? ReadLogonTime(uint sessionId);
    void RequestAgentInSession(ChildAgentRequest request);
    ChildAgentHello WaitForAgent(ChildAgentRequest request, int timeoutMs);
    ProductProcessIdentity ReadAgent(int pid);
    void RequestAgentExit(int pid);
}

internal enum ChildAgentStage { Idle, StartRequested, Ready, ExitRequested, Ended, Uncertain }

internal sealed class ChildAgentController
{
    private readonly IChildBootstrapHost host;
    private readonly uint parentSessionId;
    private readonly ChildSessionIdentity child;
    private readonly string executable;
    private readonly string digest;
    private ProductProcessIdentity agent;
    internal ChildAgentStage Stage { get; private set; }
    internal string Failure { get; private set; }

    internal ChildAgentController(IChildBootstrapHost host, uint parentSessionId,
        ChildSessionIdentity child, string executable, string digest)
    {
        if (host == null || parentSessionId == 0 || parentSessionId == child.SessionId ||
            child.SessionId == 0 || child.LogonTime <= 0 ||
            String.IsNullOrWhiteSpace(executable) || !Path.IsPathRooted(executable) ||
            String.IsNullOrEmpty(digest) || !System.Text.RegularExpressions.Regex.IsMatch(digest, "\\A[0-9a-fA-F]{64}\\z"))
            throw new InvalidDataException("Exact child and pinned agent executable are required.");
        this.host = host; this.parentSessionId = parentSessionId; this.child = child;
        this.executable = Path.GetFullPath(executable); this.digest = digest;
    }

    private void RequireChild()
    {
        ChildSessionIdentity? associated = host.ReadAssociatedChild();
        if (!associated.HasValue || !associated.Value.Equals(child) ||
            host.ReadLogonTime(child.SessionId) != child.LogonTime)
            throw new InvalidOperationException("Parent-associated child logon generation changed.");
    }

    private bool Same(ProductProcessIdentity value)
    {
        return value != null && agent != null && value.Pid == agent.Pid &&
            value.SessionId == (int)child.SessionId && value.StartTimeUtcTicks == agent.StartTimeUtcTicks &&
            String.Equals(Path.GetFullPath(value.ExecutablePath), executable, StringComparison.OrdinalIgnoreCase) &&
            String.Equals(value.ExecutableSha256, digest, StringComparison.OrdinalIgnoreCase);
    }

    internal void Start(ChildAgentRequest request)
    {
        if (Stage != ChildAgentStage.Idle) throw new InvalidOperationException("Agent start is already resolved or uncertain.");
        request.Validate();
        if (request.ParentSessionId != parentSessionId || !request.Child.Equals(child))
            throw new InvalidOperationException("Agent request targets another parent or child.");
        RequireChild();
        Stage = ChildAgentStage.StartRequested;
        try
        {
            host.RequestAgentInSession(request);
            ChildAgentHello hello = host.WaitForAgent(request, 15000);
            RequireChild();
            if (hello == null || !hello.Child.Equals(child) || hello.Nonce != request.Nonce || hello.Pid <= 0)
                throw new InvalidOperationException("Child agent handshake did not match the requested session.");
            agent = host.ReadAgent(hello.Pid);
            if (agent == null || agent.Pid != hello.Pid || agent.SessionId != (int)child.SessionId ||
                agent.StartTimeUtcTicks <= 0 ||
                !String.Equals(Path.GetFullPath(agent.ExecutablePath), executable, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(agent.ExecutableSha256, digest, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Child agent process identity is not exact.");
            Stage = ChildAgentStage.Ready;
        }
        catch (Exception ex) { Failure = ex.Message; Stage = ChildAgentStage.Uncertain; throw; }
    }

    internal bool Reconcile()
    {
        if (Stage != ChildAgentStage.Ready || agent == null) return false;
        try
        {
            RequireChild();
            if (Same(host.ReadAgent(agent.Pid))) return true;
            Failure = "Child agent changed or exited; no runtime operation is allowed.";
        }
        catch (Exception ex) { Failure = ex.Message; }
        Stage = ChildAgentStage.Uncertain;
        return false;
    }

    internal string Execute(ChildAgentOperation operation, string payload)
    {
        if (!Reconcile()) throw new InvalidOperationException("A verified child agent is required for runtime operation.");
        var commands = host as IChildAgentCommandHost;
        if (commands == null) throw new InvalidOperationException("This host has no authenticated child command channel.");
        try { return commands.Exchange(operation, payload, operation == ChildAgentOperation.PairingPost ? 30000 : 15000); }
        catch (ChildAgentCommandRejectedException) { throw; }
        catch (Exception ex) { Failure = ex.Message; Stage = ChildAgentStage.Uncertain; throw; }
    }

    internal void Stop()
    {
        if (!Reconcile()) throw new InvalidOperationException("Exact running child agent is required for stop.");
        Stage = ChildAgentStage.ExitRequested;
        try
        {
            host.RequestAgentExit(agent.Pid);
            RequireChild();
            if (host.ReadAgent(agent.Pid) != null)
                throw new InvalidOperationException("Child agent exit was not verified.");
            Stage = ChildAgentStage.Ended;
        }
        catch (Exception ex) { Failure = ex.Message; Stage = ChildAgentStage.Uncertain; throw; }
    }
}

internal static class WindowsChildAgentEntry
{
    internal static int Run(string encoded)
    {
        ChildAgentRequest request;
        try { request = ChildAgentRequest.Decode(encoded); }
        catch { return 2; }
        var process = new WindowsProductProcessHost();
        if (process.CurrentSessionId != (int)request.Child.SessionId ||
            process.ReadSessionLogonTime((int)request.Child.SessionId) != request.Child.LogonTime ||
            new WindowsRuntimeTokenReader().Read() != RuntimeTokenStatus.Limited ||
            !String.Equals(WindowsIdentity.GetCurrent().User.Value, request.RequesterSid, StringComparison.Ordinal))
            return 3;
        try
        {
            using (var pipe = new NamedPipeClientStream(".", request.PipeName, PipeDirection.InOut,
                PipeOptions.None, TokenImpersonationLevel.Identification))
            {
                pipe.Connect(10000);
                uint serverPid;
                if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out serverPid) ||
                    serverPid != (uint)request.ParentPid) return 4;
                ProcessTokenObservation parentToken = WindowsProcessToken.Read(request.ParentPid);
                ProductProcessIdentity parentProcess = process.Read(request.ParentPid);
                if (parentToken.Elevation != RuntimeTokenStatus.Limited ||
                    !String.Equals(parentToken.Sid, request.RequesterSid, StringComparison.Ordinal) ||
                    parentProcess == null || parentProcess.SessionId != (int)request.ParentSessionId ||
                    !String.Equals(parentProcess.ExecutableSha256, request.ParentExecutableSha256, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(Path.GetFullPath(parentProcess.ExecutablePath),
                        Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName), StringComparison.OrdinalIgnoreCase))
                    return 4;
                using (var writer = new BinaryWriter(pipe, Encoding.UTF8, true))
                {
                    writer.Write(0x43534131); writer.Write(Encoding.ASCII.GetBytes(request.Nonce));
                    writer.Write(Process.GetCurrentProcess().Id); writer.Write(request.Child.SessionId);
                    writer.Write(request.Child.LogonTime); writer.Flush();
                    if (process.CurrentSessionId != (int)request.Child.SessionId ||
                        process.ReadSessionLogonTime((int)request.Child.SessionId) != request.Child.LogonTime)
                        return 4;
                    using (var operations = new WindowsChildAgentOperations(request))
                    using (var lifetime = new Timer(state => { try { pipe.Dispose(); } catch { } },
                        null, TimeSpan.FromHours(8), System.Threading.Timeout.InfiniteTimeSpan))
                    {
                        Func<bool> stillOwned = () =>
                        {
                            ProductProcessIdentity currentParent = process.Read(request.ParentPid);
                            ProcessTokenObservation currentToken = WindowsProcessToken.Read(request.ParentPid);
                            return process.CurrentSessionId == (int)request.Child.SessionId &&
                                process.ReadSessionLogonTime((int)request.Child.SessionId) == request.Child.LogonTime &&
                                new WindowsRuntimeTokenReader().Read() == RuntimeTokenStatus.Limited &&
                                currentParent != null && currentParent.SessionId == (int)request.ParentSessionId &&
                                currentParent.StartTimeUtcTicks == parentProcess.StartTimeUtcTicks &&
                                String.Equals(currentParent.ExecutableSha256, request.ParentExecutableSha256,
                                    StringComparison.OrdinalIgnoreCase) &&
                                currentToken.Elevation == RuntimeTokenStatus.Limited &&
                                currentToken.Sid == request.RequesterSid;
                        };
                        while (ChildAgentWire.ServeOne(pipe, operations, stillOwned)) { }
                        return 0;
                    }
                }
            }
        }
        catch { return 6; }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
        out uint serverPid);
}

// Uses only an already registered, exact ChildStream interactive-token task.
// Registration/removal belong to the separately approved installer journal.
// RunEx is a process-start request and never counts as a successful bootstrap
// until the pipe peer, WTS generation and executable identity are rechecked.
internal sealed class WindowsChildTaskBootstrapHost : IChildBootstrapHost, IChildAgentCommandHost, IDisposable
{
    private readonly IChildSessionApi sessions;
    private readonly WindowsProductProcessHost processes = new WindowsProductProcessHost();
    private readonly string executable;
    private readonly string digest;
    private NamedPipeServerStream pipe;
    private int peerPid;
    private long peerStartTime;
    private ChildSessionIdentity? peerChild;
    private string peerSid;

    internal WindowsChildTaskBootstrapHost(IChildSessionApi sessions, string executable, string digest)
    {
        if (sessions == null || String.IsNullOrEmpty(executable) || !Path.IsPathRooted(executable) ||
            String.IsNullOrEmpty(digest) || !System.Text.RegularExpressions.Regex.IsMatch(digest, "\\A[0-9a-fA-F]{64}\\z"))
            throw new InvalidDataException("Exact owned task executable and digest are required.");
        this.sessions = sessions; this.executable = Path.GetFullPath(executable); this.digest = digest;
    }

    public ChildSessionIdentity? ReadAssociatedChild() { return sessions.ReadAssociatedChild(); }
    public long? ReadLogonTime(uint sessionId) { return processes.ReadSessionLogonTime((int)sessionId); }
    public ProductProcessIdentity ReadAgent(int pid) { return processes.Read(pid); }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
        out uint clientPid);

    private void CheckTask(dynamic task)
    {
        if (!(bool)task.Enabled) throw new InvalidOperationException("ChildStream task is disabled.");
        dynamic definition = task.Definition;
        if ((int)definition.Triggers.Count != 0 || (int)definition.Actions.Count != 1 ||
            !(bool)definition.Settings.AllowDemandStart || !(bool)definition.Settings.Enabled ||
            (int)definition.Principal.LogonType != 3 || (int)definition.Principal.RunLevel != 0)
            throw new InvalidOperationException("ChildStream task is not a demand-only, limited interactive-token task.");
        dynamic action = definition.Actions.Item(1);
        if ((int)action.Type != 0 ||
            !String.Equals(Path.GetFullPath((string)action.Path), executable, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals((string)action.Arguments, "-child-agent $(Arg0)", StringComparison.Ordinal))
            throw new InvalidOperationException("ChildStream task action changed.");
        string principal = (string)definition.Principal.UserId;
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!String.Equals(principal, identity.Name, StringComparison.OrdinalIgnoreCase) &&
            !String.Equals(principal, identity.User.Value, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ChildStream task principal changed.");
        using (var stream = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var sha = SHA256.Create())
        {
            string actual = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
            if (!String.Equals(actual, digest, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("ChildStream task executable digest changed.");
        }
    }

    public void RequestAgentInSession(ChildAgentRequest request)
    {
        request.Validate();
        if (pipe != null || processes.CurrentSessionId != (int)request.ParentSessionId ||
            Process.GetCurrentProcess().Id != request.ParentPid ||
            new WindowsRuntimeTokenReader().Read() != RuntimeTokenStatus.Limited ||
            !String.Equals(WindowsIdentity.GetCurrent().User.Value, request.RequesterSid, StringComparison.Ordinal))
            throw new InvalidOperationException("Only the exact parent can request one child agent.");
        ProductProcessIdentity parent = processes.Read(request.ParentPid);
        if (parent == null || parent.SessionId != (int)request.ParentSessionId ||
            !String.Equals(parent.ExecutableSha256, request.ParentExecutableSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Parent executable changed before child-agent request.");
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        pipe = new NamedPipeServerStream(request.PipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
        try
        {
            Type serviceType = Type.GetTypeFromProgID("Schedule.Service");
            if (serviceType == null) throw new InvalidOperationException("Task Scheduler COM is unavailable.");
            dynamic service = Activator.CreateInstance(serviceType);
            service.Connect();
            dynamic folder = service.GetFolder("\\");
            dynamic task = folder.GetTask(ChildAgentTaskPolicy.Name(request.RequesterSid));
            CheckTask(task);
            task.RunEx(request.Encode(), 4, (int)request.Child.SessionId, null);
        }
        catch { Dispose(); throw; }
    }

    public ChildAgentHello WaitForAgent(ChildAgentRequest request, int timeoutMs)
    {
        if (pipe == null || timeoutMs < 1000 || timeoutMs > 30000)
            throw new InvalidOperationException("No bounded child-agent launch is pending.");
        IAsyncResult pending = pipe.BeginWaitForConnection(null, null);
        if (!pending.AsyncWaitHandle.WaitOne(timeoutMs))
            throw new TimeoutException("Task Scheduler did not produce a verified child agent.");
        pipe.EndWaitForConnection(pending);
        uint pid;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid) || pid == 0 || pid > int.MaxValue)
            throw new InvalidOperationException("Child agent pipe peer PID is unavailable.");
        ProcessTokenObservation peerToken = WindowsProcessToken.Read((int)pid);
        if (peerToken.Elevation != RuntimeTokenStatus.Limited ||
            !String.Equals(peerToken.Sid, request.RequesterSid, StringComparison.Ordinal))
            throw new InvalidOperationException("Child agent pipe peer has the wrong user or elevated token.");
        Task<ChildAgentHello> read = Task.Run(() =>
        {
            using (var reader = new BinaryReader(pipe, Encoding.UTF8, true))
            {
                if (reader.ReadInt32() != 0x43534131)
                    throw new InvalidDataException("Child agent handshake version changed.");
                byte[] nonce = reader.ReadBytes(64);
                if (nonce.Length != 64) throw new EndOfStreamException("Child agent nonce is incomplete.");
                var hello = new ChildAgentHello { Nonce = Encoding.ASCII.GetString(nonce), Pid = reader.ReadInt32(),
                    Child = new ChildSessionIdentity(reader.ReadUInt32(), reader.ReadInt64()) };
                if (hello.Pid != (int)pid || hello.Nonce != request.Nonce || !hello.Child.Equals(request.Child))
                    throw new InvalidOperationException("Child agent pipe peer identity changed.");
                return hello;
            }
        });
        if (!read.Wait(timeoutMs))
        { Dispose(); throw new TimeoutException("Child agent handshake did not complete within the time limit."); }
        ChildAgentHello verified = read.GetAwaiter().GetResult();
        ProductProcessIdentity image = processes.Read(verified.Pid);
        ChildSessionIdentity? associated = sessions.ReadAssociatedChild();
        if (image == null || image.SessionId != (int)request.Child.SessionId ||
            image.StartTimeUtcTicks <= 0 ||
            !String.Equals(Path.GetFullPath(image.ExecutablePath), executable, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(image.ExecutableSha256, digest, StringComparison.OrdinalIgnoreCase) ||
            processes.ReadSessionLogonTime((int)request.Child.SessionId) != request.Child.LogonTime ||
            !associated.HasValue || !request.Child.Equals(associated.Value))
            throw new InvalidOperationException("Child agent process, executable or session generation changed during handshake.");
        peerPid = verified.Pid;
        peerStartTime = image.StartTimeUtcTicks;
        peerChild = request.Child;
        peerSid = request.RequesterSid;
        return verified;
    }

    public void RequestAgentExit(int pid)
    {
        if (pipe == null || !pipe.IsConnected || pid != peerPid || pid <= 0)
            throw new InvalidOperationException("Exact connected child agent is required for shutdown.");
        string status = Exchange(ChildAgentOperation.Status, "", 5000);
        var state = new System.Web.Script.Serialization.JavaScriptSerializer().DeserializeObject(status)
            as System.Collections.Generic.Dictionary<string, object>;
        if (state == null || !state.ContainsKey("stage") || !state.ContainsKey("steamStage") ||
            Convert.ToString(state["stage"]) != "NoSunshine" ||
            (Convert.ToString(state["steamStage"]) != "NotStarted" &&
             Convert.ToString(state["steamStage"]) != "Ended"))
            throw new InvalidOperationException("Exact owned Sunshine and Steam must be stopped before child agent exit.");
        pipe.WriteByte(0x53); pipe.Flush();
        for (int i = 0; i < 50; i++)
        {
            if (processes.Read(pid) == null) { Dispose(); return; }
            Thread.Sleep(100);
        }
        throw new TimeoutException("Child agent did not exit after the bounded shutdown request.");
    }

    public string Exchange(ChildAgentOperation operation, string payload, int timeoutMs)
    {
        if (pipe == null || !pipe.IsConnected || peerPid <= 0 || !peerChild.HasValue ||
            timeoutMs < 1000 || timeoutMs > 30000)
            throw new InvalidOperationException("No verified child agent channel exists.");
        ProductProcessIdentity current = processes.Read(peerPid);
        ProcessTokenObservation peer = WindowsProcessToken.Read(peerPid);
        ChildSessionIdentity? associated = sessions.ReadAssociatedChild();
        if (current == null || current.SessionId != (int)peerChild.Value.SessionId ||
            current.StartTimeUtcTicks != peerStartTime ||
            processes.ReadSessionLogonTime((int)peerChild.Value.SessionId) != peerChild.Value.LogonTime ||
            !associated.HasValue || !peerChild.Value.Equals(associated.Value) ||
            !String.Equals(Path.GetFullPath(current.ExecutablePath), executable, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(current.ExecutableSha256, digest, StringComparison.OrdinalIgnoreCase) ||
            peer.Elevation != RuntimeTokenStatus.Limited ||
            !String.Equals(peer.Sid, peerSid, StringComparison.Ordinal) ||
            processes.CurrentSessionId == (int)peerChild.Value.SessionId ||
            !String.Equals(WindowsIdentity.GetCurrent().User.Value, peerSid, StringComparison.Ordinal))
            throw new InvalidOperationException("Child agent channel peer changed.");
        ChildAgentWire.WriteRequest(pipe, operation, payload);
        Task<string> read = Task.Run(() => ChildAgentWire.ReadResponse(pipe));
        if (!read.Wait(timeoutMs)) { Dispose(); throw new TimeoutException("Child agent operation outcome is unknown."); }
        return read.GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        if (pipe != null) { pipe.Dispose(); pipe = null; }
        peerPid = 0; peerStartTime = 0; peerChild = null; peerSid = null;
    }
}
