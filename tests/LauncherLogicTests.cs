using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

static class LauncherLogicTests
{
    static int cases;
    sealed class FakeSessionApi : IChildSessionApi
    {
        public uint CurrentSessionId { get; set; }
        public ChildSessionIdentity? Child;
        public bool FailRead, FailLogoff, ThrowLogoff;
        public int LogoffCalls;
        public Action DuringLogoff;
        public FakeSessionApi() { CurrentSessionId = 1; }
        public ChildSessionIdentity? ReadAssociatedChild()
        {
            if (FailRead) throw new IOException("synthetic query failure");
            return Child;
        }
        public bool Logoff(uint sessionId)
        {
            LogoffCalls++;
            if (DuringLogoff != null) DuringLogoff();
            if (ThrowLogoff) throw new IOException("synthetic ambiguous logoff");
            if (FailLogoff) return false;
            Child = null;
            return true;
        }
    }
    sealed class FakeFiles : ILegacyFileAccess
    {
        public bool Present, Inaccessible, DeleteFails, Reparse;
        public int Deletes;
        public FileAttributes GetAttributes(string path)
        {
            if (Inaccessible) throw new UnauthorizedAccessException();
            if (!Present) throw new FileNotFoundException();
            return Reparse ? FileAttributes.ReparsePoint : FileAttributes.Normal;
        }
        public void Delete(string path)
        {
            Deletes++;
            if (DeleteFails) throw new IOException("synthetic delete failure");
            Present = false;
        }
    }
    static void Expect(bool condition, string name)
    {
        cases++;
        if (!condition) throw new Exception("Failed: " + name);
    }
    static void Display(string input, bool valid)
    {
        try
        {
            MethodInfo method = typeof(Program).GetMethod("ParseDisplayConfig", BindingFlags.NonPublic | BindingFlags.Static);
            int[] result = (int[])method.Invoke(null, new object[] { input });
            Expect(valid && result[0] >= 640 && result[1] >= 480, "display " + input);
        }
        catch (TargetInvocationException ex)
        {
            Expect(!valid && ex.InnerException is FormatException, "display rejects " + input);
        }
    }
    static ChildSessionLifecycle Connected(FakeSessionApi api, ISignOutIntentStore store = null)
    {
        var lifecycle = new ChildSessionLifecycle(api, 1, store);
        Expect(lifecycle.TryBeginConnection() && lifecycle.State == ChildLifecycleState.Connecting, "initial connect");
        api.Child = new ChildSessionIdentity(7, 100);
        Expect(lifecycle.ObserveConnected() && lifecycle.State == ChildLifecycleState.Connected, "child established");
        return lifecycle;
    }
    sealed class ThrowingIntent : ISignOutIntentStore
    {
        public bool HasUnresolvedIntent(uint parent) { return false; }
        public void RecordIntent(uint parent, ChildSessionIdentity child) { throw new IOException("Cannot persist intent"); }
        public void ResolveIntent(uint parent) { }
    }
    static void SignOutGuardTests()
    {
        string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session-guard-tests");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "signout-1.intent");
        if (File.Exists(path)) File.Delete(path);
        var store = new FileSignOutIntentStore(dir);
        var api = new FakeSessionApi { Child = new ChildSessionIdentity(7, 100) };
        var newProcess = new ChildSessionLifecycle(api, 1, store);
        Expect(!newProcess.TryBeginConnection() && newProcess.State == ChildLifecycleState.Error,
            "new process refuses an existing parent-associated child");
        api.Child = null;
        var connected = Connected(api, store); api.FailLogoff = true;
        Expect(connected.SignOut() == SignOutResult.OutcomeUnknown && store.HasUnresolvedIntent(1),
            "ambiguous signout persists intent");
        api.Child = null;
        newProcess = new ChildSessionLifecycle(api, 1, new FileSignOutIntentStore(dir));
        Expect(!newProcess.TryBeginConnection() && newProcess.State == ChildLifecycleState.Error,
            "restart refuses unresolved signout despite absent child");
        Expect(store.ReconcileAbsentChild(api, 1) && !store.HasUnresolvedIntent(1),
            "explicit absence reconciliation clears only intent");
        Expect(new ChildSessionLifecycle(api, 1, store).TryBeginConnection(), "fresh connection after explicit reconciliation");
        api.FailLogoff = false;
        connected = Connected(api, store);
        Expect(connected.SignOut() == SignOutResult.Complete && !store.HasUnresolvedIntent(1),
            "verified successful signout clears intent");
        api = new FakeSessionApi(); connected = Connected(api, new ThrowingIntent());
        Expect(connected.SignOut() == SignOutResult.PersistenceFailed && api.LogoffCalls == 0,
            "intent persistence failure prevents logoff");
        Expect(!connected.TryBeginConnection() && connected.State == ChildLifecycleState.Error,
            "persistence failure leaves connection blocked");
        File.WriteAllBytes(path, new byte[] { 0, 1 });
        Expect(!new ChildSessionLifecycle(new FakeSessionApi(), 1, store).TryBeginConnection(),
            "malformed persistent intent fails closed");
        File.Delete(path);
        api = new FakeSessionApi();
        var racing = new ChildSessionLifecycle(api, 1);
        Expect(racing.TryBeginConnection(), "initial check sees no child");
        api.Child = new ChildSessionIdentity(8, 200);
        Expect(!racing.CheckConnectionPreflight() && racing.State == ChildLifecycleState.Error,
            "child appearing before ActiveX Connect blocks connection");
    }
    static void LifecycleTests()
    {
        var api = new FakeSessionApi();
        var lifecycle = Connected(api);
        lifecycle.ObserveViewerDisconnected();
        Expect(lifecycle.State == ChildLifecycleState.ViewerDisconnected, "viewer disconnect keeps child");
        Expect(lifecycle.TryBeginConnection() && lifecycle.State == ChildLifecycleState.Reconnecting, "manual or automatic reconnect");
        Expect(lifecycle.ObserveConnected() && lifecycle.State == ChildLifecycleState.Connected, "successful reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api);
        lifecycle.ObserveViewerDisconnected(); api.Child = new ChildSessionIdentity(8, 100);
        Expect(!lifecycle.TryBeginConnection() && lifecycle.State == ChildLifecycleState.Error, "changed child blocks reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api);
        lifecycle.ObserveViewerDisconnected(); api.Child = new ChildSessionIdentity(7, 200);
        Expect(!lifecycle.TryBeginConnection() && lifecycle.State == ChildLifecycleState.Error, "reused ID blocks reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api);
        lifecycle.ObserveViewerDisconnected(); api.FailRead = true;
        Expect(!lifecycle.TryBeginConnection() && lifecycle.State == ChildLifecycleState.Error, "query failure blocks reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api);
        var pending = lifecycle;
        api.DuringLogoff = () => Expect(pending.State == ChildLifecycleState.SignOutOutcomeUnknown &&
            !pending.TryBeginConnection(), "pending signout blocks reentrant reconnect");
        Expect(lifecycle.SignOut() == SignOutResult.Complete && lifecycle.State == ChildLifecycleState.Terminated, "intentional signout");
        Expect(api.LogoffCalls == 1 && !lifecycle.TryBeginConnection(), "terminal blocks reconnect");
        Expect(lifecycle.SignOut() == SignOutResult.Denied && api.LogoffCalls == 1, "repeated signout blocked");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.FailLogoff = true;
        Expect(lifecycle.SignOut() == SignOutResult.OutcomeUnknown && lifecycle.State == ChildLifecycleState.SignOutOutcomeUnknown, "failed logoff unknown");
        Expect(!lifecycle.TryBeginConnection() && api.LogoffCalls == 1, "failed logoff blocks recreation");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.ThrowLogoff = true;
        Expect(lifecycle.SignOut() == SignOutResult.OutcomeUnknown && lifecycle.State == ChildLifecycleState.SignOutOutcomeUnknown, "ambiguous logoff unknown");
        Expect(!lifecycle.TryBeginConnection(), "ambiguous logoff blocks manual reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.Child = null;
        lifecycle.ObserveViewerDisconnected();
        Expect(lifecycle.State == ChildLifecycleState.Terminated && !lifecycle.TryBeginConnection(), "termination during disconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api);
        lifecycle.ObserveViewerDisconnected(); api.Child = null;
        Expect(!lifecycle.TryBeginConnection() && lifecycle.State == ChildLifecycleState.Terminated, "termination before reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.Child = new ChildSessionIdentity(8, 100);
        Expect(lifecycle.SignOut() == SignOutResult.IdentityChanged && api.LogoffCalls == 0, "ID change blocks logoff");
        Expect(lifecycle.State == ChildLifecycleState.Error && !lifecycle.TryBeginConnection(), "changed ID terminal error");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.Child = new ChildSessionIdentity(7, 200);
        Expect(lifecycle.SignOut() == SignOutResult.IdentityChanged && api.LogoffCalls == 0, "reused ID blocks logoff");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.Child = new ChildSessionIdentity(uint.MaxValue, 100);
        Expect(lifecycle.SignOut() == SignOutResult.IdentityChanged && api.LogoffCalls == 0, "invalid ID blocks logoff");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.Child = new ChildSessionIdentity(7, 0);
        Expect(!lifecycle.CheckConnectedIdentity() && lifecycle.State == ChildLifecycleState.Error, "invalid generation rejected");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.CurrentSessionId = 2;
        Expect(lifecycle.SignOut() == SignOutResult.IdentityChanged && api.LogoffCalls == 0, "parent change blocks logoff");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.FailRead = true;
        Expect(lifecycle.SignOut() == SignOutResult.IdentityChanged && api.LogoffCalls == 0, "query failure blocks logoff");

        api = new FakeSessionApi(); lifecycle = Connected(api);
        lifecycle.UnrecoverableError();
        Expect(lifecycle.State == ChildLifecycleState.Error && !lifecycle.TryBeginConnection(), "monitor failure blocks reconnect");

        api = new FakeSessionApi(); lifecycle = Connected(api); api.FailLogoff = true;
        lifecycle.SignOut(); lifecycle.UnrecoverableError();
        Expect(lifecycle.State == ChildLifecycleState.SignOutOutcomeUnknown, "later error cannot clear signout uncertainty");

        api = new FakeSessionApi(); lifecycle = new ChildSessionLifecycle(api, 1);
        Expect(!lifecycle.ObserveConnected() && lifecycle.State == ChildLifecycleState.NoChild, "unexpected connect event rejected");
        Expect(lifecycle.TryBeginConnection(), "initial attempt allowed");
        lifecycle.ConnectionAttemptFailed();
        Expect(lifecycle.State == ChildLifecycleState.Error && !lifecycle.TryBeginConnection(), "ambiguous connect failure blocks retry");
    }
    static void CredentialTests()
    {
        const string exe = @"C:\ChildStream\ChildStream.exe";
        const string credential = @"C:\ChildStream\cred.bin";
        var files = new FakeFiles();
        var cleanup = new LegacyCredentialCleanup(exe, credential, files);
        Expect(cleanup.Inspect() == LegacyCredentialStatus.Absent, "genuinely absent");
        Expect(cleanup.RemoveWithApproval(true) == LegacyCredentialStatus.Absent && files.Deletes == 0, "repeated absent cleanup");
        files.Present = true;
        Expect(cleanup.Inspect() == LegacyCredentialStatus.Present, "present credential");
        Expect(cleanup.RemoveWithApproval(false) == LegacyCredentialStatus.Cancelled && files.Deletes == 0, "approval required");
        files.Inaccessible = true;
        Expect(cleanup.Inspect() == LegacyCredentialStatus.Inaccessible, "inaccessible differs from absent");
        Expect(cleanup.RemoveWithApproval(true) == LegacyCredentialStatus.Inaccessible && files.Deletes == 0, "inaccessible not deleted");
        files.Inaccessible = false; files.DeleteFails = true;
        Expect(cleanup.RemoveWithApproval(true) == LegacyCredentialStatus.Failed, "delete failure reported");
        files.DeleteFails = false;
        Expect(cleanup.RemoveWithApproval(true) == LegacyCredentialStatus.Removed, "removal verified");
        Expect(cleanup.RemoveWithApproval(true) == LegacyCredentialStatus.Absent, "repeated cleanup after removal");
        files.Present = true; files.Reparse = true;
        Expect(cleanup.RemoveWithApproval(true) == LegacyCredentialStatus.OutsideOwnedPath, "reparse target refused");
        var outside = new LegacyCredentialCleanup(exe, @"C:\Other\cred.bin", files);
        Expect(outside.RemoveWithApproval(true) == LegacyCredentialStatus.OutsideOwnedPath, "outside path refused");
        var renamed = new LegacyCredentialCleanup(@"C:\ChildStream\Other.exe", credential, files);
        Expect(renamed.RemoveWithApproval(true) == LegacyCredentialStatus.OutsideOwnedPath, "unowned executable refused");
    }
    public static int Main()
    {
        Type ex = typeof(Program).GetNestedType("WtsInfoEx", BindingFlags.NonPublic);
        Type level1 = typeof(Program).GetNestedType("WtsInfoExLevel1", BindingFlags.NonPublic);
        Expect(ex != null && level1 != null, "WTS information structures present");
        Expect(Marshal.OffsetOf(ex, "Data").ToInt64() == 8, "WTSINFOEX union alignment");
        Expect(Marshal.OffsetOf(level1, "LogonTime").ToInt64() == 160, "WTSINFOEX logon-time layout");
        Expect(new ChildSessionIdentity(7, 100).Equals(new ChildSessionIdentity(7, 100)), "identity exact");
        Expect(!new ChildSessionIdentity(7, 100).Equals(new ChildSessionIdentity(8, 100)), "identity ID differs");
        Expect(!new ChildSessionIdentity(7, 100).Equals(new ChildSessionIdentity(7, 200)), "identity generation differs");
        Expect(!new ChildSessionIdentity(uint.MaxValue, 100).Equals(new ChildSessionIdentity(7, 100)), "invalid sentinel differs");
        Display("1920x1080", true); Display("2800x1272x225", true); Display("-1x1080", false);
        Display("1920x0", false); Display("1920x1080x0", false); Display("1920x1080x225x9", false);
        LifecycleTests(); SignOutGuardTests(); CredentialTests();
        Console.WriteLine(cases + " offline launcher logic cases passed");
        return 0;
    }
}
