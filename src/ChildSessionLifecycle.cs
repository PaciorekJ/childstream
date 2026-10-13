using System;

internal enum ChildLifecycleState
{
    NoChild,
    Connecting,
    Connected,
    ViewerDisconnected,
    Reconnecting,
    SignOutRequested,
    SignOutOutcomeUnknown,
    Terminated,
    Error
}

internal struct ChildSessionIdentity : IEquatable<ChildSessionIdentity>
{
    internal readonly uint SessionId;
    internal readonly long LogonTime;

    internal ChildSessionIdentity(uint sessionId, long logonTime)
    {
        SessionId = sessionId;
        LogonTime = logonTime;
    }

    public bool Equals(ChildSessionIdentity other)
    {
        return SessionId == other.SessionId && LogonTime == other.LogonTime;
    }
}

internal interface IChildSessionApi
{
    uint CurrentSessionId { get; }
    ChildSessionIdentity? ReadAssociatedChild();
    bool Logoff(uint sessionId);
}

internal interface ISignOutIntentStore
{
    bool HasUnresolvedIntent(uint parentSessionId);
    void RecordIntent(uint parentSessionId, ChildSessionIdentity child);
    void ResolveIntent(uint parentSessionId);
}

internal enum SignOutResult
{
    Denied,
    PersistenceFailed,
    IdentityChanged,
    OutcomeUnknown,
    Complete
}

// All connection and destructive-operation entry points use this state machine.
// The Windows adapter supplies a session logon time as a generation check; neither
// that check nor WTSGetChildSessionId makes query + logoff atomic.
internal sealed class ChildSessionLifecycle
{
    private readonly IChildSessionApi api;
    private readonly uint parentSessionId;
    private readonly ISignOutIntentStore intentStore;
    private ChildSessionIdentity? observedChild;

    internal ChildLifecycleState State { get; private set; }
    internal ChildSessionIdentity? ObservedChild { get { return observedChild; } }
    internal string FailureReason { get; private set; }

    internal ChildSessionLifecycle(IChildSessionApi api, uint parentSessionId, ISignOutIntentStore intentStore = null)
    {
        this.api = api;
        this.parentSessionId = parentSessionId;
        this.intentStore = intentStore;
        State = ChildLifecycleState.NoChild;
    }

    private ChildSessionIdentity? ReadValidChild()
    {
        if (api.CurrentSessionId != parentSessionId)
            throw new InvalidOperationException("The launcher is no longer in its original parent session.");
        ChildSessionIdentity? child = api.ReadAssociatedChild();
        if (child.HasValue && (child.Value.SessionId == uint.MaxValue ||
            child.Value.SessionId == parentSessionId || child.Value.LogonTime <= 0))
            throw new InvalidOperationException("The associated child has an invalid identity.");
        return child;
    }

    private bool ObservedChildStillExists()
    {
        ChildSessionIdentity? current = ReadValidChild();
        if (!current.HasValue)
        {
            FailureReason = "The previously observed child session is absent.";
            State = ChildLifecycleState.Terminated;
            return false;
        }
        if (!observedChild.HasValue || !current.Value.Equals(observedChild.Value))
        {
            FailureReason = "The parent-associated child identity changed.";
            State = ChildLifecycleState.Error;
            return false;
        }
        return true;
    }

    internal bool TryBeginConnection()
    {
        if (State == ChildLifecycleState.NoChild)
        {
            try
            {
                if (intentStore != null && intentStore.HasUnresolvedIntent(parentSessionId))
                    throw new InvalidOperationException("An earlier sign-out is unresolved. Reconcile it before connecting.");
                if (ReadValidChild().HasValue)
                    throw new InvalidOperationException("A parent-associated child already exists. Reconcile it before starting a fresh connection.");
            }
            catch (Exception ex) { FailureReason = ex.Message; State = ChildLifecycleState.Error; return false; }
            State = ChildLifecycleState.Connecting;
            return true;
        }
        if (State != ChildLifecycleState.ViewerDisconnected) return false;
        try
        {
            if (!ObservedChildStillExists()) return false;
            State = ChildLifecycleState.Reconnecting;
            return true;
        }
        catch (Exception ex) { FailureReason = ex.Message; State = ChildLifecycleState.Error; return false; }
    }

    internal bool ObserveConnected()
    {
        if (State != ChildLifecycleState.Connecting && State != ChildLifecycleState.Reconnecting)
            return false;
        try
        {
            ChildSessionIdentity? current = ReadValidChild();
            if (!current.HasValue || (observedChild.HasValue && !observedChild.Value.Equals(current.Value)))
            {
                FailureReason = "The connected child identity is absent or changed.";
                State = ChildLifecycleState.Error;
                return false;
            }
            observedChild = current;
            State = ChildLifecycleState.Connected;
            return true;
        }
        catch (Exception ex) { FailureReason = ex.Message; State = ChildLifecycleState.Error; return false; }
    }

    internal bool CheckConnectionPreflight()
    {
        if (State != ChildLifecycleState.Connecting && State != ChildLifecycleState.Reconnecting) return false;
        try
        {
            if (State == ChildLifecycleState.Reconnecting) return ObservedChildStillExists();
            if ((intentStore != null && intentStore.HasUnresolvedIntent(parentSessionId)) || ReadValidChild().HasValue)
            {
                FailureReason = "A sign-out intent or parent-associated child appeared before connection.";
                State = ChildLifecycleState.Error;
                return false;
            }
            return true;
        }
        catch (Exception ex) { FailureReason = ex.Message; State = ChildLifecycleState.Error; return false; }
    }

    internal void ObserveViewerDisconnected()
    {
        if (State != ChildLifecycleState.Connected) return;
        try
        {
            if (ObservedChildStillExists()) State = ChildLifecycleState.ViewerDisconnected;
        }
        catch (Exception ex) { FailureReason = ex.Message; State = ChildLifecycleState.Error; }
    }

    internal bool CheckConnectedIdentity()
    {
        if (State != ChildLifecycleState.Connected) return false;
        try { return ObservedChildStillExists(); }
        catch (Exception ex) { FailureReason = ex.Message; State = ChildLifecycleState.Error; return false; }
    }

    internal void ConnectionAttemptFailed()
    {
        if (State == ChildLifecycleState.Connecting || State == ChildLifecycleState.Reconnecting)
        {
            FailureReason = "The connection attempt did not establish a verified child session.";
            State = ChildLifecycleState.Error; // Outcome may already include a newly created child.
        }
    }

    internal void UnrecoverableError()
    {
        if (State != ChildLifecycleState.Terminated && State != ChildLifecycleState.SignOutRequested &&
            State != ChildLifecycleState.SignOutOutcomeUnknown)
            State = ChildLifecycleState.Error;
    }

    internal SignOutResult SignOut()
    {
        if (State != ChildLifecycleState.Connected || !observedChild.HasValue)
            return SignOutResult.Denied;
        State = ChildLifecycleState.SignOutRequested;
        try
        {
            ChildSessionIdentity? current = ReadValidChild();
            if (!current.HasValue || !current.Value.Equals(observedChild.Value))
            {
                FailureReason = "The child identity changed or disappeared before sign-out.";
                State = current.HasValue ? ChildLifecycleState.Error : ChildLifecycleState.Terminated;
                return SignOutResult.IdentityChanged;
            }
            if (intentStore != null)
            {
                try { intentStore.RecordIntent(parentSessionId, current.Value); }
                catch (Exception ex)
                {
                    FailureReason = "Sign-out intent could not be persisted; no logoff was attempted: " + ex.Message;
                    State = ChildLifecycleState.Error;
                    return SignOutResult.PersistenceFailed;
                }
            }
            // Set this before the call: a false return or exception may follow a partial logoff.
            State = ChildLifecycleState.SignOutOutcomeUnknown;
            if (!api.Logoff(current.Value.SessionId))
            {
                FailureReason = "WTSLogoffSession did not confirm completion.";
                return SignOutResult.OutcomeUnknown;
            }
            if (intentStore != null)
            {
                if (ReadValidChild().HasValue)
                {
                    FailureReason = "The child is still associated after sign-out returned.";
                    return SignOutResult.OutcomeUnknown;
                }
                intentStore.ResolveIntent(parentSessionId);
            }
            State = ChildLifecycleState.Terminated;
            return SignOutResult.Complete;
        }
        catch (Exception ex)
        {
            FailureReason = ex.Message;
            if (State == ChildLifecycleState.SignOutRequested) State = ChildLifecycleState.Error;
            return State == ChildLifecycleState.SignOutOutcomeUnknown
                ? SignOutResult.OutcomeUnknown : SignOutResult.IdentityChanged;
        }
    }
}
