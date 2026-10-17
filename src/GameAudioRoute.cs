using System;
using System.Collections.Generic;

// A snapshot is evidence of a render session, not proof that the
// endpoint is private or that Moonlight played the samples.
internal enum GameAudioSessionState { Unknown = -1, Inactive = 0, Active = 1, Expired = 2 }

internal sealed class GameAudioSessionSnapshot
{
    internal bool Complete;
    internal readonly List<GameAudioSession> Sessions = new List<GameAudioSession>();
}

internal sealed class GameAudioSession
{
    internal string EndpointId;
    internal int ProcessId;
    internal GameAudioSessionState State;
    internal string InstanceIdentifier;
    internal bool MultiProcess;
}

internal static class GameAudioRoute
{
    internal const string MixerUri = "ms-settings:apps-volume";

    internal static string Assess(ProductProcessIdentity game, ProductProcessIdentity current,
        ChildSessionIdentity child, string selectedEndpoint, ChildAudioEndpointInventory endpoints,
        GameAudioSessionSnapshot snapshot, string admittedInstanceIdentifier,
        out string activeInstanceIdentifier)
    {
        activeInstanceIdentifier = null;
        if (game == null) return "WaitingForGame";
        if (current == null || current.Pid != game.Pid ||
            current.StartTimeUtcTicks != game.StartTimeUtcTicks ||
            current.SessionId != (int)child.SessionId || game.SessionId != (int)child.SessionId ||
            !String.Equals(current.ExecutablePath, game.ExecutablePath, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(current.ExecutableSha256, game.ExecutableSha256, StringComparison.OrdinalIgnoreCase))
            return "GameIdentityLost";
        if (endpoints == null || !endpoints.Complete || endpoints.SessionId != (int)child.SessionId ||
            String.IsNullOrEmpty(selectedEndpoint) || !endpoints.ActiveRenderIds.Contains(selectedEndpoint))
            return "CaptureEndpointLost";
        if (snapshot == null || !snapshot.Complete) return "ObservationIncomplete";
        bool other = false, ambiguous = false, changed = false, knownIdle = false;
        string selectedActive = null;
        int exactLiveSessions = 0;
        foreach (GameAudioSession session in snapshot.Sessions)
        {
            if (session == null || String.IsNullOrEmpty(session.EndpointId) ||
                !endpoints.ActiveRenderIds.Contains(session.EndpointId) ||
                String.IsNullOrEmpty(session.InstanceIdentifier) ||
                session.State == GameAudioSessionState.Unknown) return "ObservationIncomplete";
            if (session.State == GameAudioSessionState.Expired) continue;
            // AUDCLNT_S_NO_SINGLE_PROCESS reports only the initial PID. It
            // cannot identify every process in the session on any endpoint.
            if (session.MultiProcess) { ambiguous = true; continue; }
            if (session.ProcessId != game.Pid) continue;
            exactLiveSessions++;
            bool onSelected = String.Equals(session.EndpointId, selectedEndpoint, StringComparison.Ordinal);
            if (!onSelected)
            {
                if (session.State == GameAudioSessionState.Active ||
                    String.Equals(session.InstanceIdentifier, admittedInstanceIdentifier, StringComparison.Ordinal))
                    other = true;
                continue;
            }
            if (admittedInstanceIdentifier != null &&
                !String.Equals(session.InstanceIdentifier, admittedInstanceIdentifier, StringComparison.Ordinal))
                changed = true;
            if (session.State == GameAudioSessionState.Active)
            {
                if (selectedActive != null) ambiguous = true;
                selectedActive = session.InstanceIdentifier;
            }
            else if (String.Equals(session.InstanceIdentifier, admittedInstanceIdentifier, StringComparison.Ordinal))
                knownIdle = true;
        }
        if (ambiguous) return "AmbiguousSession";
        if (other) return "WrongEndpoint";
        if (changed || exactLiveSessions > 1) return "AudioSessionChanged";
        if (selectedActive != null)
        {
            activeInstanceIdentifier = selectedActive;
            return "GameRenderObserved";
        }
        return knownIdle ? "GameRenderIdle" : "WaitingForRender";
    }
}
