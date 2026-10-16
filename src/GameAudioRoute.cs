using System;
using System.Collections.Generic;

// A snapshot is evidence of an active render session, not proof that the
// endpoint is private or that Moonlight played the samples.
internal sealed class GameAudioSessionSnapshot
{
    internal bool Complete;
    internal readonly List<GameAudioSession> Sessions = new List<GameAudioSession>();
}

internal sealed class GameAudioSession
{
    internal string EndpointId;
    internal int ProcessId;
    internal bool Active;
    internal bool MultiProcess;
}

internal static class GameAudioRoute
{
    internal const string MixerUri = "ms-settings:apps-volume";

    internal static string Assess(ProductProcessIdentity game, ProductProcessIdentity current,
        ChildSessionIdentity child, string selectedEndpoint, ChildAudioEndpointInventory endpoints,
        GameAudioSessionSnapshot snapshot)
    {
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
        bool selected = false, other = false, ambiguous = false;
        foreach (GameAudioSession session in snapshot.Sessions)
        {
            if (session == null || String.IsNullOrEmpty(session.EndpointId) ||
                !endpoints.ActiveRenderIds.Contains(session.EndpointId)) return "ObservationIncomplete";
            if (!session.Active) continue;
            // AUDCLNT_S_NO_SINGLE_PROCESS reports only the initial PID. It
            // cannot identify every process in the session on any endpoint.
            if (session.MultiProcess) { ambiguous = true; continue; }
            if (session.ProcessId != game.Pid) continue;
            if (String.Equals(session.EndpointId, selectedEndpoint, StringComparison.Ordinal)) selected = true;
            else other = true;
        }
        if (ambiguous) return "AmbiguousSession";
        if (other) return "WrongEndpoint";
        return selected ? "GameRenderObserved" : "WaitingForRender";
    }
}
