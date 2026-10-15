using System;
using System.Collections.Generic;

// A source-side acceptance harness. Values must be measured on the approved
// physical test target; defaults are Unknown and never imply success.
internal sealed class PhysicalProductEvidence
{
    internal bool? IndependentParentAndChildInput;
    internal bool? ChildDisplayActive, ParentDisplayUnchanged;
    internal string ParentDisplayId, ChildDisplayId, SunshineCaptureDisplayId;
    internal int? SunshineSessionId;
    internal string EncoderObserved;
    internal int? MoonlightWidth, MoonlightHeight, MoonlightFps;
    internal bool? SustainedStreamStable, ParentForegroundGamepadWorks,
        ParentUnaffectedByGamepad, TwoControllersDistinct,
        ChildAudioOnTv, ParentAudioOnPc, AudioIsolated,
        SteamBigPictureInChild, MinecraftDungeonsPlayedInChild,
        ExactChildTeardown, OriginalSettingsRestored;
}

internal sealed class ProductGateResult
{
    internal string Id, Detail;
    internal bool Pass;
}

internal static class ProductAcceptance
{
    private static void Add(List<ProductGateResult> rows, string id, bool pass, string detail)
    { rows.Add(new ProductGateResult { Id = id, Pass = pass, Detail = detail }); }

    internal static IList<ProductGateResult> Evaluate(ChildSessionIdentity child, PhysicalProductEvidence evidence)
    {
        var rows = new List<ProductGateResult>();
        if (evidence == null) evidence = new PhysicalProductEvidence();
        Add(rows, "independent-desktops", evidence.IndependentParentAndChildInput == true,
            "Both Windows desktops must accept independent interaction.");
        bool childDisplay = evidence.ChildDisplayActive == true &&
            !String.IsNullOrEmpty(evidence.ChildDisplayId) &&
            !String.Equals(evidence.ChildDisplayId, evidence.ParentDisplayId, StringComparison.OrdinalIgnoreCase) &&
            String.Equals(evidence.ChildDisplayId, evidence.SunshineCaptureDisplayId,
                StringComparison.OrdinalIgnoreCase) && evidence.ParentDisplayUnchanged == true;
        Add(rows, "child-capture", childDisplay, "Capture must name a distinct active child display; parent display stays unchanged.");
        Add(rows, "child-process", evidence.SunshineSessionId == (int)child.SessionId && child.LogonTime > 0,
            "Sunshine process session and child logon generation must be verified.");
        Add(rows, "nvenc", String.Equals(evidence.EncoderObserved, "nvenc", StringComparison.OrdinalIgnoreCase),
            "Actual Sunshine encoder log must identify NVENC.");
        Add(rows, "moonlight-1080p60", evidence.MoonlightWidth == 1920 &&
            evidence.MoonlightHeight == 1080 && evidence.MoonlightFps >= 60 &&
            evidence.SustainedStreamStable == true,
            "A sustained Fire TV stream must measure at least 1920x1080 at 60 FPS.");
        Add(rows, "controllers", evidence.ParentForegroundGamepadWorks == true &&
            evidence.ParentUnaffectedByGamepad == true && evidence.TwoControllersDistinct == true,
            "Moonlight controllers must work in the child while parent has focus without affecting parent input.");
        Add(rows, "audio", evidence.ChildAudioOnTv == true && evidence.ParentAudioOnPc == true &&
            evidence.AudioIsolated == true,
            "Child stream and parent audio must remain independently audible and isolated.");
        Add(rows, "game", evidence.SteamBigPictureInChild == true &&
            evidence.MinecraftDungeonsPlayedInChild == true,
            "Steam and Minecraft Dungeons must run in the child session.");
        Add(rows, "restoration", evidence.ExactChildTeardown == true && evidence.OriginalSettingsRestored == true,
            "Exact child teardown and independent original-state restoration must pass.");
        return rows;
    }

    internal static bool Complete(IList<ProductGateResult> rows)
    {
        if (rows == null || rows.Count == 0) return false;
        foreach (ProductGateResult row in rows) if (!row.Pass) return false;
        return true;
    }
}
