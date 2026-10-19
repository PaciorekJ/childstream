using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Win32;

// These reads are invoked only inside the verified limited child agent. They
// examine Steam and the fixed game app, never arbitrary development processes.
internal static class WindowsSteamDiscovery
{
    private static string Sha256(string path)
    {
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var hash = SHA256.Create())
            return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "");
    }
    private static string RequireRegular(string path, string leaf)
    {
        if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path))
            throw new InvalidOperationException("Steam installation path is unavailable.");
        path = Path.GetFullPath(path);
        if (!String.Equals(Path.GetFileName(path), leaf, StringComparison.OrdinalIgnoreCase) ||
            (File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException("Steam executable identity is unsupported or ambiguous.");
        InstallerPolicy.ValidateCanonicalFilePath(path);
        return path;
    }
    internal static SteamInstallation ReadInstallation()
    {
        string steamPath = null;
        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam", false))
            if (key != null)
            {
                steamPath = key.GetValue("SteamExe") as string;
                if (String.IsNullOrWhiteSpace(steamPath))
                {
                    string root = key.GetValue("SteamPath") as string;
                    if (!String.IsNullOrWhiteSpace(root)) steamPath = Path.Combine(root, "steam.exe");
                }
            }
        if (String.IsNullOrWhiteSpace(steamPath))
            steamPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Steam", "steam.exe");
        steamPath = RequireRegular(steamPath, "steam.exe");
        string steamApps = Path.Combine(Path.GetDirectoryName(steamPath), "steamapps");
        string manifest = Path.Combine(steamApps, "appmanifest_" + SteamChildPolicy.MinecraftDungeonsAppId + ".acf");
        InstallerPolicy.ValidateCanonicalFilePath(manifest);
        var info = new FileInfo(manifest);
        if (!info.Exists || info.Length <= 0 || info.Length > 65536)
            throw new FileNotFoundException("Minecraft Dungeons Steam manifest is absent from this library.", manifest);
        string text = File.ReadAllText(manifest);
        Match match = Regex.Match(text, "(?m)^\\s*\"installdir\"\\s*\"([^\"]+)\"\\s*$", RegexOptions.IgnoreCase);
        if (!match.Success || Regex.Matches(text, "(?m)^\\s*\"installdir\"", RegexOptions.IgnoreCase).Count != 1)
            throw new InvalidDataException("Minecraft Dungeons Steam installation directory is ambiguous.");
        string installDir = match.Groups[1].Value;
        if (!Regex.IsMatch(installDir, "\\A[A-Za-z0-9 ._'()-]{1,120}\\z") ||
            installDir == "." || installDir == "..")
            throw new InvalidDataException("Minecraft Dungeons installation directory is unsafe.");
        string gameRoot = Path.Combine(steamApps, "common", installDir);
        InstallerPolicy.ValidateCanonicalFilePath(gameRoot, true);
        if (!Directory.Exists(gameRoot)) throw new DirectoryNotFoundException("Minecraft Dungeons game files are absent.");
        var matches = new List<string>();
        var pending = new Stack<string>(); pending.Push(gameRoot);
        int directories = 0, files = 0;
        while (pending.Count != 0)
        {
            string folder = pending.Pop();
            if (++directories > 256 || (File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Minecraft Dungeons install tree is too large or redirected.");
            foreach (string item in Directory.GetFiles(folder))
            {
                if (++files > 5000) throw new InvalidDataException("Minecraft Dungeons install tree exceeds the inspection limit.");
                if (String.Equals(Path.GetFileName(item), "Dungeons-Win64-Shipping.exe", StringComparison.OrdinalIgnoreCase))
                    matches.Add(RequireRegular(item, "Dungeons-Win64-Shipping.exe"));
            }
            foreach (string item in Directory.GetDirectories(folder)) pending.Push(item);
        }
        if (matches.Count != 1)
            throw new InvalidOperationException("Exactly one supported Minecraft Dungeons game executable must be observed.");
        return new SteamInstallation { SteamPath = steamPath, SteamSha256 = Sha256(steamPath),
            GamePath = matches[0], GameSha256 = Sha256(matches[0]) };
    }
    internal static SteamLaunchObservation ReadSteamProcesses(IProductProcessHost host,
        ChildSessionIdentity child, uint parentSessionId)
    {
        var observed = new SteamLaunchObservation { Complete = true };
        foreach (Process process in Process.GetProcessesByName("steam"))
        {
            using (process)
            {
                ProductProcessIdentity value = host.Read(process.Id);
                if (value == null) { observed.Complete = false; continue; }
                if (value.SessionId == (int)child.SessionId &&
                    host.ReadSessionLogonTime(value.SessionId) == child.LogonTime)
                    observed.ChildSteam = true;
                else if (value.SessionId == (int)parentSessionId) observed.ParentSteam = true;
                else observed.UnrelatedSteam = true;
            }
        }
        return observed;
    }
    internal static ProductProcessIdentity ReadExactGame(IProductProcessHost host,
        ChildSessionIdentity child, SteamInstallation installation)
    {
        if (installation == null || String.IsNullOrEmpty(installation.GamePath))
            throw new InvalidOperationException("Exact game installation is unavailable.");
        ProductProcessIdentity matched = null;
        string processName = Path.GetFileNameWithoutExtension(installation.GamePath);
        foreach (Process process in Process.GetProcessesByName(processName))
        {
            using (process)
            {
                ProductProcessIdentity value = host.Read(process.Id);
                if (value == null) throw new InvalidOperationException("A matching game process could not be inspected.");
                if (!String.Equals(Path.GetFullPath(value.ExecutablePath), installation.GamePath,
                    StringComparison.OrdinalIgnoreCase)) continue;
                if (value.SessionId != (int)child.SessionId ||
                    host.ReadSessionLogonTime(value.SessionId) != child.LogonTime ||
                    !String.Equals(value.ExecutableSha256, installation.GameSha256, StringComparison.OrdinalIgnoreCase) ||
                    matched != null)
                    throw new InvalidOperationException("Game process ownership or uniqueness is uncertain.");
                matched = value;
            }
        }
        return matched;
    }
}
