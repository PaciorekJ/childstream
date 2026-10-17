using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

// A reviewed pre-feature packet record is distinct from Stage A/B child-loopback
// evidence. It never treats a closed socket or firewall metadata as a packet drop.
internal sealed class QualificationInterface
{
    internal int Index;
    internal string Path; // External, Guest, or Unknown
    internal string Identity;
    internal string Addresses;
}
internal sealed class QualificationDrop
{
    internal long RecordId, UtcTicks;
    internal int InterfaceIndex, Protocol, LocalPort;
    internal string FilterOrigin, RemoteAddress, LocalAddress;
    internal string Canonical()
    { return RecordId + "|" + UtcTicks + "|" + InterfaceIndex + "|" + Protocol + "|" +
        LocalPort + "|" + FilterOrigin + "|" + RemoteAddress + "|" + LocalAddress; }
}
internal sealed class QualificationBoundary
{
    internal string MachineId;
    internal readonly List<QualificationInterface> Interfaces = new List<QualificationInterface>();
    internal readonly List<QualificationDrop> Drops = new List<QualificationDrop>();
}
internal interface IConnectedQualificationHost
{
    QualificationBoundary Observe(long notBeforeUtcTicks, int rdpPort);
    long UtcNowTicks { get; }
}
internal sealed class QualificationRecord
{
    internal string MachineId, AccountHash, PlanHash, ContainmentHash, NetworkFingerprint,
        FirewallFingerprint, InterfaceFingerprint;
    internal int WindowsBuild, RdpPort, ExternalPaths, GuestPaths;
    internal long CapturedUtcTicks, ExpiresUtcTicks;
    internal readonly List<QualificationDrop> Drops = new List<QualificationDrop>();
    internal string Hash;
    internal byte[] Bytes()
    {
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            writer.Write("ChildStream.ConnectedQualification.v1");
            writer.Write(MachineId); writer.Write(AccountHash); writer.Write(PlanHash);
            writer.Write(ContainmentHash); writer.Write(NetworkFingerprint);
            writer.Write(FirewallFingerprint); writer.Write(InterfaceFingerprint);
            writer.Write(WindowsBuild); writer.Write(RdpPort);
            writer.Write(ExternalPaths); writer.Write(GuestPaths);
            writer.Write(CapturedUtcTicks); writer.Write(ExpiresUtcTicks);
            writer.Write(Drops.Count);
            foreach (var drop in Drops.OrderBy(x => x.InterfaceIndex).ThenBy(x => x.Protocol))
                writer.Write(drop.Canonical());
            writer.Flush(); return stream.ToArray();
        }
    }
    internal static QualificationRecord Read(byte[] bytes)
    {
        if (bytes == null || bytes.Length > 16384) throw new InvalidDataException("Qualification record size is invalid.");
        using (var stream = new MemoryStream(bytes))
        using (var reader = new BinaryReader(stream, Encoding.UTF8))
        {
            if (reader.ReadString() != "ChildStream.ConnectedQualification.v1")
                throw new InvalidDataException("Unknown qualification version.");
            var r = new QualificationRecord { MachineId = reader.ReadString(), AccountHash = reader.ReadString(),
                PlanHash = reader.ReadString(), ContainmentHash = reader.ReadString(),
                NetworkFingerprint = reader.ReadString(), FirewallFingerprint = reader.ReadString(),
                InterfaceFingerprint = reader.ReadString(), WindowsBuild = reader.ReadInt32(),
                RdpPort = reader.ReadInt32(), ExternalPaths = reader.ReadInt32(),
                GuestPaths = reader.ReadInt32(), CapturedUtcTicks = reader.ReadInt64(),
                ExpiresUtcTicks = reader.ReadInt64() };
            int count = reader.ReadInt32();
            if (count < 0 || count > 32) throw new InvalidDataException("Qualification coverage is unbounded.");
            for (int i = 0; i < count; i++)
            {
                string[] parts = reader.ReadString().Split('|');
                if (parts.Length != 8) throw new InvalidDataException("Malformed packet record.");
                r.Drops.Add(new QualificationDrop { RecordId = Int64.Parse(parts[0]),
                    UtcTicks = Int64.Parse(parts[1]), InterfaceIndex = Int32.Parse(parts[2]),
                    Protocol = Int32.Parse(parts[3]), LocalPort = Int32.Parse(parts[4]),
                    FilterOrigin = parts[5], RemoteAddress = parts[6], LocalAddress = parts[7] });
            }
            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing qualification data.");
            r.Hash = ProbeCodec.Hash(bytes); return r;
        }
    }
}

internal sealed class ConnectedQualificationGate
{
    private readonly IConnectedQualificationHost host;
    private readonly string root, accountHash;
    private const long Window = 10L * TimeSpan.TicksPerMinute;
    internal ConnectedQualificationGate(IConnectedQualificationHost host, string privateRoot, string accountHash)
    {
        if (host == null || !ProductInstallPayload.IsHex256(accountHash))
            throw new InvalidDataException("Qualification needs a native observer and requester identity.");
        root = InstallerPolicy.ValidateCanonicalFilePath(privateRoot, true);
        this.host = host; this.accountHash = accountHash.ToLowerInvariant();
    }
    private string Pending { get { return Path.Combine(root, "qualification.pending"); } }
    private string Reviewed { get { return Path.Combine(root, "qualification.reviewed"); } }
    private string ReviewHash { get { return Path.Combine(root, "qualification.reviewed.hash"); } }
    private string Used { get { return Path.Combine(root, "qualification.used"); } }
    internal bool HasActiveEvidence
    { get { return File.Exists(Pending) || File.Exists(Reviewed) || File.Exists(ReviewHash) || File.Exists(Used); } }
    private static string Interfaces(QualificationBoundary boundary)
    {
        if (boundary == null || String.IsNullOrWhiteSpace(boundary.MachineId) ||
            boundary.Interfaces.Count == 0 || boundary.Interfaces.Count > 16 ||
            boundary.Interfaces.Any(x => x.Index <= 0 || String.IsNullOrWhiteSpace(x.Identity) ||
                String.IsNullOrWhiteSpace(x.Addresses) ||
                (x.Path != "External" && x.Path != "Guest")) ||
            boundary.Interfaces.Select(x => x.Index).Distinct().Count() != boundary.Interfaces.Count ||
            !boundary.Interfaces.Any(x => x.Path == "External"))
            throw new InvalidOperationException("Relevant physical/virtual paths are unknown or incomplete.");
        return ProbeCodec.Hash(Encoding.UTF8.GetBytes(String.Join("\n", boundary.Interfaces
            .OrderBy(x => x.Index).Select(x => x.Index + "|" + x.Path + "|" + x.Identity + "|" + x.Addresses))));
    }
    private static List<QualificationDrop> Covered(QualificationBoundary boundary, int port, long now)
    {
        var selected = new List<QualificationDrop>();
        foreach (var path in boundary.Interfaces)
            foreach (int protocol in new[] { 6, 17 })
            {
                string origin = RdpContainmentTransaction.Expected(protocol).Name;
                QualificationDrop drop = boundary.Drops.Where(x => x.InterfaceIndex == path.Index &&
                    x.Protocol == protocol && x.FilterOrigin == origin && x.LocalPort == port &&
                    x.RecordId > 0 && x.UtcTicks >= now - Window && x.UtcTicks <= now &&
                    ValidNonLoopback(x.RemoteAddress) && ValidNonLoopback(x.LocalAddress) &&
                    path.Addresses.Split(',').Contains(x.LocalAddress))
                    .OrderByDescending(x => x.UtcTicks).FirstOrDefault();
                if (drop == null) throw new InvalidOperationException("An exact owned-rule WFP drop is missing for " +
                    path.Path + " interface " + path.Index + " protocol " + protocol + ".");
                selected.Add(drop);
            }
        if (selected.Select(x => x.RecordId).Distinct().Count() != selected.Count)
            throw new InvalidOperationException("Packet evidence reuses a Security event record.");
        return selected;
    }
    private static void RequireStoredCoverage(QualificationBoundary boundary, QualificationRecord r)
    {
        if (r.Drops.Count != boundary.Interfaces.Count * 2 ||
            r.Drops.Select(x => x.RecordId).Distinct().Count() != r.Drops.Count)
            throw new InvalidOperationException("Qualification packet coverage is incomplete or reused.");
        foreach (var path in boundary.Interfaces)
            foreach (int protocol in new[] { 6, 17 })
            {
                var recorded = r.Drops.Where(x => x.InterfaceIndex == path.Index && x.Protocol == protocol).ToArray();
                if (recorded.Length != 1 || recorded[0].FilterOrigin != RdpContainmentTransaction.Expected(protocol).Name ||
                    recorded[0].LocalPort != r.RdpPort ||
                    recorded[0].UtcTicks < r.CapturedUtcTicks - Window ||
                    recorded[0].UtcTicks > r.CapturedUtcTicks ||
                    !ValidNonLoopback(recorded[0].RemoteAddress) ||
                    !ValidNonLoopback(recorded[0].LocalAddress) ||
                    !path.Addresses.Split(',').Contains(recorded[0].LocalAddress))
                    throw new InvalidOperationException("Qualification packet coverage has a wrong origin or path.");
            }
    }
    private static bool ValidNonLoopback(string text)
    {
        System.Net.IPAddress ip;
        return System.Net.IPAddress.TryParse(text, out ip) &&
            !System.Net.IPAddress.IsLoopback(ip) && !ip.Equals(System.Net.IPAddress.Any) &&
            !ip.Equals(System.Net.IPAddress.IPv6Any);
    }
    private static void WriteOnce(string path, byte[] data)
    {
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { file.Write(data, 0, data.Length); file.Flush(true); }
    }
    private static string Summary(QualificationRecord r, string state)
    {
        Func<string, string> shortId = x => x == null ? "unknown" : x.Substring(0, Math.Min(12, x.Length));
        return state + " qualification " + r.Hash + "; machine=" + r.MachineId +
            "; requester=" + shortId(r.AccountHash) +
            "; plan=" + shortId(r.PlanHash) +
            "; containment=" + shortId(r.ContainmentHash) +
            "; build=" + r.WindowsBuild +
            "; network=" + shortId(r.NetworkFingerprint) +
            "; firewall=" + shortId(r.FirewallFingerprint) +
            "; paths=" + r.ExternalPaths + " external/" + r.GuestPaths + " guest" +
            "; WFP records=" + r.Drops.Count + "/" + (2 * (r.ExternalPaths + r.GuestPaths)) +
            "; expires=" + new DateTime(r.ExpiresUtcTicks, DateTimeKind.Utc).ToString("u") +
            "; child loopback=unrun";
    }
    private QualificationRecord Validate(ProbePlan plan, RdpContainmentTransaction containment,
        QualificationRecord r, bool reobserve)
    {
        if (plan == null || plan.Original.FormatVersion != 7 || !containment.Verify() ||
            containment.JournalHash() != plan.Original.QualifiedContainmentHash ||
            !String.Equals(r.AccountHash, accountHash, StringComparison.Ordinal) ||
            r.AccountHash != plan.Original.AccountBinding ||
            r.PlanHash != plan.Hash || r.ContainmentHash != containment.JournalHash() ||
            r.NetworkFingerprint != plan.Original.NetworkFingerprint ||
            r.FirewallFingerprint != plan.Original.FirewallFingerprint ||
            r.WindowsBuild != plan.Original.WindowsBuild || r.RdpPort < 1 || r.RdpPort > 65535 ||
            r.ExternalPaths < 1 || r.GuestPaths < 0 || r.ExternalPaths + r.GuestPaths > 16 ||
            r.RdpPort != containment.Observation().ConfiguredRdpPort ||
            host.UtcNowTicks < r.CapturedUtcTicks || host.UtcNowTicks >= r.ExpiresUtcTicks ||
            r.ExpiresUtcTicks - r.CapturedUtcTicks > Window ||
            r.Hash != ProbeCodec.Hash(r.Bytes()))
            throw new InvalidOperationException("Qualified evidence is stale, altered, incomplete, or belongs to another plan.");
        if (reobserve)
        {
            QualificationBoundary fresh = host.Observe(r.CapturedUtcTicks - Window, r.RdpPort);
            if (fresh.MachineId != r.MachineId || Interfaces(fresh) != r.InterfaceFingerprint)
                throw new InvalidOperationException("Machine or network path identity changed.");
            if (fresh.Interfaces.Count(x => x.Path == "External") != r.ExternalPaths ||
                fresh.Interfaces.Count(x => x.Path == "Guest") != r.GuestPaths)
                throw new InvalidOperationException("Network path coverage changed.");
            RequireStoredCoverage(fresh, r);
            if (r.Drops.Any(x => !fresh.Drops.Any(y => y.Canonical() == x.Canonical())))
                throw new InvalidOperationException("Native packet evidence changed or cannot be reread.");
        }
        return r;
    }
    internal string Observe(ProbePlan plan, RdpContainmentTransaction containment,
        RdpContainmentObservation policy)
    {
        if (File.Exists(Pending) || File.Exists(Reviewed) || File.Exists(ReviewHash) || File.Exists(Used))
            throw new InvalidOperationException("Previous qualification evidence exists; review or recover it first.");
        if (!containment.Verify() || policy == null || !RdpContainmentTransaction.Configured(policy) ||
            plan.Original.FormatVersion != 7 ||
            plan.Original.AccountBinding != accountHash ||
            plan.Original.QualifiedContainmentHash != containment.JournalHash())
            throw new InvalidOperationException("The exact owned containment is not effective.");
        long now = host.UtcNowTicks;
        QualificationBoundary boundary = host.Observe(now - Window, policy.ConfiguredRdpPort);
        string interfaceHash = Interfaces(boundary);
        List<QualificationDrop> covered = Covered(boundary, policy.ConfiguredRdpPort, now);
        var r = new QualificationRecord { MachineId = boundary.MachineId, AccountHash = accountHash,
            PlanHash = plan.Hash, ContainmentHash = containment.JournalHash(),
            NetworkFingerprint = plan.Original.NetworkFingerprint,
            FirewallFingerprint = plan.Original.FirewallFingerprint,
            InterfaceFingerprint = interfaceHash, WindowsBuild = plan.Original.WindowsBuild,
            RdpPort = policy.ConfiguredRdpPort,
            ExternalPaths = boundary.Interfaces.Count(x => x.Path == "External"),
            GuestPaths = boundary.Interfaces.Count(x => x.Path == "Guest"),
            CapturedUtcTicks = now, ExpiresUtcTicks = now + Window };
        r.Drops.AddRange(covered); r.Hash = ProbeCodec.Hash(r.Bytes());
        WriteOnce(Pending, r.Bytes());
        return Summary(r, "Pending");
    }
    internal string Review(string exactHash, ProbePlan currentPlan, RdpContainmentTransaction containment)
    {
        if (File.Exists(Reviewed) || File.Exists(Used) || !File.Exists(Pending))
            throw new InvalidOperationException("No new unreviewed qualification exists.");
        QualificationRecord r = QualificationRecord.Read(File.ReadAllBytes(Pending));
        if (!String.Equals(r.Hash, exactHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Reviewed qualification hash differs.");
        Validate(currentPlan, containment, r, true);
        File.Move(Pending, Reviewed);
        WriteOnce(ReviewHash, Encoding.ASCII.GetBytes(r.Hash + "\n"));
        return Summary(r, "Reviewed");
    }
    internal string Admit(ProbePlan currentPlan, RdpContainmentTransaction containment, bool begin)
    {
        if (!File.Exists(Reviewed) || !File.Exists(ReviewHash))
            throw new InvalidOperationException("No complete reviewed native packet evidence exists.");
        QualificationRecord r = Validate(currentPlan, containment,
            QualificationRecord.Read(File.ReadAllBytes(Reviewed)), true);
        if (File.ReadAllText(ReviewHash) != r.Hash + "\n")
            throw new InvalidOperationException("The reviewed evidence hash changed.");
        if (begin)
        {
            if (File.Exists(Used)) throw new InvalidOperationException("Qualification was already consumed.");
            WriteOnce(Used, Encoding.ASCII.GetBytes(r.Hash + "\n" + currentPlan.Hash + "\n"));
        }
        else if (!File.Exists(Used) || File.ReadAllText(Used) != r.Hash + "\n" + currentPlan.Hash + "\n")
            throw new InvalidOperationException("Feature approval does not match the admitted journal.");
        return r.Hash;
    }
    internal string Status()
    {
        if (File.Exists(Used)) return "Qualification consumed; inspect exact setup journal before recovery.";
        if (File.Exists(Reviewed)) return File.Exists(ReviewHash) &&
            File.ReadAllText(ReviewHash) == QualificationRecord.Read(File.ReadAllBytes(Reviewed)).Hash + "\n"
            ? Summary(QualificationRecord.Read(File.ReadAllBytes(Reviewed)), "Reviewed") :
            "Qualification review is interrupted; admission disabled.";
        if (File.Exists(Pending)) return Summary(QualificationRecord.Read(File.ReadAllBytes(Pending)), "Pending");
        return "No packet qualification evidence.";
    }
    internal string Retire(string exactHash, ProbeJournal journal, ProbePlan current,
        RdpContainmentTransaction containment)
    {
        if (!ProductInstallPayload.IsHex256(exactHash) || !containment.Verify() ||
            current == null || current.Original.FeatureEnabled ||
            journal != null && journal.Stage != ProbeStage.Restored)
            throw new InvalidOperationException("Feature, child, listener, or containment restoration is not verified.");
        exactHash = exactHash.ToLowerInvariant();
        string source = new[] { Reviewed, Pending, Reviewed + ".retired." + exactHash,
            Pending + ".retired." + exactHash }.FirstOrDefault(File.Exists);
        if (!File.Exists(source)) throw new InvalidOperationException("No exact qualification record is available to retire.");
        QualificationRecord record = QualificationRecord.Read(File.ReadAllBytes(source));
        string admittedPlanHash = journal == null ? current.Hash : journal.Plan.Hash;
        if (!String.Equals(record.Hash, exactHash, StringComparison.OrdinalIgnoreCase) ||
            record.PlanHash != admittedPlanHash || record.AccountHash != accountHash ||
            record.ContainmentHash != containment.JournalHash() ||
            File.Exists(Used) && File.ReadAllText(Used) != record.Hash + "\n" + admittedPlanHash + "\n" ||
            File.Exists(ReviewHash) && File.ReadAllText(ReviewHash) != record.Hash + "\n")
            throw new InvalidOperationException("Qualification retirement identity changed.");
        foreach (string path in new[] { Pending, Reviewed, ReviewHash, Used })
            if (File.Exists(path))
            {
                string retired = path + ".retired." + record.Hash;
                if (File.Exists(retired))
                {
                    if (!File.ReadAllBytes(path).SequenceEqual(File.ReadAllBytes(retired)))
                        throw new InvalidOperationException("Qualification retirement has conflicting copies.");
                    File.Delete(path);
                }
                else File.Move(path, retired);
            }
        return "Qualification " + record.Hash + " retired after verified feature restoration.";
    }
}
