using System.Management;
using Chronos.Models;

namespace Chronos.Services;

/// <summary>Collects static machine facts via WMI/CIM. Every probe is independent and failure-safe.</summary>
public static class SystemInfoService
{
    public static bool IsElevated
    {
        get
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                return new System.Security.Principal.WindowsPrincipal(identity)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public static SystemInfo Collect()
    {
        var info = new SystemInfo();
        var probes = new List<Action>();
        void Queue(Action a) => probes.Add(() => Probe(a));

        Queue(() =>
        {
            foreach (var os in Query("SELECT Caption, Version, BuildNumber, InstallDate FROM Win32_OperatingSystem"))
            {
                info.WindowsEdition = S(os["Caption"]);
                info.WindowsVersion = DisplayVersion() is { Length: > 0 } dv ? dv : S(os["Version"]);
                info.Build = $"{S(os["Version"])} (build {S(os["BuildNumber"])})";
                var raw = S(os["InstallDate"]);
                if (raw.Length >= 14)
                    info.InstallDate = ManagementDateTimeConverter.ToDateTime(raw);
            }
        });

        Queue(() =>
        {
            foreach (var cpu in Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"))
                info.Cpu = $"{S(cpu["Name"]).Trim()} ({S(cpu["NumberOfCores"])} cores / {S(cpu["NumberOfLogicalProcessors"])} threads)";
        });

        Queue(() =>
        {
            var gpus = Query("SELECT Name FROM Win32_VideoController").Select(g => S(g["Name"])).Where(s => s.Length > 0);
            info.Gpu = string.Join(" + ", gpus);
        });

        Queue(() =>
        {
            ulong total = 0; var slots = 0;
            foreach (var m in Query("SELECT Capacity, Speed FROM Win32_PhysicalMemory"))
            {
                if (ulong.TryParse(S(m["Capacity"]), out var cap)) total += cap;
                slots++;
            }
            info.Ram = $"{total / 1024.0 / 1024 / 1024:0.#} GB ({slots} module(s))";
        });

        Queue(() =>
        {
            foreach (var b in Query("SELECT Manufacturer, Product FROM Win32_BaseBoard"))
                info.Motherboard = $"{S(b["Manufacturer"])} {S(b["Product"])}".Trim();
        });

        Queue(() =>
        {
            foreach (var b in Query("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS"))
            {
                var rel = S(b["ReleaseDate"]);
                var date = rel.Length >= 8 ? $" ({rel[..4]}-{rel[4..6]}-{rel[6..8]})" : "";
                info.Bios = $"{S(b["Manufacturer"])} {S(b["SMBIOSBIOSVersion"])}{date}".Trim();
            }
        });

        Queue(() =>
        {
            foreach (var p in Query("SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct"))
            {
                var sn = S(p["IdentifyingNumber"]).Trim();
                info.SerialNumber = sn is "" or "Default string" or "To be filled by O.E.M." ? "(not provided by OEM)" : sn;
            }
        });

        Queue(() =>
        {
            var disks = new List<string>();
            foreach (var d in Query("SELECT Model, Size FROM Win32_DiskDrive"))
            {
                var size = ulong.TryParse(S(d["Size"]), out var s) ? $" {s / 1_000_000_000} GB" : "";
                disks.Add($"{S(d["Model"]).Trim()}{size}");
            }
            info.Storage = string.Join("; ", disks);
        });

        var elevated = IsElevated;

        Queue(() =>
        {
            // the TPM WMI namespace is admin-only and takes ~5 s to fail otherwise
            if (!elevated) { info.Tpm = "Requires administrator"; return; }
            info.Tpm = "Not detected";
            foreach (var t in Query(@"root\cimv2\Security\MicrosoftTpm", "SELECT SpecVersion, IsEnabled_InitialValue FROM Win32_Tpm"))
            {
                var ver = S(t["SpecVersion"]).Split(',')[0].Trim();
                info.Tpm = $"TPM {ver}" + (S(t["IsEnabled_InitialValue"]) == "True" ? " (enabled)" : "");
            }
        });

        Queue(() =>
        {
            // UEFI SecureBoot state is exposed in the registry; readable without elevation.
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            info.SecureBoot = key?.GetValue("UEFISecureBootEnabled") switch
            {
                1 => "Enabled",
                0 => "Disabled",
                _ => "Unknown (legacy BIOS?)",
            };
        });

        Queue(() =>
        {
            // the BitLocker WMI namespace is also admin-only
            if (!elevated) { info.BitLocker = "Requires administrator"; return; }
            var vols = new List<string>();
            foreach (var v in Query(@"root\cimv2\Security\MicrosoftVolumeEncryption",
                "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume"))
            {
                var status = S(v["ProtectionStatus"]) switch { "1" => "On", "2" => "Unknown", _ => "Off" };
                var letter = S(v["DriveLetter"]);
                if (letter.Length > 0) vols.Add($"{letter} {status}");
            }
            info.BitLocker = vols.Count > 0 ? string.Join(", ", vols) : "Off";
        });

        Queue(() =>
        {
            info.Battery = "No battery (desktop)";
            foreach (var b in Query("SELECT EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery"))
            {
                var health = BatteryHealth();
                info.Battery = $"Charge {S(b["EstimatedChargeRemaining"])}%" + (health > 0 ? $", health {health}%" : "");
            }
        });

        Parallel.Invoke(new ParallelOptions { MaxDegreeOfParallelism = 6 }, probes.ToArray());
        return info;
    }

    /// <summary>Design capacity vs full-charge capacity → health percent, from root\wmi. 0 when unavailable.</summary>
    public static int BatteryHealth()
    {
        try
        {
            ulong designed = 0, full = 0;
            foreach (var o in Query(@"root\wmi", "SELECT DesignedCapacity FROM BatteryStaticData"))
                designed = Convert.ToUInt64(o["DesignedCapacity"]);
            foreach (var o in Query(@"root\wmi", "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity"))
                full = Convert.ToUInt64(o["FullChargedCapacity"]);
            return designed > 0 && full > 0 ? (int)Math.Min(100, full * 100 / designed) : 0;
        }
        catch { return 0; }
    }

    private static string? DisplayVersion()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("DisplayVersion") as string; // e.g. "24H2"
        }
        catch { return null; }
    }

    private static IEnumerable<ManagementBaseObject> Query(string wql) => Query(@"root\cimv2", wql);

    private static IEnumerable<ManagementBaseObject> Query(string scope, string wql)
    {
        using var searcher = new ManagementObjectSearcher(scope, wql);
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results) yield return o;
    }

    private static string S(object? o) => o?.ToString() ?? "";

    private static void Probe(Action probe)
    {
        try { probe(); }
        catch (Exception ex) { LogService.Warn("SystemInfo probe failed: " + ex.Message); }
    }
}
