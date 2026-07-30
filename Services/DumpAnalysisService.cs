using System.IO;
using System.Text;
using Chronos.Models;

namespace Chronos.Services;

/// <summary>Result of analyzing one crash dump file: what happened, who did it, what to do.</summary>
public sealed class DumpAnalysis
{
    public string FilePath { get; init; } = "";
    public string FileName => Path.GetFileName(FilePath);
    public DateTime Timestamp { get; init; }
    public long FileSize { get; init; }
    public bool IsKernel { get; init; }

    /// <summary>e.g. "DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1)" or "Access violation in chrome.exe".</summary>
    public string Headline { get; init; } = "";

    /// <summary>One-sentence probable cause, plain language.</summary>
    public string Verdict { get; init; } = "";

    /// <summary>What this kind of crash means.</summary>
    public string Explanation { get; init; } = "";

    /// <summary>Concrete resolution steps, in order.</summary>
    public List<string> Resolutions { get; init; } = new();

    /// <summary>Faulting module / suspect driver, when identified.</summary>
    public string? Culprit { get; init; }

    /// <summary>Third-party drivers spotted in a kernel dump (candidates).</summary>
    public List<string> ThirdPartyDrivers { get; init; } = new();

    /// <summary>Raw codes and addresses for the technically inclined.</summary>
    public string TechnicalDetails { get; init; } = "";

    public string SizeText => FileSize > 1_048_576 ? $"{FileSize / 1048576.0:0.#} MB" : $"{FileSize / 1024.0:0.#} KB";
}

/// <summary>
/// Parses Windows crash dumps without debugger tooling or symbols:
///  - kernel minidumps (C:\Windows\Minidump, 'PAGE'+'DU64'/'DUMP' header) → bugcheck code,
///    parameters and a suspect-driver sweep;
///  - WER user-mode dumps (%LOCALAPPDATA%\CrashDumps, 'MDMP' format) → exception code,
///    faulting module via the module list stream.
/// Each result carries a human-readable verdict and resolution steps.
/// </summary>
public static class DumpAnalysisService
{
    private const int MaxSweepBytes = 64 * 1024 * 1024;

    // ------------------------------------------------------------------ discovery

    public static (List<DumpAnalysis> Dumps, List<string> Notes) LocateAndAnalyze()
    {
        var dumps = new List<DumpAnalysis>();
        var notes = new List<string>();

        void Scan(string dir, string label)
        {
            try
            {
                if (!Directory.Exists(dir)) return;
                foreach (var f in Directory.EnumerateFiles(dir, "*.dmp"))
                {
                    var a = TryAnalyze(f);
                    if (a is not null) dumps.Add(a);
                }
            }
            catch (UnauthorizedAccessException)
            {
                notes.Add($"{label} requires administrator rights ({dir}). Run Chronos as administrator to analyze kernel dumps.");
            }
            catch (Exception ex)
            {
                LogService.Warn($"Dump scan failed for {dir}: {ex.Message}");
            }
        }

        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Scan(Path.Combine(windir, "Minidump"), "The BSOD minidump folder");
        Scan(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrashDumps"),
             "The WER crash dump folder");

        var full = Path.Combine(windir, "MEMORY.DMP");
        if (File.Exists(full))
        {
            var a = TryAnalyze(full);
            if (a is not null) dumps.Add(a);
            else notes.Add("MEMORY.DMP exists but could not be read (in use or requires administrator).");
        }

        if (!Directory.Exists(Path.Combine(windir, "Minidump")))
            notes.Add("No BSOD minidump folder found - this machine has no recorded blue-screen dumps.");

        return (dumps.OrderByDescending(d => d.Timestamp).ToList(), notes);
    }

    public static DumpAnalysis? TryAnalyze(string path)
    {
        try { return Analyze(path); }
        catch (Exception ex)
        {
            LogService.Warn($"Dump analysis failed for {path}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Analyzes a single .dmp file (kernel or user-mode). Throws on unreadable files.</summary>
    public static DumpAnalysis Analyze(string path)
    {
        var info = new FileInfo(path);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var sig = new byte[8];
        if (fs.Read(sig, 0, 8) < 8) throw new InvalidDataException("File too small to be a dump.");

        var ascii = Encoding.ASCII.GetString(sig);
        if (ascii.StartsWith("PAGE"))
            return AnalyzeKernel(fs, info, is64: ascii[4..] == "DU64");
        if (ascii.StartsWith("MDMP"))
            return AnalyzeUserMode(fs, info);

        throw new InvalidDataException("Not a recognized Windows dump format (expected PAGEDU64/PAGEDUMP or MDMP).");
    }

    // ------------------------------------------------------------------ kernel dumps

    private static DumpAnalysis AnalyzeKernel(FileStream fs, FileInfo info, bool is64)
    {
        var header = new byte[0x60];
        fs.Position = 0;
        if (fs.Read(header, 0, header.Length) < header.Length)
            throw new InvalidDataException("Truncated kernel dump header.");

        uint code;
        ulong p1, p2, p3, p4;
        if (is64)
        {
            code = BitConverter.ToUInt32(header, 0x38);
            p1 = BitConverter.ToUInt64(header, 0x40);
            p2 = BitConverter.ToUInt64(header, 0x48);
            p3 = BitConverter.ToUInt64(header, 0x50);
            p4 = BitConverter.ToUInt64(header, 0x58);
        }
        else
        {
            code = BitConverter.ToUInt32(header, 0x28);
            p1 = BitConverter.ToUInt32(header, 0x2C);
            p2 = BitConverter.ToUInt32(header, 0x30);
            p3 = BitConverter.ToUInt32(header, 0x34);
            p4 = BitConverter.ToUInt32(header, 0x38);
        }

        var thirdParty = SweepDrivers(fs);
        var kb = BugCheckInfo(code);
        var culprit = thirdParty.FirstOrDefault();
        var culpritDesc = culprit is not null ? DescribeDriver(culprit) : null;

        var verdict = culprit is not null
            ? $"Probably caused by a driver. Suspect: {culprit}" + (culpritDesc is not null ? $" ({culpritDesc})" : "") + "."
            : "No third-party driver stood out in the dump; suspect hardware (RAM, storage, overheating) or a core driver.";

        var resolutions = new List<string>(kb.Resolutions);
        if (culpritDesc is not null)
            resolutions.Insert(0, $"Update or reinstall the {culpritDesc} - the driver {culprit} was loaded and is the most likely culprit.");
        else if (culprit is not null)
            resolutions.Insert(0, $"Look up the driver '{culprit}', find which program or device installed it, and update or remove it.");

        return new DumpAnalysis
        {
            FilePath = info.FullName,
            Timestamp = info.LastWriteTime,
            FileSize = info.Length,
            IsKernel = true,
            Headline = $"{kb.Name} (0x{code:X})",
            Verdict = verdict,
            Explanation = kb.Explanation,
            Resolutions = resolutions,
            Culprit = culprit,
            ThirdPartyDrivers = thirdParty,
            TechnicalDetails =
                $"Bugcheck 0x{code:X8}  P1=0x{p1:X}  P2=0x{p2:X}  P3=0x{p3:X}  P4=0x{p4:X}  " +
                $"({(is64 ? "x64" : "x86")} kernel dump, {info.Length / 1024} KB)",
        };
    }

    /// <summary>Scans dump bytes for driver names (*.sys, ASCII and UTF-16) that are not core Windows drivers.</summary>
    private static List<string> SweepDrivers(FileStream fs)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var len = (int)Math.Min(fs.Length, MaxSweepBytes);
        var buf = new byte[len];
        fs.Position = 0;
        var read = 0;
        while (read < len)
        {
            var n = fs.Read(buf, read, len - read);
            if (n <= 0) break;
            read += n;
        }

        // ASCII scan for ".sys"
        for (var i = 4; i < read - 1; i++)
        {
            if (buf[i] != (byte)'.' || (buf[i + 1] | 0x20) != 's') continue;
            if (i + 3 >= read || (buf[i + 2] | 0x20) != 'y' || (buf[i + 3] | 0x20) != 's') continue;
            var start = i;
            while (start > 0 && IsNameChar(buf[start - 1])) start--;
            if (i - start is > 2 and < 48)
                found.Add(Encoding.ASCII.GetString(buf, start, i - start) + ".sys");
        }

        // UTF-16LE scan for ".sys"
        for (var i = 8; i < read - 7; i += 2)
        {
            if (buf[i] != (byte)'.' || buf[i + 1] != 0 || (buf[i + 2] | 0x20) != 's' || buf[i + 3] != 0) continue;
            if ((buf[i + 4] | 0x20) != 'y' || buf[i + 5] != 0 || (buf[i + 6] | 0x20) != 's' || buf[i + 7] != 0) continue;
            var start = i;
            while (start > 1 && buf[start - 1] == 0 && IsNameChar(buf[start - 2])) start -= 2;
            var chars = (i - start) / 2;
            if (chars is > 2 and < 48)
                found.Add(Encoding.Unicode.GetString(buf, start, i - start) + ".sys");
        }

        return found
            .Select(f => f.ToLowerInvariant())
            .Distinct()
            .Where(f => !CoreDrivers.Contains(f) && !f.StartsWith("dump_"))
            .OrderByDescending(f => DescribeDriver(f) is not null) // known third-party first
            .ThenBy(f => f)
            .Take(15)
            .ToList();
    }

    private static bool IsNameChar(byte b) =>
        b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9'
          or (byte)'_' or (byte)'-';

    // ------------------------------------------------------------------ user-mode (MDMP) dumps

    private static DumpAnalysis AnalyzeUserMode(FileStream fs, FileInfo info)
    {
        var len = (int)Math.Min(fs.Length, int.MaxValue);
        var buf = new byte[Math.Min(len, 256 * 1024 * 1024)];
        fs.Position = 0;
        var read = 0;
        while (read < buf.Length)
        {
            var n = fs.Read(buf, read, buf.Length - read);
            if (n <= 0) break;
            read += n;
        }

        var streamCount = BitConverter.ToUInt32(buf, 8);
        var dirRva = BitConverter.ToUInt32(buf, 12);

        uint excCode = 0;
        ulong excAddress = 0;
        var modules = new List<(string Name, ulong Base, uint Size)>();

        for (var i = 0; i < streamCount; i++)
        {
            var entry = (int)dirRva + i * 12;
            if (entry + 12 > read) break;
            var type = BitConverter.ToUInt32(buf, entry);
            var rva = (int)BitConverter.ToUInt32(buf, entry + 8);

            if (type == 6 && rva + 40 <= read) // ExceptionStream
            {
                excCode = BitConverter.ToUInt32(buf, rva + 8);
                excAddress = BitConverter.ToUInt64(buf, rva + 24);
            }
            else if (type == 4 && rva + 4 <= read) // ModuleListStream
            {
                var count = BitConverter.ToUInt32(buf, rva);
                for (var m = 0; m < count; m++)
                {
                    var e = rva + 4 + m * 108;
                    if (e + 108 > read) break;
                    var baseAddr = BitConverter.ToUInt64(buf, e);
                    var size = BitConverter.ToUInt32(buf, e + 8);
                    var nameRva = (int)BitConverter.ToUInt32(buf, e + 20);
                    var name = "";
                    if (nameRva + 4 <= read)
                    {
                        var nameLen = (int)BitConverter.ToUInt32(buf, nameRva);
                        if (nameLen > 0 && nameLen < 2048 && nameRva + 4 + nameLen <= read)
                            name = Encoding.Unicode.GetString(buf, nameRva + 4, nameLen);
                    }
                    modules.Add((name, baseAddr, size));
                }
            }
        }

        var exeName = modules.Count > 0 ? Path.GetFileName(modules[0].Name) : Path.GetFileName(info.Name).Split('.')[0] + ".exe";
        var faulting = modules.FirstOrDefault(m => excAddress >= m.Base && excAddress < m.Base + m.Size);
        var faultingName = faulting.Name.Length > 0 ? Path.GetFileName(faulting.Name) : null;

        var kb = ExceptionInfo(excCode, exeName, faultingName);
        var culpritDesc = faultingName is not null ? DescribeDriver(faultingName.ToLowerInvariant()) : null;

        // Managed (.NET) and C++ exceptions are raised via RaiseException in KERNELBASE -
        // that module is the messenger, not the culprit.
        var raisedViaWindows = excCode is 0xE0434352 or 0xE06D7363 &&
            faultingName is "KERNELBASE.dll" or "kernelbase.dll" or "kernel32.dll";
        if (raisedViaWindows) faultingName = exeName;

        var verdict = faultingName is null
            ? $"{exeName} crashed at an address outside every loaded module (often heap corruption or a bad function pointer)."
            : raisedViaWindows
                ? $"An unhandled exception in {exeName}'s own code terminated the process."
                : faultingName.Equals(exeName, StringComparison.OrdinalIgnoreCase)
                    ? $"The crash happened inside {exeName} itself - this is a bug in the application."
                    : $"The crash happened inside {faultingName}{(culpritDesc is not null ? $" ({culpritDesc})" : "")} loaded by {exeName}.";

        return new DumpAnalysis
        {
            FilePath = info.FullName,
            Timestamp = info.LastWriteTime,
            FileSize = info.Length,
            IsKernel = false,
            Headline = $"{kb.Name} in {exeName}",
            Verdict = verdict,
            Explanation = kb.Explanation,
            Resolutions = kb.Resolutions.ToList(),
            Culprit = faultingName,
            TechnicalDetails =
                $"Exception 0x{excCode:X8} at 0x{excAddress:X}  faulting module: {faultingName ?? "(unknown)"}  " +
                $"modules: {modules.Count}  (user-mode MDMP, {info.Length / 1024} KB)",
        };
    }

    // ------------------------------------------------------------------ knowledge base

    private sealed record CrashKb(string Name, string Explanation, string[] Resolutions);

    private static CrashKb BugCheckInfo(uint code) => code switch
    {
        0x0A => new("IRQL_NOT_LESS_OR_EQUAL",
            "The kernel or a driver touched memory it must not touch at a high interrupt level. Almost always a buggy driver; sometimes faulty RAM.",
            new[] { "Update network, GPU, storage and antivirus drivers.", "Test the RAM with Windows Memory Diagnostic or MemTest86.", "Undo any recent driver installation or overclock." }),
        0x1A => new("MEMORY_MANAGEMENT",
            "The kernel's memory bookkeeping found corruption. The usual causes are failing RAM, a bad overclock/XMP profile, or a driver corrupting memory.",
            new[] { "Run MemTest86 overnight (or Windows Memory Diagnostic).", "Disable XMP/EXPO and any RAM overclock and re-test.", "If memory tests pass, update chipset and GPU drivers." }),
        0x1E => new("KMODE_EXCEPTION_NOT_HANDLED",
            "A kernel-mode component raised an exception nothing handled - typically a driver bug, occasionally RAM.",
            new[] { "Update or roll back recently changed drivers.", "Run a memory test.", "Check disk health (chkdsk, SMART)." }),
        0x3B => new("SYSTEM_SERVICE_EXCEPTION",
            "A system service crashed while running - commonly graphics or antivirus drivers.",
            new[] { "Update the GPU driver (clean install with DDU if it repeats).", "Temporarily remove third-party antivirus.", "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'." }),
        0x50 => new("PAGE_FAULT_IN_NONPAGED_AREA",
            "The system referenced memory that is not there. Causes: failing RAM, a corrupt NTFS volume, or a faulty driver (antivirus filters are common).",
            new[] { "Test the RAM.", "Run 'chkdsk /f' on the system drive.", "Remove or update antivirus / recently added drivers." }),
        0x7A => new("KERNEL_DATA_INPAGE_ERROR",
            "Windows failed to read kernel data back from disk - the storage device, cable or controller lost data.",
            new[] { "Check SMART health of the disk immediately and back up data.", "Reseat/replace SATA cable or try another M.2 slot.", "Update storage (AHCI/NVMe/RST) drivers and SSD firmware." }),
        0x7E => new("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
            "A system thread crashed. The parameters usually point at the responsible driver.",
            new[] { "Update the driver named in the dump (see suspects below).", "Boot into Safe Mode and roll back recent driver updates.", "Run a memory test if no driver stands out." }),
        0x9F => new("DRIVER_POWER_STATE_FAILURE",
            "A driver failed to complete a sleep/resume power transition. Typical culprits: network, GPU or storage drivers, or a USB device.",
            new[] { "Update network and GPU drivers.", "Disconnect USB devices and docks, then re-test sleep.", "Disable Fast Startup (powercfg /h off also helps).", "Update BIOS and chipset drivers." }),
        0xC2 => new("BAD_POOL_CALLER",
            "A driver misused kernel memory pools.",
            new[] { "Remove or update recently installed drivers and antivirus.", "Check for driver updates for all devices in Device Manager." }),
        0x19 => new("BAD_POOL_HEADER",
            "Kernel pool memory was corrupted - a driver wrote where it should not.",
            new[] { "Update or remove third-party antivirus and VPN drivers.", "Test RAM.", "Undo overclocks." }),
        0xD1 => new("DRIVER_IRQL_NOT_LESS_OR_EQUAL",
            "A driver accessed pageable memory at a too-high interrupt level - a driver bug, most often network or storage drivers.",
            new[] { "Update the suspect driver (see below), especially WiFi/Ethernet drivers.", "If it started recently, roll back the last driver update.", "Test RAM if no driver stands out." }),
        0xEF => new("CRITICAL_PROCESS_DIED",
            "A process Windows cannot live without (csrss, wininit, svchost...) terminated. Causes range from disk corruption to antivirus interference.",
            new[] { "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'.", "Run 'chkdsk /f'.", "Uninstall third-party antivirus temporarily.", "Check the disk's SMART health." }),
        0xFC => new("ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
            "Code tried to run from a memory page marked no-execute - driver bug or RAM failure.",
            new[] { "Test the RAM.", "Update drivers, BIOS and chipset.", "Undo overclocks." }),
        0x109 => new("CRITICAL_STRUCTURE_CORRUPTION",
            "Kernel structures were modified unexpectedly - a rogue/buggy driver, cheat/anticheat software, or failing RAM.",
            new[] { "Uninstall game anti-cheat drivers, tuning tools (CPU-Z-style utilities, RGB software) and re-test.", "Test the RAM.", "Update the BIOS." }),
        0x116 => new("VIDEO_TDR_FAILURE",
            "The graphics driver stopped responding and could not recover. GPU driver or GPU hardware/overheating.",
            new[] { "Clean-install the GPU driver (use DDU in Safe Mode).", "Check GPU temperatures and fans.", "Remove GPU overclock.", "If it persists on a known-good driver, the GPU itself may be failing." }),
        0x124 => new("WHEA_UNCORRECTABLE_ERROR",
            "The CPU reported an unrecoverable hardware error (machine check). This is hardware: CPU, power delivery, overheating, or an unstable overclock/undervolt.",
            new[] { "Remove every overclock/undervolt including XMP and re-test.", "Check CPU temperatures and the cooler mount.", "Update the BIOS.", "Test with another PSU if it continues - and consider RMA for the CPU." }),
        0x133 => new("DPC_WATCHDOG_VIOLATION",
            "A driver kept the CPU busy too long at high priority. Very often old SSD/NVMe firmware or storage drivers, sometimes GPU/network drivers.",
            new[] { "Update SSD firmware and storage (NVMe/AHCI/RST) drivers.", "Update GPU and network drivers.", "Check Event Viewer for disk timeouts around the crash." }),
        0x139 => new("KERNEL_SECURITY_CHECK_FAILURE",
            "The kernel detected corruption of a critical structure - buggy driver, RAM failure, or corrupted system files.",
            new[] { "Run 'sfc /scannow'.", "Test the RAM.", "Update or remove recently installed drivers." }),
        0x154 => new("UNEXPECTED_STORE_EXCEPTION",
            "The memory-compression store hit an unrecoverable error - very frequently a failing SSD/HDD.",
            new[] { "Check SMART health and back up data now.", "Update SSD firmware.", "Run 'chkdsk /f'." }),
        _ => new($"BUGCHECK_0x{code:X}",
            "Windows stopped to prevent damage after an unrecoverable kernel error.",
            new[] { "Update drivers for GPU, network, storage and antivirus.", "Test RAM and check disk SMART health.", "Search the bugcheck code online together with the suspect driver below." }),
    };

    private static CrashKb ExceptionInfo(uint code, string exe, string? module) => code switch
    {
        0xC0000005 => new("Access violation",
            $"{exe} read or wrote memory it does not own and Windows terminated it. This is a bug in the crashing module - or memory corruption caused by another component (overlays, shell extensions, antivirus hooks are frequent).",
            new[] { $"Update {exe} to the latest version.", module is null || module.Equals(exe, StringComparison.OrdinalIgnoreCase) ? $"If it keeps crashing, reinstall {exe} and report the crash to its vendor." : $"Update or remove the component {module} - the crash occurred inside it.", "Disable overlays (Discord, GeForce Experience) and third-party antivirus as a test.", "If many different programs crash this way, test the RAM." }),
        0xC0000094 or 0xC0000095 => new("Integer arithmetic error",
            $"{exe} performed an invalid arithmetic operation (e.g. divide by zero) - an application bug.",
            new[] { $"Update {exe}.", "Report the crash to the vendor if it repeats." }),
        0xC00000FD => new("Stack overflow",
            $"{exe} exhausted its call stack, usually infinite recursion - an application bug, sometimes triggered by a specific document or plugin.",
            new[] { $"Update {exe}.", "Remove recently added plugins/extensions of this program.", "Note what file/action triggers it and report to the vendor." }),
        0xC0000374 => new("Heap corruption",
            $"The memory heap of {exe} was corrupted. A bug in the application or in an injected component (antivirus, overlay, codec, shell extension).",
            new[] { $"Update {exe} and any plugins.", "Test with antivirus/overlays disabled.", "If widespread across apps, test RAM." }),
        0xC0000409 => new("Stack buffer overrun / fail-fast",
            $"{exe} detected corruption of its own state and terminated itself deliberately (a security guard tripped).",
            new[] { $"Update {exe} - this is fixed by the vendor, not by system repair.", "Update or remove plugins loaded into the program." }),
        0xE06D7363 => new("C++ application exception",
            $"{exe} threw a C++ exception that nothing handled - an application bug, sometimes triggered by a corrupt settings file or a plugin.",
            new[] { $"Update {exe}.", "Try resetting the program's settings or profile.", "Remove recently added plugins.", "Report to the vendor if it repeats." }),
        0xE0434352 => new(".NET application exception",
            $"{exe} is a .NET application that died with an unhandled managed exception. The exact error text is in Event Viewer (source '.NET Runtime', event 1026) and in Chronos's Errors timeline.",
            new[] { "Open the matching '.NET application crash' event in the timeline for the real error message.", $"Update {exe} and the .NET runtime.", "Report the error text to the application vendor." }),
        0x80000003 => new("Breakpoint / assertion",
            $"{exe} hit a debug breakpoint outside a debugger - a deliberate crash on an internal assertion.",
            new[] { $"Update {exe}.", "Report to the vendor with the dump file." }),
        0 => new("Process dump (no exception record)",
            $"This dump of {exe} contains no exception - it was probably captured manually or by a hang report rather than a crash.",
            new[] { "If the program hangs, update it and check for conflicting overlays or antivirus.", "Use the timeline's 'Application hang' events to see when it stopped responding." }),
        _ => new($"Exception 0x{code:X8}",
            $"{exe} was terminated by an unhandled exception.",
            new[] { $"Update {exe}.", "Search the exception code online for specifics.", "Report to the vendor if it repeats." }),
    };

    // ------------------------------------------------------------------ driver knowledge

    /// <summary>Vendor/purpose description for well-known third-party modules; null when unknown.</summary>
    public static string? DescribeDriver(string file)
    {
        var f = file.ToLowerInvariant();
        foreach (var (prefix, desc) in KnownDrivers)
            if (f.StartsWith(prefix)) return desc;
        return null;
    }

    private static readonly (string Prefix, string Desc)[] KnownDrivers =
    {
        ("nvlddmkm", "NVIDIA graphics driver"), ("nvwgf2um", "NVIDIA graphics driver"),
        ("atikmdag", "AMD graphics driver"), ("amdkmdag", "AMD graphics driver"), ("amdkmdap", "AMD graphics driver"),
        ("igdkmd", "Intel graphics driver"), ("igdumdim", "Intel graphics driver"), ("igxelpicd", "Intel graphics driver"),
        ("iastora", "Intel RST storage driver"), ("iastorac", "Intel RST storage driver"), ("iastorvd", "Intel RST storage driver"),
        ("rtwlane", "Realtek WiFi driver"), ("rtwlanu", "Realtek WiFi USB driver"), ("rt640", "Realtek Ethernet driver"),
        ("rtl8", "Realtek network driver"), ("rtkvhd", "Realtek audio driver"),
        ("athw", "Qualcomm Atheros WiFi driver"), ("qca", "Qualcomm WiFi driver"),
        ("netwtw", "Intel WiFi driver"), ("ibtusb", "Intel Bluetooth driver"), ("e1d", "Intel Ethernet driver"),
        ("mwifiex", "Marvell WiFi driver"), ("bcmwl", "Broadcom WiFi driver"),
        ("klif", "Kaspersky antivirus"), ("klbackup", "Kaspersky antivirus"), ("kneps", "Kaspersky antivirus"),
        ("asw", "Avast antivirus"), ("avgnt", "Avira antivirus"), ("avg", "AVG antivirus"),
        ("epfw", "ESET firewall"), ("eamonm", "ESET antivirus"), ("ehdrv", "ESET antivirus"),
        ("bdvedisk", "Bitdefender"), ("trufos", "Bitdefender"), ("atc", "Bitdefender"),
        ("mbam", "Malwarebytes"), ("farflt", "Malwarebytes"),
        ("csagent", "CrowdStrike Falcon"), ("csboot", "CrowdStrike Falcon"),
        ("sentinelmonitor", "SentinelOne"), ("cyprotectdrv", "Cylance"),
        ("vgk", "Riot Vanguard anti-cheat"), ("easyanticheat", "EasyAntiCheat"), ("bedaisy", "BattlEye anti-cheat"),
        ("faceit", "FACEIT anti-cheat"), ("ricochet", "Ricochet anti-cheat"),
        ("cpuz", "CPUID hardware-info driver (CPU-Z and similar tools)"), ("asio", "ASUS I/O utility driver"),
        ("iocbios", "Intel XTU tuning driver"), ("rzudd", "Razer device driver"), ("lgcoretemp", "Logitech driver"),
        ("dtsoftbus", "Daemon Tools virtual bus"), ("vboxdrv", "VirtualBox"), ("vmci", "VMware"), ("vmx86", "VMware"),
        ("npcap", "Npcap packet capture"), ("npf", "WinPcap packet capture"),
        ("wintun", "WireGuard/VPN adapter"), ("tapwindows", "OpenVPN TAP adapter"), ("tap0901", "OpenVPN TAP adapter"),
        ("nordlwf", "NordVPN filter"), ("pia", "Private Internet Access VPN"),
        ("logi", "Logitech device software"), ("corsair", "Corsair iCUE"), ("icue", "Corsair iCUE"),
        ("asmedia", "ASMedia USB controller driver"), ("amdppm", "AMD processor driver"),
        ("ene", "ENE RGB/SD controller driver"), ("gdrv", "Gigabyte utility driver"),
    };

    /// <summary>Core Windows drivers excluded from the suspect sweep.</summary>
    private static readonly HashSet<string> CoreDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntoskrnl.sys", "ntkrnlmp.sys", "hal.sys", "ci.sys", "clfs.sys", "cng.sys", "ksecdd.sys", "ksecpkg.sys",
        "win32k.sys", "win32kbase.sys", "win32kfull.sys", "dxgkrnl.sys", "dxgmms1.sys", "dxgmms2.sys", "watchdog.sys",
        "ndis.sys", "netio.sys", "tcpip.sys", "fwpkclnt.sys", "afd.sys", "http.sys", "nwifi.sys", "vwififlt.sys",
        "fltmgr.sys", "fileinfo.sys", "ntfs.sys", "refs.sys", "fastfat.sys", "exfat.sys", "cdfs.sys",
        "volsnap.sys", "volmgr.sys", "volmgrx.sys", "volume.sys", "partmgr.sys", "mountmgr.sys", "mup.sys", "rdbss.sys",
        "disk.sys", "classpnp.sys", "storport.sys", "stornvme.sys", "storahci.sys", "ataport.sys", "scsiport.sys",
        "acpi.sys", "pci.sys", "pcw.sys", "msrpc.sys", "wdf01000.sys", "wdfldr.sys", "wmilib.sys", "werkernel.sys",
        "intelppm.sys", "processr.sys", "usbxhci.sys", "usbport.sys", "usbhub.sys", "usbhub3.sys", "usbccgp.sys",
        "hidclass.sys", "hidusb.sys", "kbdclass.sys", "mouclass.sys", "kbdhid.sys", "mouhid.sys",
        "wdfilter.sys", "wdnisdrv.sys", "mssecflt.sys", "sleepstudyhelper.sys", "mmcss.sys",
        "srv.sys", "srv2.sys", "srvnet.sys", "mrxsmb.sys", "mrxsmb20.sys", "bowser.sys",
        "luafv.sys", "wcifs.sys", "cldflt.sys", "bindflt.sys", "iorate.sys", "ahcache.sys", "wof.sys",
        "winhvr.sys", "vmswitch.sys", "vmbus.sys", "vmbkmcl.sys", "hyperkbd.sys", "hypervideo.sys",
        "bam.sys", "beep.sys", "bthport.sys", "bthusb.sys", "monitor.sys", "npsvctrig.sys", "nsiproxy.sys",
        "rdyboost.sys", "spaceport.sys", "tm.sys", "vdrvroot.sys", "wfplwfs.sys", "peauth.sys", "tbs.sys",
    };
}
