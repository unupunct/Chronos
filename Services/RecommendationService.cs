using System.Text;
using Chronos.Models;

namespace Chronos.Services;

/// <summary>
/// Rule-based analysis of the collected timeline: actionable recommendations
/// plus a natural-language health summary ("AI Insights").
/// </summary>
public static class RecommendationService
{
    public static List<Recommendation> Analyze(IReadOnlyList<TimelineEvent> events, SystemInfo info)
    {
        var recs = new List<Recommendation>();
        var days = Math.Max(1, (events.Count == 0 ? 1 :
            (events.Max(e => e.Timestamp) - events.Min(e => e.Timestamp)).TotalDays));

        int Count(Func<TimelineEvent, bool> f) => events.Count(f);

        var unexpected = Count(e => e.EventId is 6008 or 41 && e.Category == EventCategory.System);
        if (unexpected >= 3)
            recs.Add(new(EventSeverity.Critical, $"{unexpected} unexpected shutdowns detected",
                "The machine lost power or was forced off repeatedly. Check the power supply, battery, cabling and overheating. " +
                "If it is a laptop, test with the charger connected; if a desktop, consider a PSU test."));
        else if (unexpected > 0)
            recs.Add(new(EventSeverity.Warning, $"{unexpected} unexpected shutdown(s) detected",
                "Occasional unexpected shutdowns can be caused by power cuts or a forced power-off. Keep an eye on it."));

        var bsod = Count(e => e.Title.Contains("Blue Screen"));
        if (bsod > 0)
            recs.Add(new(bsod >= 3 ? EventSeverity.Critical : EventSeverity.Warning,
                $"{bsod} Blue Screen (BSOD) event(s)",
                "Windows crashed at kernel level. Common causes: faulty drivers, RAM, storage or overheating. " +
                "Check the bugcheck codes in the timeline and update GPU/chipset drivers first."));

        var smart = Count(e => e.Title.Contains("SMART", StringComparison.OrdinalIgnoreCase));
        if (smart > 0)
            recs.Add(new(EventSeverity.Critical, "Disk failure predicted (S.M.A.R.T.)",
                "A drive is reporting SMART failure prediction. Back up your data immediately and plan a disk replacement. " +
                "This warning almost always precedes real failure."));

        var diskErr = Count(e => e.Category == EventCategory.Errors && (e.Title.Contains("Disk") || e.Title.Contains("File system")));
        if (diskErr >= 3)
            recs.Add(new(EventSeverity.Warning, $"{diskErr} disk / file-system errors",
                "Repeated disk errors detected. Run 'chkdsk /f' and check SATA/NVMe connections. Verify SMART health of the drive."));

        var whea = Count(e => e.Title.Contains("WHEA"));
        if (whea >= 3)
            recs.Add(new(EventSeverity.Critical, $"{whea} hardware (WHEA) errors",
                "The CPU/memory/PCIe subsystem reported machine-level errors. Test RAM (Windows Memory Diagnostic or MemTest86), " +
                "remove any overclock, and check temperatures."));

        var updateFails = Count(e => e.Title == "Update failed");
        if (updateFails >= 3)
            recs.Add(new(EventSeverity.Warning, $"Windows Update failed {updateFails} times",
                "Updates are failing repeatedly. Run the Windows Update troubleshooter, free up disk space, " +
                "or reset the update components (SoftwareDistribution folder)."));

        var failedLogins = Count(e => e.Title == "Failed login");
        if (failedLogins >= 10)
            recs.Add(new(EventSeverity.Warning, $"{failedLogins} failed login attempts",
                "There is a high number of failed logons. If this machine is reachable over RDP or the network, " +
                "verify the source IPs in the timeline and consider disabling RDP or enforcing lockout policies."));

        var defenderOff = Count(e => e.Title == "Real-time protection disabled");
        if (defenderOff > 0)
            recs.Add(new(EventSeverity.Warning, "Defender real-time protection was disabled",
                "Real-time protection was turned off at least once during this period. If you did not do this " +
                "intentionally (or via another antivirus), investigate."));

        var malware = Count(e => e.Title == "Malware detected");
        if (malware > 0)
            recs.Add(new(EventSeverity.Critical, $"{malware} malware detection(s)",
                "Windows Defender detected threats in this period. Open Windows Security and review protection history; " +
                "run a full scan to confirm the system is clean."));

        var crashes = events.Where(e => e.Title.StartsWith("Application crash")).ToList();
        if (crashes.Count >= 5)
        {
            var top = crashes.GroupBy(e => e.Title).OrderByDescending(g => g.Count()).First();
            recs.Add(new(EventSeverity.Warning, $"{crashes.Count} application crashes",
                $"The most frequent is '{top.Key}' ({top.Count()} times). Update or reinstall that application; " +
                "if many different apps crash, suspect RAM or an unstable driver."));
        }

        var usbChurn = events.Where(e => e.Title.StartsWith("USB device")).GroupBy(e => e.Details.FirstOrDefault(d => d.Key == "Device instance").Value)
            .Where(g => !string.IsNullOrEmpty(g.Key) && g.Count() >= 8).ToList();
        if (usbChurn.Count > 0)
            recs.Add(new(EventSeverity.Warning, "USB device repeatedly reconnecting",
                $"{usbChurn.Count} USB device(s) connected/disconnected many times. This usually means a faulty cable, " +
                "port or power-management issue (try disabling USB selective suspend)."));

        var throttle = Count(e => e.Title == "CPU throttled");
        if (throttle > 0)
            recs.Add(new(EventSeverity.Warning, "CPU thermal/power throttling detected",
                "The processor was slowed down by firmware. Clean fans and heatsinks, renew thermal paste, " +
                "and check that vents are unobstructed."));

        var (avgBoot, worst) = StatisticsService.BootStats(events);
        if (avgBoot > 90)
            recs.Add(new(EventSeverity.Warning, $"Slow boot: average {avgBoot:0.#} s",
                $"Boot regularly takes over 90 seconds (worst {worst:0.#} s). Disable unnecessary startup programs " +
                "(Task Manager > Startup) and check disk health."));

        var battery = SystemInfoService.BatteryHealth();
        if (battery is > 0 and < 60)
            recs.Add(new(EventSeverity.Warning, $"Battery health is {battery}%",
                "The battery has lost a significant part of its design capacity and should be considered for replacement."));
        else if (battery is > 0 and < 80)
            recs.Add(new(EventSeverity.Information, $"Battery health is {battery}%",
                "The battery shows normal wear. No action needed yet."));

        var logCleared = Count(e => e.Title.Contains("log cleared", StringComparison.OrdinalIgnoreCase));
        if (logCleared > 0)
            recs.Add(new(EventSeverity.Warning, "Event log was cleared",
                "One or more event logs were cleared in this period. On a machine you are diagnosing for someone else, " +
                "treat pre-clear history as unavailable."));

        if (recs.Count == 0)
            recs.Add(new(EventSeverity.Success, "No significant problems detected",
                "The timeline shows no crash clusters, disk warnings, failed updates or security anomalies in the selected period."));

        return recs.OrderByDescending(r => r.Severity).ToList();
    }

    /// <summary>Natural-language summary of the machine's recent history. Fully offline.</summary>
    public static string GenerateInsights(IReadOnlyList<TimelineEvent> events, SystemInfo info)
    {
        if (events.Count == 0)
            return "No events were collected for the selected period, so no summary can be generated.";

        var fromD = events.Min(e => e.Timestamp);
        var toD = events.Max(e => e.Timestamp);
        var days = Math.Max(1, (int)Math.Ceiling((toD - fromD).TotalDays));

        int Count(Func<TimelineEvent, bool> f) => events.Count(f);
        var sb = new StringBuilder();

        var critical = Count(e => e.Severity == EventSeverity.Critical);
        var bsod = Count(e => e.Title.Contains("Blue Screen"));
        var unexpected = Count(e => e.EventId is 6008 or 41 && e.Category == EventCategory.System);
        var crashes = Count(e => e.Title.StartsWith("Application crash") || e.Title.StartsWith("Application hang"));

        sb.Append(critical == 0
            ? $"The computer has been stable during the last {days} days. "
            : critical <= 3
                ? $"The computer has been mostly stable during the last {days} days, with {critical} critical event(s) worth reviewing. "
                : $"The computer shows signs of instability: {critical} critical events in the last {days} days. ");

        if (bsod > 0) sb.Append($"{bsod} blue screen(s) occurred. ");
        if (unexpected > 0) sb.Append($"{unexpected} shutdown(s) were unexpected. ");
        sb.Append(crashes switch
        {
            0 => "No application crashes were recorded. ",
            1 => "Only one application crash occurred. ",
            _ => $"{crashes} application crashes or hangs occurred. ",
        });

        var updates = Count(e => e.Category == EventCategory.Updates && e.Severity == EventSeverity.Success);
        var updateFails = Count(e => e.Title == "Update failed");
        if (updates > 0 && updateFails == 0) sb.Append("Windows Updates are installing regularly and without errors. ");
        else if (updateFails > 0) sb.Append($"Windows Update failed {updateFails} time(s). ");

        var smart = Count(e => e.Title.Contains("SMART", StringComparison.OrdinalIgnoreCase));
        sb.Append(smart > 0
            ? "The storage drive shows early S.M.A.R.T. warnings - back up important data. "
            : "Storage reported no failure predictions. ");

        var battery = SystemInfoService.BatteryHealth();
        if (battery > 0) sb.Append($"Battery health is {battery}%. ");

        var malware = Count(e => e.Title == "Malware detected");
        var defenderEvents = Count(e => e.Category == EventCategory.Defender);
        if (malware > 0) sb.Append($"Windows Defender detected {malware} threat(s) - review the protection history. ");
        else if (defenderEvents > 0) sb.Append("No malware activity was detected. ");

        var installs = Count(e => e.Category == EventCategory.Software && e.Title.EndsWith("installed"));
        if (installs > 0) sb.Append($"{installs} program(s) were installed in this period. ");

        var netDrops = Count(e => e.Category == EventCategory.Network && e.Title.Contains("disconnected", StringComparison.OrdinalIgnoreCase));
        if (netDrops >= 10) sb.Append($"The network disconnected {netDrops} times, which may indicate WiFi instability. ");

        return sb.ToString().TrimEnd();
    }
}
