using Chronos.Models;

namespace Chronos.Services;

/// <summary>Computes the statistics dashboard content from the collected timeline.</summary>
public static class StatisticsService
{
    public static List<StatTile> BuildTiles(IReadOnlyList<TimelineEvent> events)
    {
        int Count(Func<TimelineEvent, bool> f) => events.Count(f);

        var boots = Count(e => e.EventId == 6005 && e.Category == EventCategory.System);
        var shutdowns = Count(e => e.EventId is 6006 && e.Category == EventCategory.System);
        var unexpected = Count(e => e.EventId is 6008 or 41 && e.Category == EventCategory.System);
        var bsod = Count(e => e.Title.Contains("Blue Screen"));
        var updates = Count(e => e.Category == EventCategory.Updates && e.Severity == EventSeverity.Success);
        var installs = Count(e => e.Category == EventCategory.Software && e.Title.EndsWith("installed"));
        var usb = Count(e => e.Category == EventCategory.Hardware && e.Title.StartsWith("USB"));
        var netDrops = Count(e => e.Category == EventCategory.Network && e.Title.Contains("disconnected", StringComparison.OrdinalIgnoreCase));
        var crashes = Count(e => e.Category == EventCategory.Errors && e.Title.StartsWith("Application"));
        var logins = Count(e => e.Category == EventCategory.Security && e.Title.Contains("login", StringComparison.OrdinalIgnoreCase) && e.Severity == EventSeverity.Success);
        var failedLogins = Count(e => e.Title == "Failed login");

        var tiles = new List<StatTile>
        {
            new("Boots", boots.ToString(), "", "System starts in range"),
            new("Shutdowns", shutdowns.ToString(), "", "Clean shutdowns"),
            new("Unexpected shutdowns", unexpected.ToString(), "", "Power loss / forced off / crash"),
            new("Blue Screens", bsod.ToString(), "", "BSOD bugchecks"),
            new("Windows Updates", updates.ToString(), "", "Successfully installed"),
            new("Programs installed", installs.ToString(), "", "MSI + registry installers"),
            new("USB device events", usb.ToString(), "", "Configured or removed"),
            new("Network drops", netDrops.ToString(), "", "WiFi / network disconnects"),
            new("App crashes & hangs", crashes.ToString(), "", "Application faults"),
        };

        if (logins + failedLogins > 0)
            tiles.Add(new("Logins", $"{logins} / {failedLogins}", "", "Successful / failed"));

        var (avgBoot, worstBoot) = BootStats(events);
        if (avgBoot > 0)
            tiles.Add(new("Average boot time", $"{avgBoot:0.#} s", "", $"Slowest: {worstBoot:0.#} s"));

        var uptime = LongestUptime(events);
        if (uptime is { } up)
            tiles.Add(new("Longest uptime", Humanize(up), "", "Between boot and shutdown"));

        return tiles;
    }

    public static (double AvgSeconds, double WorstSeconds) BootStats(IReadOnlyList<TimelineEvent> events)
    {
        var times = events
            .Where(e => e.Category == EventCategory.Performance && e.EventId == 100)
            .Select(e => e.Details.FirstOrDefault(d => d.Key.StartsWith("Boot duration")).Value)
            .Select(v => long.TryParse(v, out var ms) ? ms / 1000.0 : 0)
            .Where(s => s > 0)
            .ToList();
        return times.Count == 0 ? (0, 0) : (times.Average(), times.Max());
    }

    public static TimeSpan? LongestUptime(IReadOnlyList<TimelineEvent> events)
    {
        // pair each boot (6005) with the next shutdown of any kind, chronologically
        var markers = events
            .Where(e => e.Category == EventCategory.System && e.EventId is 6005 or 6006 or 6008 or 41)
            .OrderBy(e => e.Timestamp)
            .ToList();

        TimeSpan best = TimeSpan.Zero;
        DateTime? bootAt = null;
        foreach (var m in markers)
        {
            if (m.EventId == 6005) { bootAt = m.Timestamp; continue; }
            if (bootAt is { } b && m.Timestamp > b)
            {
                var span = m.Timestamp - b;
                if (span > best) best = span;
                bootAt = null;
            }
        }
        return best > TimeSpan.Zero ? best : null;
    }

    /// <summary>Events per category, for the category chart.</summary>
    public static List<ChartBar> CategoryChart(IReadOnlyList<TimelineEvent> events)
    {
        var groups = events.GroupBy(e => e.Category)
            .Select(g => (Meta: CategoryMeta.Get(g.Key), Count: g.Count()))
            .OrderByDescending(g => g.Count)
            .ToList();
        var max = groups.Count > 0 ? groups.Max(g => g.Count) : 1;
        return groups.Select(g => new ChartBar(g.Meta.DisplayName, g.Count, (double)g.Count / max, g.Meta.Brush)).ToList();
    }

    /// <summary>Events per day (last N days), for the activity chart.</summary>
    public static List<ChartBar> ActivityChart(IReadOnlyList<TimelineEvent> events, int days = 14)
    {
        var today = DateTime.Today;
        var byDay = events.GroupBy(e => e.Timestamp.Date).ToDictionary(g => g.Key, g => g.Count());
        var list = new List<(string Label, int Count)>();
        for (var i = days - 1; i >= 0; i--)
        {
            var day = today.AddDays(-i);
            list.Add((day.ToString("dd MMM"), byDay.GetValueOrDefault(day)));
        }
        var max = Math.Max(1, list.Max(x => x.Count));
        var brush = CategoryMeta.Get(EventCategory.System).Brush;
        return list.Select(x => new ChartBar(x.Label, x.Count, (double)x.Count / max, brush)).ToList();
    }

    /// <summary>Most frequent error titles.</summary>
    public static List<ChartBar> TopErrors(IReadOnlyList<TimelineEvent> events, int top = 8)
    {
        var groups = events
            .Where(e => e.Category == EventCategory.Errors || e.Severity == EventSeverity.Critical)
            .GroupBy(e => e.Title)
            .Select(g => (Title: g.Key, Count: g.Count()))
            .OrderByDescending(g => g.Count)
            .Take(top)
            .ToList();
        var max = groups.Count > 0 ? groups.Max(g => g.Count) : 1;
        var brush = CategoryMeta.Get(EventCategory.Errors).Brush;
        return groups.Select(g => new ChartBar(g.Title, g.Count, (double)g.Count / max, brush)).ToList();
    }

    public static string Humanize(TimeSpan t) =>
        t.TotalDays >= 1 ? $"{(int)t.TotalDays}d {t.Hours}h" :
        t.TotalHours >= 1 ? $"{(int)t.TotalHours}h {t.Minutes}m" :
        $"{(int)t.TotalMinutes}m";
}
