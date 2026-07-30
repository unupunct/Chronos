using System.Windows.Media;

namespace Chronos.Models;

/// <summary>Severity of a timeline event. Drives the colored dot / border on each card.</summary>
public enum EventSeverity
{
    Information,
    Success,
    Warning,
    Critical
}

/// <summary>Top-level timeline categories. Each has a color and icon (see CategoryMeta).</summary>
public enum EventCategory
{
    System,        // boot, shutdown, sleep, restart, kernel power, fast startup, safe mode
    Updates,       // Windows Update, feature/security/driver updates, servicing
    Security,      // logon/logoff, accounts, UAC, firewall, BitLocker, audit
    Defender,      // Windows Defender detections and state
    Hardware,      // USB, disks, SMART, memory, monitors, printers, devices
    Software,      // installs / uninstalls / updates (MSI + registry), Office, browsers, runtimes
    Network,       // WiFi/Ethernet connect-disconnect, VPN, DNS/IP changes
    Services,      // service installed/removed/crashed, scheduled tasks
    Errors,        // BSOD, application crashes/hangs, WER, disk errors
    Performance    // boot/shutdown duration, degradation, thermal
}

/// <summary>One entry on the unified timeline.</summary>
public sealed class TimelineEvent
{
    public DateTime Timestamp { get; init; }
    public EventCategory Category { get; init; }
    public EventSeverity Severity { get; init; }
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";

    /// <summary>Origin: event log channel, provider, registry, etc.</summary>
    public string Source { get; init; } = "";
    public int EventId { get; init; }
    public string? User { get; init; }

    /// <summary>Extra key/value pairs shown when the card is expanded.</summary>
    public List<KeyValuePair<string, string>> Details { get; init; } = new();

    // Precomputed lowercase haystack for instant search.
    private string? _searchText;
    public string SearchText => _searchText ??=
        $"{Title}\n{Description}\n{Source}\n{User}\n{EventId}\n{CategoryMeta.Get(Category).DisplayName}\n{string.Join('\n', Details.Select(d => d.Key + " " + d.Value))}"
        .ToLowerInvariant();
}

/// <summary>Display metadata for a category: name, Segoe Fluent icon glyph, accent brush.</summary>
public sealed class CategoryMeta
{
    public EventCategory Category { get; }
    public string DisplayName { get; }
    public string Glyph { get; }
    public SolidColorBrush Brush { get; }

    private CategoryMeta(EventCategory category, string name, string glyph, string hex)
    {
        Category = category;
        DisplayName = name;
        Glyph = glyph;
        Brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        Brush.Freeze();
    }

    private static readonly Dictionary<EventCategory, CategoryMeta> All = new[]
    {
        new CategoryMeta(EventCategory.System,      "Windows",        "", "#4EA1FF"), // power button
        new CategoryMeta(EventCategory.Updates,     "Windows Update", "", "#3FD48A"), // sync
        new CategoryMeta(EventCategory.Security,    "Security",       "", "#F2C94C"), // lock
        new CategoryMeta(EventCategory.Defender,    "Defender",       "", "#2EC8C8"), // shield
        new CategoryMeta(EventCategory.Hardware,    "Hardware",       "", "#B08CFF"), // hard drive
        new CategoryMeta(EventCategory.Software,    "Software",       "", "#5FD2F2"), // all apps
        new CategoryMeta(EventCategory.Network,     "Network",        "", "#63D0A8"), // globe
        new CategoryMeta(EventCategory.Services,    "Services",       "", "#C9A227"), // gear
        new CategoryMeta(EventCategory.Errors,      "Errors",         "", "#FF6B6B"), // error badge
        new CategoryMeta(EventCategory.Performance, "Performance",    "", "#FFA94D"), // speed high
    }.ToDictionary(m => m.Category);

    public static CategoryMeta Get(EventCategory c) => All[c];
    public static IReadOnlyCollection<CategoryMeta> GetAll() => All.Values;
}

/// <summary>Static machine facts shown in the System Info view, status bar and reports.</summary>
public sealed class SystemInfo
{
    public string ComputerName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public string WindowsEdition { get; set; } = "";
    public string WindowsVersion { get; set; } = "";
    public string Build { get; set; } = "";
    public string Cpu { get; set; } = "";
    public string Gpu { get; set; } = "";
    public string Ram { get; set; } = "";
    public string Motherboard { get; set; } = "";
    public string Bios { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public string Tpm { get; set; } = "";
    public string SecureBoot { get; set; } = "";
    public string BitLocker { get; set; } = "";
    public string Storage { get; set; } = "";
    public string Battery { get; set; } = "";
    public DateTime? InstallDate { get; set; }

    public IEnumerable<KeyValuePair<string, string>> AsPairs()
    {
        yield return new("Computer Name", ComputerName);
        yield return new("Current User", UserName);
        yield return new("Windows", WindowsEdition);
        yield return new("Version", WindowsVersion);
        yield return new("Build", Build);
        if (InstallDate is { } d) yield return new("OS Installed", d.ToString("yyyy-MM-dd"));
        yield return new("CPU", Cpu);
        yield return new("GPU", Gpu);
        yield return new("RAM", Ram);
        yield return new("Motherboard", Motherboard);
        yield return new("BIOS", Bios);
        yield return new("Serial Number", SerialNumber);
        yield return new("TPM", Tpm);
        yield return new("Secure Boot", SecureBoot);
        yield return new("BitLocker", BitLocker);
        yield return new("Storage", Storage);
        yield return new("Battery", Battery);
    }
}

/// <summary>A single computed statistic tile.</summary>
public sealed record StatTile(string Title, string Value, string Glyph, string Detail);

/// <summary>One bar in a statistics chart.</summary>
public sealed record ChartBar(string Label, int Value, double Fraction, Brush Brush);

/// <summary>One recommendation produced by the rules engine.</summary>
public sealed record Recommendation(EventSeverity Severity, string Title, string Explanation);
