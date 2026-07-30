using Chronos.Models;
using Microsoft.Win32;

namespace Chronos.Collectors;

/// <summary>
/// Reads the Uninstall registry keys (HKLM 64/32-bit + HKCU) and emits an
/// "Application installed" timeline event for every program whose InstallDate
/// falls inside the collection window. This catches non-MSI installers
/// (Chrome, Office C2R, Steam, VS Code, runtimes) that never touch the event log.
/// </summary>
public static class SoftwareRegistryCollector
{
    private static readonly (RegistryKey Root, string Path, string Scope)[] Sources =
    {
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "machine (64-bit)"),
        (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "machine (32-bit)"),
        (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "current user"),
    };

    public static List<TimelineEvent> Collect(DateTime from, DateTime to)
    {
        var events = new List<TimelineEvent>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (root, path, scope) in Sources)
        {
            using var key = root.OpenSubKey(path);
            if (key is null) continue;

            foreach (var sub in key.GetSubKeyNames())
            {
                try
                {
                    using var app = key.OpenSubKey(sub);
                    if (app is null) continue;

                    var name = app.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    if (app.GetValue("SystemComponent") is int sc && sc == 1) continue;

                    var when = ResolveInstallDate(app);
                    if (when is null || when < from || when > to) continue;

                    var version = app.GetValue("DisplayVersion") as string ?? "";
                    if (!seen.Add($"{name}|{version}|{when:yyyyMMdd}")) continue;

                    var publisher = app.GetValue("Publisher") as string ?? "";
                    var ev = new TimelineEvent
                    {
                        Timestamp = when.Value,
                        Category = EventCategory.Software,
                        Severity = EventSeverity.Success,
                        Title = $"{name} installed",
                        Description = string.IsNullOrEmpty(version)
                            ? $"{name} was installed ({scope})."
                            : $"{name} {version} was installed ({scope}).",
                        Source = "Registry / Uninstall",
                        EventId = 0,
                    };
                    ev.Details.Add(new("Program", name));
                    if (version.Length > 0) ev.Details.Add(new("Version", version));
                    if (publisher.Length > 0) ev.Details.Add(new("Publisher", publisher));
                    ev.Details.Add(new("Scope", scope));
                    if (app.GetValue("InstallLocation") is string loc && loc.Length > 0)
                        ev.Details.Add(new("Location", loc));
                    ev.Details.Add(new("Class", Classify(name)));
                    events.Add(ev);
                }
                catch { /* one unreadable key must not break the sweep */ }
            }
        }

        return events;
    }

    /// <summary>InstallDate is "yyyyMMdd" when present; otherwise fall back to the key's write time via InstallDate absence → skip.</summary>
    private static DateTime? ResolveInstallDate(RegistryKey app)
    {
        if (app.GetValue("InstallDate") is string s && s.Length == 8 &&
            DateTime.TryParseExact(s, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out var d))
            return d.AddHours(12); // midday marker: the registry stores no time of day

        return null;
    }

    /// <summary>Tag well-known software families so search terms like "Office" or "browser" work.</summary>
    private static string Classify(string name)
    {
        var n = name.ToLowerInvariant();
        if (n.Contains("office") || n.Contains("word") || n.Contains("excel") || n.Contains("outlook") || n.Contains("teams")) return "Microsoft Office";
        if (n.Contains("chrome") || n.Contains("edge") || n.Contains("firefox") || n.Contains("opera") || n.Contains("brave")) return "Browser";
        if (n.Contains("adobe") || n.Contains("acrobat") || n.Contains("photoshop")) return "Adobe";
        if (n.Contains("steam") || n.Contains("epic games")) return "Gaming";
        if (n.Contains("visual studio") || n.Contains("vs code")) return "Development";
        if (n.Contains(".net") || n.Contains("visual c++") || n.Contains("redistributable")) return "Runtime";
        if (n.Contains("java") || n.Contains("python") || n.Contains("node")) return "Runtime";
        if (n.Contains("docker") || n.Contains("wsl")) return "Development";
        if (n.Contains("driver") || n.Contains("nvidia") || n.Contains("amd") || n.Contains("intel")) return "Driver";
        return "Application";
    }
}
