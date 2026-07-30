using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using Chronos.Models;

namespace Chronos.Services;

/// <summary>
/// Exports the timeline + statistics + system info + recommendations to
/// HTML, JSON, CSV, Markdown and PDF. PDF is produced by printing the HTML
/// report with the built-in Edge browser (headless), so no external library
/// or internet connection is required.
/// </summary>
public static class ReportService
{
    public sealed record ReportData(
        IReadOnlyList<TimelineEvent> Events,
        IReadOnlyList<StatTile> Stats,
        IReadOnlyList<Recommendation> Recommendations,
        string Insights,
        SystemInfo Info,
        DateTime From,
        DateTime To,
        IReadOnlyList<DumpAnalysis>? Dumps = null);

    // ------------------------------------------------------------------ JSON

    public static void ExportJson(ReportData d, string path)
    {
        var doc = new
        {
            generator = "Chronos - Windows Timeline",
            generatedAt = DateTime.Now,
            range = new { from = d.From, to = d.To },
            computer = d.Info.AsPairs().ToDictionary(p => p.Key, p => p.Value),
            statistics = d.Stats.Select(s => new { s.Title, s.Value, s.Detail }),
            recommendations = d.Recommendations.Select(r => new { severity = r.Severity.ToString(), r.Title, r.Explanation }),
            insights = d.Insights,
            crashDumps = (d.Dumps ?? Array.Empty<DumpAnalysis>()).Select(x => new
            {
                file = x.FileName,
                timestamp = x.Timestamp,
                kind = x.IsKernel ? "kernel (BSOD)" : "user-mode (application)",
                x.Headline,
                x.Verdict,
                x.Explanation,
                resolutions = x.Resolutions,
                culprit = x.Culprit,
                suspectDrivers = x.ThirdPartyDrivers,
                technical = x.TechnicalDetails,
            }),
            events = d.Events.Select(e => new
            {
                timestamp = e.Timestamp,
                category = e.Category.ToString(),
                severity = e.Severity.ToString(),
                e.Title,
                e.Description,
                e.Source,
                e.EventId,
                e.User,
                details = e.Details.ToDictionary(x => x.Key, x => x.Value),
            }),
        };
        File.WriteAllText(path, JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
    }

    // ------------------------------------------------------------------ CSV

    public static void ExportCsv(ReportData d, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Timestamp,Category,Severity,Title,Description,Source,EventId,User");
        foreach (var e in d.Events.OrderByDescending(e => e.Timestamp))
            sb.AppendLine(string.Join(',',
                Csv(e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")),
                Csv(CategoryMeta.Get(e.Category).DisplayName),
                Csv(e.Severity.ToString()),
                Csv(e.Title), Csv(e.Description), Csv(e.Source),
                Csv(e.EventId.ToString()), Csv(e.User ?? "")));
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true)); // BOM so Excel reads UTF-8
    }

    private static string Csv(string s) => '"' + s.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + '"';

    // ------------------------------------------------------------------ Markdown

    public static void ExportMarkdown(ReportData d, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Chronos - Windows Timeline Report");
        sb.AppendLine();
        sb.AppendLine($"**Computer:** {d.Info.ComputerName} | **User:** {d.Info.UserName} | **Windows:** {d.Info.WindowsEdition} {d.Info.WindowsVersion}");
        sb.AppendLine($"**Period:** {d.From:yyyy-MM-dd} to {d.To:yyyy-MM-dd} | **Generated:** {DateTime.Now:yyyy-MM-dd HH:mm}");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine(d.Insights);
        sb.AppendLine();
        sb.AppendLine("## Statistics");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value | Notes |");
        sb.AppendLine("|---|---|---|");
        foreach (var s in d.Stats) sb.AppendLine($"| {s.Title} | {s.Value} | {s.Detail} |");
        sb.AppendLine();
        sb.AppendLine("## Recommendations");
        sb.AppendLine();
        foreach (var r in d.Recommendations)
            sb.AppendLine($"- **[{r.Severity}] {r.Title}** - {r.Explanation}");
        sb.AppendLine();
        if (d.Dumps is { Count: > 0 } dumps)
        {
            sb.AppendLine("## Crash dump analysis");
            sb.AppendLine();
            foreach (var x in dumps)
            {
                sb.AppendLine($"### {x.Headline}  ({x.Timestamp:yyyy-MM-dd HH:mm}, {x.FileName})");
                sb.AppendLine();
                sb.AppendLine($"**Verdict:** {x.Verdict}");
                sb.AppendLine();
                sb.AppendLine(x.Explanation);
                sb.AppendLine();
                sb.AppendLine("What to do:");
                foreach (var (r, i) in x.Resolutions.Select((r, i) => (r, i)))
                    sb.AppendLine($"{i + 1}. {r}");
                if (x.ThirdPartyDrivers.Count > 0)
                    sb.AppendLine($"\nThird-party drivers in the dump: {string.Join(", ", x.ThirdPartyDrivers.Take(12))}");
                sb.AppendLine($"\n`{x.TechnicalDetails}`");
                sb.AppendLine();
            }
        }
        sb.AppendLine("## Computer");
        sb.AppendLine();
        sb.AppendLine("| Property | Value |");
        sb.AppendLine("|---|---|");
        foreach (var p in d.Info.AsPairs()) sb.AppendLine($"| {p.Key} | {p.Value} |");
        sb.AppendLine();
        sb.AppendLine($"## Timeline ({d.Events.Count} events)");
        sb.AppendLine();
        foreach (var g in d.Events.OrderByDescending(e => e.Timestamp).GroupBy(e => e.Timestamp.Date))
        {
            sb.AppendLine($"### {g.Key:dddd, dd MMMM yyyy}");
            sb.AppendLine();
            foreach (var e in g)
                sb.AppendLine($"- `{e.Timestamp:HH:mm:ss}` **[{CategoryMeta.Get(e.Category).DisplayName}]** {Sev(e.Severity)} {e.Title} - {e.Description}");
            sb.AppendLine();
        }
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static string Sev(EventSeverity s) => s switch
    {
        EventSeverity.Critical => "(CRITICAL)",
        EventSeverity.Warning => "(warning)",
        EventSeverity.Success => "(ok)",
        _ => "",
    };

    // ------------------------------------------------------------------ HTML

    public static void ExportHtml(ReportData d, string path)
    {
        File.WriteAllText(path, BuildHtml(d), Encoding.UTF8);
    }

    private static string H(string s) => System.Net.WebUtility.HtmlEncode(s);

    private static string SevColor(EventSeverity s) => s switch
    {
        EventSeverity.Critical => "#FF6B6B",
        EventSeverity.Warning => "#FFA94D",
        EventSeverity.Success => "#3FD48A",
        _ => "#8FA3B8",
    };

    private static string CatColor(EventCategory c) => c switch
    {
        EventCategory.System => "#4EA1FF",
        EventCategory.Updates => "#3FD48A",
        EventCategory.Security => "#F2C94C",
        EventCategory.Defender => "#2EC8C8",
        EventCategory.Hardware => "#B08CFF",
        EventCategory.Software => "#5FD2F2",
        EventCategory.Network => "#63D0A8",
        EventCategory.Services => "#C9A227",
        EventCategory.Errors => "#FF6B6B",
        _ => "#FFA94D",
    };

    private static string BuildHtml(ReportData d)
    {
        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Chronos Report</title>
<style>
 :root { color-scheme: dark; }
 * { box-sizing: border-box; }
 body { background:#0F1420; color:#DDE6F2; font-family:'Segoe UI',system-ui,sans-serif; margin:0; padding:32px; }
 h1 { font-size:26px; font-weight:600; margin:0 0 4px; }
 h2 { font-size:18px; font-weight:600; margin:32px 0 12px; color:#4EA1FF; }
 .sub { color:#8FA3B8; font-size:13px; margin-bottom:24px; }
 .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(190px,1fr)); gap:12px; }
 .tile { background:#182031; border:1px solid #24304A; border-radius:10px; padding:14px; }
 .tile .v { font-size:24px; font-weight:600; color:#4EA1FF; }
 .tile .t { font-size:12px; color:#8FA3B8; margin-top:2px; }
 .rec { border-left:3px solid; background:#182031; border-radius:8px; padding:10px 14px; margin-bottom:8px; }
 table { border-collapse:collapse; width:100%; font-size:13px; }
 td,th { padding:6px 10px; border-bottom:1px solid #24304A; text-align:left; vertical-align:top; }
 th { color:#8FA3B8; font-weight:600; }
 .day { background:#182031; border-radius:8px; padding:6px 12px; margin:18px 0 8px; font-weight:600; color:#4EA1FF; }
 .ev { display:flex; gap:10px; padding:7px 4px; border-bottom:1px solid #1B2436; font-size:13px; }
 .ev .time { color:#8FA3B8; min-width:64px; font-variant-numeric:tabular-nums; }
 .badge { border-radius:20px; padding:1px 10px; font-size:11px; white-space:nowrap; align-self:flex-start; }
 .desc { color:#A9B7C9; }
 @media print { body { background:#fff; color:#111; } .tile,.rec,.day { background:#f4f6fa; } :root{color-scheme:light} }
</style></head><body>
""");
        sb.Append($"<h1>Chronos - Windows Timeline</h1><div class='sub'>{H(d.Info.ComputerName)} &middot; {H(d.Info.WindowsEdition)} {H(d.Info.WindowsVersion)} &middot; period {d.From:yyyy-MM-dd} to {d.To:yyyy-MM-dd} &middot; generated {DateTime.Now:yyyy-MM-dd HH:mm}</div>");

        sb.Append("<h2>Summary</h2><p>").Append(H(d.Insights)).Append("</p>");

        sb.Append("<h2>Statistics</h2><div class='grid'>");
        foreach (var s in d.Stats)
            sb.Append($"<div class='tile'><div class='v'>{H(s.Value)}</div><div class='t'>{H(s.Title)} &middot; {H(s.Detail)}</div></div>");
        sb.Append("</div>");

        sb.Append("<h2>Recommendations</h2>");
        foreach (var r in d.Recommendations)
            sb.Append($"<div class='rec' style='border-color:{SevColor(r.Severity)}'><b>{H(r.Title)}</b><br><span class='desc'>{H(r.Explanation)}</span></div>");

        if (d.Dumps is { Count: > 0 } dumps)
        {
            sb.Append("<h2>Crash dump analysis</h2>");
            foreach (var x in dumps)
            {
                var color = x.IsKernel ? "#FF6B6B" : "#FFA94D";
                sb.Append($"<div class='rec' style='border-color:{color}'>");
                sb.Append($"<b>{H(x.Headline)}</b> <span class='desc'>&middot; {x.Timestamp:yyyy-MM-dd HH:mm} &middot; {H(x.FileName)}</span><br>");
                sb.Append($"<span style='color:{color}'>{H(x.Verdict)}</span><br>");
                sb.Append($"<span class='desc'>{H(x.Explanation)}</span>");
                sb.Append("<ol style='margin:8px 0 4px 18px;padding:0'>");
                foreach (var r in x.Resolutions) sb.Append($"<li class='desc'>{H(r)}</li>");
                sb.Append("</ol>");
                if (x.ThirdPartyDrivers.Count > 0)
                    sb.Append($"<span class='desc'>Third-party drivers in dump: {H(string.Join(", ", x.ThirdPartyDrivers.Take(12)))}</span><br>");
                sb.Append($"<span class='desc' style='font-family:Consolas,monospace;font-size:11px'>{H(x.TechnicalDetails)}</span>");
                sb.Append("</div>");
            }
        }

        sb.Append("<h2>Computer</h2><table>");
        foreach (var p in d.Info.AsPairs())
            sb.Append($"<tr><th>{H(p.Key)}</th><td>{H(p.Value)}</td></tr>");
        sb.Append("</table>");

        sb.Append($"<h2>Timeline ({d.Events.Count} events)</h2>");
        foreach (var g in d.Events.OrderByDescending(e => e.Timestamp).GroupBy(e => e.Timestamp.Date))
        {
            sb.Append($"<div class='day'>{g.Key:dddd, dd MMMM yyyy}</div>");
            foreach (var e in g)
            {
                var cat = CategoryMeta.Get(e.Category).DisplayName;
                sb.Append("<div class='ev'>");
                sb.Append($"<span class='time'>{e.Timestamp:HH:mm:ss}</span>");
                sb.Append($"<span class='badge' style='background:{CatColor(e.Category)}22;color:{CatColor(e.Category)}'>{H(cat)}</span>");
                sb.Append($"<span style='color:{SevColor(e.Severity)}'>&#9679;</span>");
                sb.Append($"<span><b>{H(e.Title)}</b> <span class='desc'>{H(e.Description)}</span></span>");
                sb.Append("</div>");
            }
        }

        sb.Append("</body></html>");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ PDF (via built-in Edge, offline)

    /// <summary>Prints the HTML report to PDF using the locally installed Edge/Chrome in headless mode.</summary>
    public static void ExportPdf(ReportData d, string path)
    {
        var browser = FindBrowser() ?? throw new InvalidOperationException(
            "PDF export uses the built-in Microsoft Edge browser, which was not found. Export HTML instead.");

        var tmpHtml = Path.Combine(Path.GetTempPath(), $"chronos-report-{Guid.NewGuid():N}.html");
        File.WriteAllText(tmpHtml, BuildHtml(d), Encoding.UTF8);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = browser,
                Arguments = $"--headless --disable-gpu --no-first-run --print-to-pdf=\"{path}\" \"file:///{tmpHtml.Replace('\\', '/')}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start the browser for PDF printing.");
            if (!proc.WaitForExit(60_000)) { proc.Kill(true); throw new TimeoutException("PDF printing timed out."); }
            if (!File.Exists(path)) throw new InvalidOperationException("The browser did not produce a PDF file.");
        }
        finally
        {
            try { File.Delete(tmpHtml); } catch { }
        }
    }

    private static string? FindBrowser()
    {
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var candidates = new[]
        {
            Path.Combine(pf86, @"Microsoft\Edge\Application\msedge.exe"),
            Path.Combine(pf, @"Microsoft\Edge\Application\msedge.exe"),
            Path.Combine(pf, @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(pf86, @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(local, @"Google\Chrome\Application\chrome.exe"),
        };
        return candidates.FirstOrDefault(File.Exists);
    }
}
