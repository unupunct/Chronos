using System.IO;
using System.Windows;
using Chronos.Collectors;
using Chronos.Services;

namespace Chronos;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        LogService.Info("Chronos starting");

        DispatcherUnhandledException += (_, args) =>
        {
            LogService.Error("Unhandled UI exception", args.Exception);
            MessageBox.Show(
                "An unexpected error occurred:\n\n" + args.Exception.Message +
                "\n\nDetails were written to Chronos.log.",
                "Chronos", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            LogService.Error("Unhandled exception", args.ExceptionObject as Exception);

        // headless modes:
        //   Chronos.exe --export <directory> [days]
        //   Chronos.exe --analyze-dump <file.dmp> [output.txt]
        var argv = e.Args;
        if (argv.Length >= 2 && argv[0].Equals("--export", StringComparison.OrdinalIgnoreCase))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var dir = argv[1];
            var days = argv.Length >= 3 && int.TryParse(argv[2], out var d) ? Math.Clamp(d, 1, 366) : 7;
            var code = RunHeadlessExport(dir, days);
            Shutdown(code);
            return;
        }
        if (argv.Length >= 2 && argv[0].Equals("--analyze-dump", StringComparison.OrdinalIgnoreCase))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(RunHeadlessDumpAnalysis(argv[1], argv.Length >= 3 ? argv[2] : null));
            return;
        }

        new MainWindow().Show();
    }

    /// <summary>Collects the last N days and writes all report formats to a directory. Exit code 0 on success.</summary>
    private static int RunHeadlessExport(string dir, int days)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var to = DateTime.Now;
            var from = DateTime.Today.AddDays(-days);
            LogService.Info($"Headless export: last {days} day(s) -> {dir}");

            var engine = new EventLogEngine();
            var infoTask = Task.Run(SystemInfoService.Collect);
            var events = engine.Collect(from, to);
            events.AddRange(SoftwareRegistryCollector.Collect(from, to));
            events.Sort((a, b) => b.Timestamp.CompareTo(a.Timestamp));
            var info = infoTask.GetAwaiter().GetResult();

            var (dumps, _) = DumpAnalysisService.LocateAndAnalyze();
            var data = new ReportService.ReportData(
                events,
                StatisticsService.BuildTiles(events),
                RecommendationService.Analyze(events, info),
                RecommendationService.GenerateInsights(events, info),
                info, from, to, dumps);

            var stem = Path.Combine(dir, $"Chronos-{info.ComputerName}-{DateTime.Now:yyyyMMdd-HHmm}");
            ReportService.ExportHtml(data, stem + ".html");
            ReportService.ExportJson(data, stem + ".json");
            ReportService.ExportCsv(data, stem + ".csv");
            ReportService.ExportMarkdown(data, stem + ".md");
            try { ReportService.ExportPdf(data, stem + ".pdf"); }
            catch (Exception ex) { LogService.Warn("PDF export skipped: " + ex.Message); }

            LogService.Info($"Headless export finished: {events.Count} events");
            return 0;
        }
        catch (Exception ex)
        {
            LogService.Error("Headless export failed", ex);
            return 1;
        }
    }

    /// <summary>Analyzes one dump file and writes a plain-text verdict (next to the dump by default).</summary>
    private static int RunHeadlessDumpAnalysis(string dumpPath, string? outPath)
    {
        try
        {
            var a = Services.DumpAnalysisService.Analyze(dumpPath);
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Chronos crash dump analysis");
            sb.AppendLine(new string('=', 60));
            sb.AppendLine($"File:      {a.FilePath}");
            sb.AppendLine($"Captured:  {a.Timestamp:yyyy-MM-dd HH:mm:ss}   Size: {a.SizeText}");
            sb.AppendLine($"Type:      {(a.IsKernel ? "Kernel (blue screen)" : "User-mode (application crash)")}");
            sb.AppendLine();
            sb.AppendLine($"WHAT HAPPENED:  {a.Headline}");
            sb.AppendLine($"VERDICT:        {a.Verdict}");
            sb.AppendLine();
            sb.AppendLine(a.Explanation);
            sb.AppendLine();
            sb.AppendLine("WHAT TO DO:");
            for (var i = 0; i < a.Resolutions.Count; i++)
                sb.AppendLine($"  {i + 1}. {a.Resolutions[i]}");
            if (a.ThirdPartyDrivers.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Third-party drivers found in the dump:");
                foreach (var drv in a.ThirdPartyDrivers.Take(20))
                {
                    var desc = Services.DumpAnalysisService.DescribeDriver(drv);
                    sb.AppendLine($"  - {drv}{(desc is not null ? $"  ({desc})" : "")}");
                }
            }
            sb.AppendLine();
            sb.AppendLine($"Technical: {a.TechnicalDetails}");

            outPath ??= Path.ChangeExtension(dumpPath, ".analysis.txt");
            File.WriteAllText(outPath, sb.ToString(), System.Text.Encoding.UTF8);
            LogService.Info($"Dump analysis written to {outPath}");
            return 0;
        }
        catch (Exception ex)
        {
            LogService.Error("Dump analysis failed", ex);
            try { File.WriteAllText(outPath ?? Path.ChangeExtension(dumpPath, ".analysis.txt"), "Analysis failed: " + ex.Message); }
            catch { }
            return 1;
        }
    }
}
