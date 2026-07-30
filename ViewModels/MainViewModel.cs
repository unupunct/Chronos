using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using Chronos.Collectors;
using Chronos.Models;
using Chronos.Services;
using Microsoft.Win32;

namespace Chronos.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly EventLogEngine _engine = new();
    private readonly DispatcherTimer _searchDebounce;
    private readonly DispatcherTimer _autoRefresh;

    private List<TimelineEvent> _allEvents = new();
    private DateTime _collectedFrom = DateTime.MinValue;
    private DateTime _lastRefresh = DateTime.MinValue;
    private CancellationTokenSource? _filterCts;

    public MainViewModel()
    {
        Categories = new ObservableCollection<FilterItemViewModel>(
            CategoryMeta.GetAll().OrderBy(m => m.DisplayName).Select(m => new FilterItemViewModel
            {
                Label = m.DisplayName, Glyph = m.Glyph, Brush = m.Brush, Tag = m.Category, Changed = ApplyFilters,
            }));

        Severities = new ObservableCollection<FilterItemViewModel>(
            new[] { EventSeverity.Critical, EventSeverity.Warning, EventSeverity.Success, EventSeverity.Information }
            .Select(s => new FilterItemViewModel { Label = s.ToString(), Tag = s, Changed = ApplyFilters }));

        RefreshCommand = new RelayCommand(_ => _ = RefreshAsync(force: true), _ => !IsBusy);
        ExportCommand = new RelayCommand(p => Export(p as string ?? "html"), _ => !IsBusy && _allEvents.Count > 0);
        NavigateCommand = new RelayCommand(p => CurrentView = p as string ?? "timeline");
        ClearSearchCommand = new RelayCommand(_ => SearchText = "");
        SelectAllCategoriesCommand = new RelayCommand(_ => SetAllCategories(true));
        SelectNoCategoriesCommand = new RelayCommand(_ => SetAllCategories(false));
        QuickFilterCommand = new RelayCommand(p => ApplyQuickFilter(p as string ?? ""));
        RescanDumpsCommand = new RelayCommand(_ => { _dumpsLoaded = false; _ = LoadDumpsAsync(); }, _ => !IsAnalyzingDumps);
        OpenDumpCommand = new RelayCommand(_ => OpenDumpFiles(), _ => !IsAnalyzingDumps);

        _searchDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _searchDebounce.Tick += (_, _) => { _searchDebounce.Stop(); ApplyFilters(); };

        _autoRefresh = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _autoRefresh.Tick += async (_, _) => { if (!IsBusy && AutoRefreshEnabled) await IncrementalRefreshAsync(); };
        _autoRefresh.Start();
    }

    // ------------------------------------------------------------------ bindables

    public ObservableCollection<FilterItemViewModel> Categories { get; }
    public ObservableCollection<FilterItemViewModel> Severities { get; }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand NavigateCommand { get; }
    public RelayCommand ClearSearchCommand { get; }
    public RelayCommand SelectAllCategoriesCommand { get; }
    public RelayCommand SelectNoCategoriesCommand { get; }
    public RelayCommand QuickFilterCommand { get; }
    public RelayCommand RescanDumpsCommand { get; }
    public RelayCommand OpenDumpCommand { get; }

    public string[] RangeOptions { get; } = { "Today", "Yesterday", "Last 7 Days", "Last 30 Days", "Last 90 Days", "Last Year", "Custom Range" };
    private string _selectedRange = "Last 7 Days";
    public string SelectedRange
    {
        get => _selectedRange;
        set
        {
            if (Set(ref _selectedRange, value))
            {
                OnPropertyChanged(nameof(IsCustomRange));
                _ = RefreshAsync(force: false);
            }
        }
    }

    public bool IsCustomRange => _selectedRange == "Custom Range";

    private DateTime? _customFrom = DateTime.Today.AddDays(-7);
    public DateTime? CustomFrom
    {
        get => _customFrom;
        set { if (Set(ref _customFrom, value) && IsCustomRange) _ = RefreshAsync(force: false); }
    }

    private DateTime? _customTo = DateTime.Today;
    public DateTime? CustomTo
    {
        get => _customTo;
        set { if (Set(ref _customTo, value) && IsCustomRange) _ = RefreshAsync(force: false); }
    }

    public string[] ZoomOptions { get; } = { "Hour", "Day", "Week", "Month", "Year" };
    private string _selectedZoom = "Day";
    public string SelectedZoom
    {
        get => _selectedZoom;
        set { if (Set(ref _selectedZoom, value)) ApplyFilters(); }
    }

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set { if (Set(ref _searchText, value)) { _searchDebounce.Stop(); _searchDebounce.Start(); OnPropertyChanged(nameof(HasSearch)); } }
    }
    public bool HasSearch => _searchText.Length > 0;

    private bool _isBusy;
    public bool IsBusy { get => _isBusy; set { if (Set(ref _isBusy, value)) OnPropertyChanged(nameof(IsIdle)); } }
    public bool IsIdle => !_isBusy;

    private string _statusText = "Ready";
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    private string _currentView = "timeline";
    public string CurrentView
    {
        get => _currentView;
        set
        {
            if (Set(ref _currentView, value) && value == "dumps" && !_dumpsLoaded)
                _ = LoadDumpsAsync();
        }
    }

    private bool _autoRefreshEnabled = true;
    public bool AutoRefreshEnabled { get => _autoRefreshEnabled; set => Set(ref _autoRefreshEnabled, value); }

    private ListCollectionView? _timelineView;
    public ListCollectionView? TimelineView { get => _timelineView; private set => Set(ref _timelineView, value); }

    private EventItemViewModel? _selectedEvent;
    public EventItemViewModel? SelectedEvent { get => _selectedEvent; set => Set(ref _selectedEvent, value); }

    private SystemInfo _systemInfo = new();
    public SystemInfo SystemInfo { get => _systemInfo; set { if (Set(ref _systemInfo, value)) OnPropertyChanged(nameof(SystemInfoPairs)); } }
    public IEnumerable<KeyValuePair<string, string>> SystemInfoPairs => SystemInfo.AsPairs().Where(p => p.Value.Length > 0);

    public ObservableCollection<StatTile> Stats { get; } = new();
    public ObservableCollection<ChartBar> CategoryChart { get; } = new();
    public ObservableCollection<ChartBar> ActivityChart { get; } = new();
    public ObservableCollection<ChartBar> TopErrors { get; } = new();
    public ObservableCollection<Recommendation> Recommendations { get; } = new();
    public ObservableCollection<string> Warnings { get; } = new();

    private string _insights = "";
    public string Insights { get => _insights; set => Set(ref _insights, value); }

    // ------------------------------------------------------------------ crash dumps

    private bool _dumpsLoaded;
    public ObservableCollection<DumpAnalysis> Dumps { get; } = new();
    public ObservableCollection<string> DumpNotes { get; } = new();

    private bool _isAnalyzingDumps;
    public bool IsAnalyzingDumps { get => _isAnalyzingDumps; set => Set(ref _isAnalyzingDumps, value); }

    private string _dumpSummary = "";
    public string DumpSummary { get => _dumpSummary; set => Set(ref _dumpSummary, value); }

    public async Task LoadDumpsAsync()
    {
        if (IsAnalyzingDumps) return;
        IsAnalyzingDumps = true;
        try
        {
            var (dumps, notes) = await Task.Run(DumpAnalysisService.LocateAndAnalyze);
            Dumps.Clear();
            foreach (var d in dumps) Dumps.Add(d);
            DumpNotes.Clear();
            foreach (var n in notes) DumpNotes.Add(n);
            DumpSummary = BuildDumpSummary(dumps);
            _dumpsLoaded = true;
            LogService.Info($"Analyzed {dumps.Count} crash dump(s)");
        }
        catch (Exception ex)
        {
            LogService.Error("Dump analysis failed", ex);
            DumpSummary = "Dump analysis failed: " + ex.Message;
        }
        finally
        {
            IsAnalyzingDumps = false;
        }
    }

    private static string BuildDumpSummary(IReadOnlyList<DumpAnalysis> dumps)
    {
        if (dumps.Count == 0)
            return "No crash dump files were found on this machine - no blue screens or captured application crashes.";

        var kernel = dumps.Count(d => d.IsKernel);
        var user = dumps.Count - kernel;
        var parts = new List<string>
        {
            $"Found {dumps.Count} crash dump(s): {kernel} blue-screen (kernel) and {user} application (user-mode).",
        };

        var topCulprit = dumps.Where(d => d.Culprit is not null)
            .GroupBy(d => d.Culprit!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault();
        if (topCulprit is not null && topCulprit.Count() >= 2)
        {
            var desc = DumpAnalysisService.DescribeDriver(topCulprit.Key);
            parts.Add($"{topCulprit.Count()} of them point at {topCulprit.Key}{(desc is not null ? $" ({desc})" : "")} - start there.");
        }

        var newest = dumps[0];
        parts.Add($"Most recent: {newest.Headline} on {newest.Timestamp:yyyy-MM-dd HH:mm}.");
        return string.Join(" ", parts);
    }

    private void OpenDumpFiles()
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Crash dumps (*.dmp)|*.dmp|All files|*.*",
            Multiselect = true,
            Title = "Analyze crash dump file(s)",
        };
        if (dlg.ShowDialog() != true) return;

        IsAnalyzingDumps = true;
        Task.Run(() =>
        {
            var results = new List<(string File, DumpAnalysis? Analysis, string? Error)>();
            foreach (var f in dlg.FileNames)
            {
                try { results.Add((f, DumpAnalysisService.Analyze(f), null)); }
                catch (Exception ex) { results.Add((f, null, ex.Message)); }
            }
            Post(() =>
            {
                foreach (var (file, analysis, error) in results)
                {
                    if (analysis is not null) Dumps.Insert(0, analysis);
                    else DumpNotes.Add($"Could not analyze {Path.GetFileName(file)}: {error}");
                }
                DumpSummary = BuildDumpSummary(Dumps.ToList());
                IsAnalyzingDumps = false;
            });
        });
    }

    private int _visibleCount;
    public int VisibleCount { get => _visibleCount; set => Set(ref _visibleCount, value); }

    private int _totalCount;
    public int TotalCount { get => _totalCount; set => Set(ref _totalCount, value); }

    private string _lastRefreshText = "never";
    public string LastRefreshText { get => _lastRefreshText; set => Set(ref _lastRefreshText, value); }

    public string StatusBarInfo =>
        $"{SystemInfo.WindowsEdition} {SystemInfo.WindowsVersion}   |   {SystemInfo.ComputerName}\\{SystemInfo.UserName}";

    // ------------------------------------------------------------------ range helpers

    private (DateTime From, DateTime To) RangeWindow => _selectedRange switch
    {
        "Today" => (DateTime.Today, DateTime.Now),
        "Yesterday" => (DateTime.Today.AddDays(-1), DateTime.Today),
        "Last 7 Days" => (DateTime.Today.AddDays(-7), DateTime.Now),
        "Last 30 Days" => (DateTime.Today.AddDays(-30), DateTime.Now),
        "Last 90 Days" => (DateTime.Today.AddDays(-90), DateTime.Now),
        "Last Year" => (DateTime.Today.AddYears(-1), DateTime.Now),
        "Custom Range" => (
            (_customFrom ?? DateTime.Today.AddDays(-7)).Date,
            (_customTo ?? DateTime.Today).Date.AddDays(1).AddSeconds(-1)),
        _ => (DateTime.Today.AddDays(-7), DateTime.Now),
    };

    // ------------------------------------------------------------------ collection

    public async Task RefreshAsync(bool force)
    {
        var (from, to) = RangeWindow;

        // if we already collected a superset window, just re-filter
        if (!force && from >= _collectedFrom && _allEvents.Count > 0)
        {
            ApplyFilters();
            return;
        }

        IsBusy = true;
        StatusText = "Collecting events...";
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            // system info (WMI) runs concurrently with event collection
            Task<SystemInfo>? infoTask = SystemInfo.WindowsEdition.Length == 0
                ? Task.Run(SystemInfoService.Collect)
                : null;

            var events = await Task.Run(() =>
            {
                var list = _engine.Collect(from, to, s => Post(() => StatusText = s));
                list.AddRange(SoftwareRegistryCollector.Collect(from, to));
                list.Sort((a, b) => b.Timestamp.CompareTo(a.Timestamp));
                return list;
            });

            _allEvents = events;
            _collectedFrom = from;
            _lastRefresh = DateTime.Now;
            LastRefreshText = _lastRefresh.ToString("HH:mm:ss");
            TotalCount = events.Count;

            Warnings.Clear();
            foreach (var w in _engine.Warnings.Distinct()) Warnings.Add(w);

            if (infoTask is not null)
            {
                SystemInfo = await infoTask;
                OnPropertyChanged(nameof(StatusBarInfo));
            }

            RebuildAnalytics();
            ApplyFilters();
            StatusText = $"Collected {events.Count:N0} events in {sw.Elapsed.TotalSeconds:0.0} s";
            LogService.Info(StatusText);
        }
        catch (Exception ex)
        {
            StatusText = "Collection failed: " + ex.Message;
            LogService.Error("Refresh failed", ex);
        }
        finally
        {
            IsBusy = false;
            TrimMemory();
        }
    }

    /// <summary>Releases parsing garbage and returns unused pages to the OS after a collection pass.</summary>
    private static void TrimMemory()
    {
        try
        {
            System.Runtime.GCSettings.LargeObjectHeapCompactionMode =
                System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            SetProcessWorkingSetSize(System.Diagnostics.Process.GetCurrentProcess().Handle, -1, -1);
        }
        catch { /* cosmetic */ }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool SetProcessWorkingSetSize(nint process, nint min, nint max);

    /// <summary>Cheap poll for new events since the last refresh (real-time mode).</summary>
    private async Task IncrementalRefreshAsync()
    {
        if (_lastRefresh == DateTime.MinValue) return;
        var since = _lastRefresh.AddSeconds(-5);
        try
        {
            var fresh = await Task.Run(() => _engine.Collect(since, DateTime.Now));
            if (fresh.Count == 0) { _lastRefresh = DateTime.Now; return; }

            var known = new HashSet<(DateTime, int, string)>(
                _allEvents.Where(e => e.Timestamp >= since).Select(e => (e.Timestamp, e.EventId, e.Title)));
            var toAdd = fresh.Where(e => !known.Contains((e.Timestamp, e.EventId, e.Title))).ToList();
            if (toAdd.Count == 0) { _lastRefresh = DateTime.Now; return; }

            _allEvents.InsertRange(0, toAdd.OrderByDescending(e => e.Timestamp));
            _lastRefresh = DateTime.Now;
            LastRefreshText = _lastRefresh.ToString("HH:mm:ss");
            TotalCount = _allEvents.Count;
            RebuildAnalytics();
            ApplyFilters();
            StatusText = $"+{toAdd.Count} new event(s)";
        }
        catch (Exception ex)
        {
            LogService.Warn("Incremental refresh failed: " + ex.Message);
        }
    }

    private void RebuildAnalytics()
    {
        var (from, to) = RangeWindow;
        var window = _allEvents.Where(e => e.Timestamp >= from && e.Timestamp <= to).ToList();

        Stats.Clear();
        foreach (var t in StatisticsService.BuildTiles(window)) Stats.Add(t);

        CategoryChart.Clear();
        foreach (var b in StatisticsService.CategoryChart(window)) CategoryChart.Add(b);

        ActivityChart.Clear();
        foreach (var b in StatisticsService.ActivityChart(window)) ActivityChart.Add(b);

        TopErrors.Clear();
        foreach (var b in StatisticsService.TopErrors(window)) TopErrors.Add(b);

        Recommendations.Clear();
        foreach (var r in RecommendationService.Analyze(window, SystemInfo)) Recommendations.Add(r);

        Insights = RecommendationService.GenerateInsights(window, SystemInfo);
    }

    // ------------------------------------------------------------------ filtering

    private void ApplyFilters()
    {
        _filterCts?.Cancel();
        var cts = _filterCts = new CancellationTokenSource();
        var token = cts.Token;

        var (from, to) = RangeWindow;
        var search = _searchText.Trim().ToLowerInvariant();
        var terms = search.Length == 0 ? Array.Empty<string>() : search.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var cats = Categories.Where(c => c.IsChecked).Select(c => (EventCategory)c.Tag!).ToHashSet();
        var sevs = Severities.Where(s => s.IsChecked).Select(s => (EventSeverity)s.Tag!).ToHashSet();
        var zoom = _selectedZoom;
        var source = _allEvents;

        Task.Run(() =>
        {
            var items = new List<EventItemViewModel>(Math.Min(source.Count, 4096));
            foreach (var e in source)
            {
                if (token.IsCancellationRequested) return;
                if (e.Timestamp < from || e.Timestamp > to) continue;
                if (!cats.Contains(e.Category) || !sevs.Contains(e.Severity)) continue;
                if (terms.Length > 0 && !MatchesSearch(e, terms)) continue;
                items.Add(new EventItemViewModel(e) { GroupKey = GroupKeyFor(e.Timestamp, zoom) });
            }

            Post(() =>
            {
                if (token.IsCancellationRequested) return;
                var view = new ListCollectionView(items);
                view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(EventItemViewModel.GroupKey)));
                TimelineView = view;
                VisibleCount = items.Count;
            });
        }, token);
    }

    private static bool MatchesSearch(TimelineEvent e, string[] terms)
    {
        // special keywords: yesterday / today match by date
        foreach (var t in terms)
        {
            var ok = t switch
            {
                "today" => e.Timestamp.Date == DateTime.Today,
                "yesterday" => e.Timestamp.Date == DateTime.Today.AddDays(-1),
                _ => e.SearchText.Contains(t),
            };
            if (!ok) return false;
        }
        return true;
    }

    private static string GroupKeyFor(DateTime t, string zoom) => zoom switch
    {
        "Hour" => t.ToString("dddd, dd MMMM yyyy  HH:00"),
        "Week" => $"Week {System.Globalization.ISOWeek.GetWeekOfYear(t)}, {System.Globalization.ISOWeek.GetYear(t)}",
        "Month" => t.ToString("MMMM yyyy"),
        "Year" => t.ToString("yyyy"),
        _ => t.Date == DateTime.Today ? "Today"
           : t.Date == DateTime.Today.AddDays(-1) ? "Yesterday"
           : t.ToString("dddd, dd MMMM yyyy"),
    };

    // ------------------------------------------------------------------ quick filters

    private void ApplyQuickFilter(string kind)
    {
        switch (kind)
        {
            case "errors":
                SetAllCategories(false);
                Check(EventCategory.Errors, true);
                SetSeverities(EventSeverity.Critical, EventSeverity.Warning);
                break;
            case "installs":
                SetAllCategories(false);
                Check(EventCategory.Software, true);
                SetSeverities(EventSeverity.Critical, EventSeverity.Warning, EventSeverity.Success, EventSeverity.Information);
                break;
            case "hardware":
                SetAllCategories(false);
                Check(EventCategory.Hardware, true);
                SetSeverities(EventSeverity.Critical, EventSeverity.Warning, EventSeverity.Success, EventSeverity.Information);
                break;
            case "updates":
                SetAllCategories(false);
                Check(EventCategory.Updates, true);
                SetSeverities(EventSeverity.Critical, EventSeverity.Warning, EventSeverity.Success, EventSeverity.Information);
                break;
            default:
                SetAllCategories(true);
                SetSeverities(EventSeverity.Critical, EventSeverity.Warning, EventSeverity.Success, EventSeverity.Information);
                break;
        }
        ApplyFilters();
    }

    private void Check(EventCategory cat, bool value)
    {
        foreach (var c in Categories.Where(c => (EventCategory)c.Tag! == cat)) c.SetSilently(value);
    }

    private void SetAllCategories(bool value)
    {
        foreach (var c in Categories) c.SetSilently(value);
        ApplyFilters();
    }

    private void SetSeverities(params EventSeverity[] on)
    {
        foreach (var s in Severities) s.SetSilently(on.Contains((EventSeverity)s.Tag!));
    }

    // ------------------------------------------------------------------ export

    private void Export(string format)
    {
        var (from, to) = RangeWindow;
        var dlg = new SaveFileDialog
        {
            FileName = $"Chronos-{SystemInfo.ComputerName}-{DateTime.Now:yyyyMMdd-HHmm}",
            Filter = format switch
            {
                "pdf" => "PDF report|*.pdf",
                "json" => "JSON|*.json",
                "csv" => "CSV|*.csv",
                "md" => "Markdown|*.md",
                _ => "HTML report|*.html",
            },
        };
        if (dlg.ShowDialog() != true) return;

        var window = _allEvents.Where(e => e.Timestamp >= from && e.Timestamp <= to).ToList();
        var data = new ReportService.ReportData(
            window, Stats.ToList(), Recommendations.ToList(), Insights, SystemInfo, from, to, Dumps.ToList());

        IsBusy = true;
        StatusText = $"Exporting {format.ToUpperInvariant()}...";
        Task.Run(() =>
        {
            try
            {
                switch (format)
                {
                    case "pdf": ReportService.ExportPdf(data, dlg.FileName); break;
                    case "json": ReportService.ExportJson(data, dlg.FileName); break;
                    case "csv": ReportService.ExportCsv(data, dlg.FileName); break;
                    case "md": ReportService.ExportMarkdown(data, dlg.FileName); break;
                    default: ReportService.ExportHtml(data, dlg.FileName); break;
                }
                Post(() =>
                {
                    StatusText = "Report saved: " + Path.GetFileName(dlg.FileName);
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe",
                        $"/select,\"{dlg.FileName}\"") { UseShellExecute = true });
                });
            }
            catch (Exception ex)
            {
                LogService.Error("Export failed", ex);
                Post(() => StatusText = "Export failed: " + ex.Message);
            }
            finally
            {
                Post(() => IsBusy = false);
            }
        });
    }

    private static void Post(Action a) => Application.Current?.Dispatcher.BeginInvoke(a);
}
