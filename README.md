# Chronos - Windows Timeline

A portable forensic/diagnostic tool that shows **everything that happened on a Windows PC in one chronological timeline** - boots, shutdowns, blue screens, Windows Updates, installed programs, USB devices, logins, Defender detections, network drops, crashes and more - without opening Event Viewer, Reliability Monitor or SetupAPI logs.

One `.exe`. No installation. No dependencies. No internet. No telemetry.

## Features

- **Unified timeline** - ~70 curated Windows Event Log rules (System, Application, Security, Setup, Defender, Firewall, TaskScheduler, WLAN, NetworkProfile, Diagnostics-Performance, BitLocker channels) plus a registry sweep of installed software.
- **Instant search** - `Chrome`, `USB`, `Blue Screen`, `yesterday`, `Office`, `Battery`, `Administrator`...
- **Filters** - date range presets + custom range, 10 color-coded categories, severity, one-click quick filters (Only Errors / Installations / Hardware / Updates).
- **Zoom** - group the timeline by hour, day, week, month or year.
- **Statistics** - boots, unexpected shutdowns, BSODs, updates, installs, USB events, network drops, average/worst boot time, longest uptime, activity charts, most frequent errors.
- **Recommendations engine** - detects unexpected-shutdown clusters, SMART warnings, WHEA errors, failing updates, brute-force logons, disabled Defender, USB churn, throttling, weak battery health.
- **Insights** - an offline natural-language health summary of the machine.
- **Crash dump analysis** - reads kernel BSOD minidumps (`C:\Windows\Minidump`, `MEMORY.DMP`) and WER application dumps (`%LOCALAPPDATA%\CrashDumps`) directly, no debugger or symbols required. Each dump gets a plain-language verdict, an explanation of the failure class, numbered resolution steps, and (for kernel dumps) a sweep for suspect third-party drivers (GPU, antivirus, anti-cheat, VPN, RGB/tuning tools...). You can also open a `.dmp` copied in from another PC.
- **Reports** - PDF (printed via the built-in Edge browser, offline), HTML, JSON, CSV, Markdown - including the crash dump analysis.
- **Computer info** - CPU, GPU, RAM, motherboard, BIOS, serial, TPM, Secure Boot, BitLocker, storage, battery health.
- **Live refresh** - polls for new events every 30 seconds.

## Build

Requires the .NET 8 SDK. Then:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Output: `publish\Chronos.exe` (single-file, self-contained, ReadyToRun). WPF does not support IL trimming, so the exe carries the runtime (~70 MB compressed).

## Headless mode

For scripted use (RMM, scheduled tasks), Chronos can generate every report format without showing the UI:

```
Chronos.exe --export C:\Reports [days]
```

Writes HTML, JSON, CSV, Markdown and PDF for the last `days` days (default 7), including any crash dump analysis found on the machine. Exit code 0 on success.

To analyze one dump file directly and get a plain-text verdict:

```
Chronos.exe --analyze-dump C:\path\to\file.dmp [output.txt]
```

Defaults to writing `file.analysis.txt` next to the dump. Works on both kernel (BSOD) and user-mode (application) dumps.

## Usage notes

- Runs as a normal user. The **Security log** (logins, account changes, audit) requires administrator rights - Chronos shows a note in "Collection notes" when not elevated; restart it as admin to include those events.
- Some optional channels (Task Scheduler operational log, Diagnostics-Performance) may be disabled on a given machine; Chronos skips them gracefully and says so.
- Logs are written to `Chronos.log` next to the exe (or `%LOCALAPPDATA%\Chronos` when the folder is read-only).
- Everything runs locally. No network calls, no telemetry, no cloud services. Reports and logs stay on disk where you save them - review before sharing, since they can include usernames, computer names, installed software and driver names.

## License

MIT - see [LICENSE](LICENSE).

## Architecture

```
Chronos/
  Models/            TimelineEvent, categories, severity, SystemInfo, chart/stat records
  Collectors/
    EventRules.cs           declarative (channel, provider, id) -> timeline event mapping table
    EventLogEngine.cs       parallel channel readers, chunked XPath queries, graceful degradation
    SoftwareRegistryCollector.cs  Uninstall-key sweep (HKLM 64/32 + HKCU)
  Services/
    SystemInfoService.cs    WMI probes (each independent + failure-safe)
    StatisticsService.cs    tiles, category/activity/error charts, boot stats, uptime
    RecommendationService.cs rules engine + offline insights text
    ReportService.cs        HTML/JSON/CSV/Markdown writers + Edge-headless PDF printing
    DumpAnalysisService.cs  kernel (PAGEDU64/PAGEDUMP) + user-mode (MDMP) dump parser, driver sweep, resolution KB
    LogService.cs           rolling file logger
  ViewModels/        MVVM (hand-rolled ObservableObject/RelayCommand, no packages)
  Themes/Dark.xaml   Fluent-style dark theme (all control templates)
  MainWindow.xaml    dashboard: sidebar filters, virtualized timeline, right details panel
```

The timeline `ListBox` uses recycling virtualization with grouping enabled, so 100,000+ events scroll smoothly; filtering runs on a background thread with cancellation.
